<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use PasargadCdn\ClientApi;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Operator', false)) {
    return;
}

/**
 * SPEC §19.1 — «دامنه‌های اپراتور»: the platform's own domains on the CDN without a WHMCS service.
 *
 *  - page: add (domain-check first, optional origin IP, plan template, note) + nameserver instructions and NS status,
 *    list (status, NS, SSL, month traffic, plan, note) with manage / NS recheck / purge all / suspend / unsuspend /
 *    change plan / edit note / delete (type the domain) / transfer (Transfer wizard);
 *  - manage: the server module's client app rendered inside the addon page in an admin context. Its API calls go to
 *    page=api&op=<token>: the token names a context stored in THIS admin session (domain + server, created when the
 *    manage page is opened and only for a site whose controller owner_kind is "operator"), so the browser never
 *    chooses the domain; ClientApi::handle() applies its whitelist / CSRF / validation with that synthetic context.
 *
 * Every write is re-checked against the controller (the site must still be an operator site) and logged with the
 * admin's username. Operator sites are never billed: they have no external_id / client, so the prepaid, overage,
 * storage-billing, referral, trial and owner-sync passes never match them (Data::siteIndex skips them explicitly).
 */
final class Operator
{
    // ------------------------------------------------------------------ controller contract (SPEC §19.1), in one place
    /** GET → the operator's sites (each with owner_kind = operator, operator_note, billing_since). */
    const LIST = '/api/v1/sites?owner=operator';
    /** POST {domain, origin_ip?, plan, operator: true, operator_note?} → 201 site; 409 exists; 422 tenancy / invalid */
    const CREATE = '/api/v1/sites';
    /** POST {domain, operator: true} → {ok, code, error, domain} */
    const CHECK = '/api/v1/domain-check';
    /** PATCH /api/v1/sites/{d}/operator {operator_note: str|null} (422 unless an operator site) */
    const NOTE_PATH = '/operator';
    const NOTE_FIELD = 'operator_note';
    const OWNER_KIND = 'operator';

    const NOTE_MAX = 200;
    /** addon KV: domain => {template, by, at} (the template an operator site was created / last re-planned with) */
    const KV = 'operator_sites';
    /** session: token => {domain, server, at, checked} — the manage contexts of this admin session */
    const SESSION = 'pasargadcdn_op_ctx';
    const SESSION_MAX = 20;
    /** a context's operator check is repeated after this many seconds */
    const RECHECK = 60;

    const ACTIONS = ['op_check', 'op_add', 'op_nscheck', 'op_purge', 'op_suspend', 'op_unsuspend', 'op_plan', 'op_note', 'op_delete',
        // SPEC §20.2: operator sites are shared by the admin (same roles as customers' shares)
        'op_share_invite', 'op_share_revoke'];

    // ------------------------------------------------------------------ plan templates

    /** key => [label, plan]: the wizard's plans as templates + «داخلی — همه امکانات». */
    public static function templates(): array
    {
        $out = [];
        foreach (Wizard::PLANS as $k => $p) {
            $plan = \pasargadcdn_plan(Wizard::configOptions($p, ['overage' => false, 'overage_allow' => 0]));
            $out[$k] = ['قالب پلن ' . $p['title'] . ' — ' . View::n($p['bw']) . ' GB', $plan];
        }
        $out['internal'] = ['داخلی — همه امکانات', self::internalPlan()];
        return $out;
    }

    /**
     * «داخلی — همه امکانات»: every feature on, unlimited traffic (bandwidth_limit_gb 0) and every cap at the maximum the
     * controller validates (routes_admin.Plan / sections.Features: records 10000, rules 1000, pools 100, tunnel paths 50,
     * webhooks 50, TCP/UDP apps 100, functions 32, storage 1 000 000 GB).
     */
    public static function internalPlan(): array
    {
        return [
            'bandwidth_limit_gb' => 0, 'max_records' => 10000, 'ssl_allowed' => true, 'rate_limit_rps' => 0,
            'features' => [
                'waf' => true, 'ddos' => true, 'load_balancer' => true, 'image_optimization' => true, 'custom_ssl' => true, 'dnssec' => true,
                'max_page_rules' => 1000, 'max_firewall_rules' => 1000, 'max_ratelimit_rules' => 1000, 'max_pools' => 100,
                'tunnel' => true, 'max_tunnel_paths' => 50, 'max_tunnel_connections' => 0, 'tunnel_max_mbps' => 0, 'edge_group' => 'general',
                'max_transform_rules' => 1000, 'max_redirects' => 10000, 'log_export' => true, 'max_webhooks' => 50,
                'l4_proxy' => true, 'max_l4_apps' => 100, 'storage_gb' => 1000000, 'edge_functions' => true, 'max_functions' => 32,
                'dns_secondary' => true, 'waiting_room' => true, 'access' => true,
            ],
        ];
    }

    private static function templateLabel(string $domain, array $site): string
    {
        $meta = (array) (Env::kvGet(self::KV, [])[$domain] ?? []);
        $t = self::templates();
        if (isset($meta['template'], $t[$meta['template']])) {
            return $t[$meta['template']][0];
        }
        $bw = (int) ($site['plan']['bandwidth_limit_gb'] ?? 0);
        return 'سفارشی' . ($site ? ' — ' . ($bw > 0 ? View::n($bw) . ' GB' : 'نامحدود') : '');
    }

    public static function remember(string $domain, ?string $template, int $admin): void
    {
        $all = (array) Env::kvGet(self::KV, []);
        if ($template === null) {
            unset($all[$domain]);
        } else {
            $all[$domain] = ['template' => $template, 'by' => $admin, 'at' => date('Y-m-d H:i:s')];
        }
        Env::kvSet(self::KV, $all);
    }

    // ------------------------------------------------------------------ controller helpers

    private static function server()
    {
        $s = Env::server();
        return $s ? Capsule::table('tblservers')->where('id', (int) $s->id)->first() : null;
    }

    /** The operator site $domain from the controller, or an error string (missing / not an operator site / unreachable). */
    public static function site(string $domain)
    {
        $domain = Env::domain($domain);
        if (!Env::validHostname($domain)) {
            return 'دامنه نامعتبر است.';
        }
        try {
            $s = Env::api(10)->get(ApiClient::site($domain));
        } catch (\Throwable $e) {
            return $e instanceof ApiException && $e->getCode() === 404 ? 'سایت ' . $domain . ' روی کنترلر وجود ندارد.'
                : 'دریافت سایت از کنترلر ناموفق بود: ' . $e->getMessage();
        }
        if (!Data::isOperator($s)) {
            return 'سایت ' . $domain . ' یک دامنهٔ اپراتور نیست (مالک آن مشتری یا نماینده است).';
        }
        return $s;
    }

    private static function note(string $v): ?string
    {
        $v = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $v) ?? '');
        $len = function_exists('mb_strlen') ? mb_strlen($v, 'UTF-8') : strlen($v);
        return $len > self::NOTE_MAX || !preg_match('//u', $v) ? null : $v;
    }

    // ------------------------------------------------------------------ actions (POST, CSRF already checked)

    /** @return array [flash list, page state] */
    public static function action(string $action, array $post, int $admin): array
    {
        if (!Env::adminHasAccess()) {
            return [[['bad', 'نقش مدیریتی شما به این ماژول دسترسی ندارد.']], []];
        }
        $domain = Env::domain(Env::input($post['domain'] ?? ''));
        if ($action === 'op_check' || $action === 'op_add') {
            return self::add($action === 'op_add', $domain, $post, $admin);
        }
        $site = self::site($domain);
        if (is_string($site)) {
            return [[['bad', View::e($site)]], []];
        }
        $who = Env::adminLabel();
        $path = ApiClient::site($domain);
        try {
            $api = Env::api(10);
            switch ($action) {
                case 'op_nscheck':
                    $r = $api->post($path . '/ns-check');
                    Env::log('operator site ' . $domain . ': NS re-check by ' . $who);
                    Pages::reset();
                    return [[!empty($r['ok']) ? ['ok', 'نیم‌سرورهای ' . View::ltr($domain) . ' تأیید شد.']
                        : ['warn', 'نیم‌سرورهای ' . View::ltr($domain) . ' هنوز تغییر نکرده است. فعلی: ' . (View::ltr(implode(', ', (array) ($r['found'] ?? []))) ?: '—')]], []];
                case 'op_purge':
                    $api->post($path . '/purge', ['urls' => []]);
                    Env::log('operator site ' . $domain . ': full cache purge by ' . $who);
                    return [[['ok', 'درخواست پاکسازی کل کش ' . View::ltr($domain) . ' ثبت شد.']], []];
                case 'op_suspend':
                case 'op_unsuspend':
                    $on = $action === 'op_suspend';
                    $api->post($path . ($on ? '/suspend' : '/unsuspend'));
                    Env::log('operator site ' . $domain . ' ' . ($on ? 'suspended' : 'unsuspended') . ' by ' . $who);
                    Pages::reset();
                    return [[['ok', $on ? 'سایت ' . View::ltr($domain) . ' معلق شد؛ بازدیدکنندگان صفحه تعلیق را می‌بینند.' : 'تعلیق ' . View::ltr($domain) . ' برداشته شد.']], []];
                case 'op_plan':
                    $key = Env::input($post['template'] ?? '');
                    $t = self::templates();
                    if (!isset($t[$key])) {
                        return [[['bad', 'قالب پلن نامعتبر است.']], []];
                    }
                    $api->patch($path . '/plan', $t[$key][1]);
                    self::remember($domain, $key, $admin);
                    Env::log('operator site ' . $domain . ': plan set to template «' . $key . '» by ' . $who);
                    Pages::reset();
                    return [[['ok', 'پلن ' . View::ltr($domain) . ' به «' . View::e($t[$key][0]) . '» تغییر کرد.']], []];
                case 'op_note':
                    $note = self::note(Env::input($post['note'] ?? ''));
                    if ($note === null) {
                        return [[['bad', 'یادداشت حداکثر ' . View::n(self::NOTE_MAX) . ' نویسه و بدون نویسهٔ کنترلی باشد.']], []];
                    }
                    $api->patch($path . self::NOTE_PATH, [self::NOTE_FIELD => $note === '' ? null : $note]);
                    Env::log('operator site ' . $domain . ': note edited by ' . $who);
                    Pages::reset();
                    return [[['ok', 'یادداشت ' . View::ltr($domain) . ' ذخیره شد.']], []];
                case 'op_share_invite':
                    require_once __DIR__ . '/Sharing.php';
                    return [[Sharing::adminInvite($domain, Env::input($post['email'] ?? ''), Env::input($post['role'] ?? ''))], []];
                case 'op_share_revoke':
                    require_once __DIR__ . '/Sharing.php';
                    $sid = (int) ($post['id'] ?? 0);
                    // scoped to THIS operator domain: an id of another site's share is refused
                    if (!\PasargadCdn\Shares::revoke($sid, ['operator_domain' => $domain])) {
                        return [[['bad', 'اشتراک یا دعوتی با این شناسه برای این دامنه نیست.']], []];
                    }
                    \PasargadCdn\Shares::log('#' . $sid . ' on operator site ' . $domain . ' revoked by ' . $who);
                    return [[['ok', 'دسترسی لغو شد.']], []];
                case 'op_delete':
                    if (strtolower(trim(Env::input($post['confirm'] ?? ''))) !== $domain) {
                        return [[['bad', 'برای حذف، نام دامنه را دقیقاً تایپ کنید؛ چیزی حذف نشد.']], []];
                    }
                    $api->delete($path);
                    self::remember($domain, null, $admin);
                    \PasargadCdn\Shares::removeForDomain($domain);   // SPEC §20.2: a deleted site keeps no shares
                    Env::log('operator site ' . $domain . ' deleted from the controller by ' . $who);
                    Pages::reset();
                    return [[['ok', 'سایت اپراتور ' . View::ltr($domain) . ' از کنترلر حذف شد.']], []];
            }
        } catch (\Throwable $e) {
            Env::log('operator site ' . $domain . ': ' . $action . ' failed (' . $e->getMessage() . ') — ' . $who);
            return [[['bad', View::e('عملیات روی ' . $domain . ' ناموفق بود: ' . $e->getMessage())]], []];
        }
        return [[['bad', 'عملیات نامعتبر است.']], []];
    }

    /** op_check: domain-check only; op_add: domain-check, then POST /api/v1/sites with operator: true. */
    private static function add(bool $create, string $domain, array $post, int $admin): array
    {
        $old = ['domain' => $domain, 'origin_ip' => trim(Env::input($post['origin_ip'] ?? '')),
            'template' => Env::input($post['template'] ?? 'internal'), 'note' => Env::input($post['note'] ?? '')];
        $errs = [];
        if (!Env::validHostname($domain)) {
            $errs[] = 'دامنه نامعتبر است (مثلاً example.ir، بدون http و مسیر).';
        }
        if ($old['origin_ip'] !== '' && !filter_var($old['origin_ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $errs[] = 'IP سرور اصلی باید یک IPv4 عمومی معتبر باشد (یا خالی بماند).';
        }
        $t = self::templates();
        if (!isset($t[$old['template']])) {
            $errs[] = 'قالب پلن نامعتبر است.';
        }
        $note = self::note($old['note']);
        if ($note === null) {
            $errs[] = 'یادداشت حداکثر ' . View::n(self::NOTE_MAX) . ' نویسه و بدون نویسهٔ کنترلی باشد.';
        }
        if ($errs) {
            return [array_map(function ($m) {
                return ['bad', View::e($m)];
            }, $errs), ['op_form' => $old]];
        }
        try {
            $api = Env::api(10);
            $chk = $api->post(self::CHECK, ['domain' => $domain, 'operator' => true]);
        } catch (\Throwable $e) {
            return [[['bad', View::e('بررسی دامنه روی کنترلر ناموفق بود: ' . $e->getMessage())]], ['op_form' => $old]];
        }
        if (empty($chk['ok'])) {
            return [[['bad', 'دامنه ' . View::ltr($domain) . ' قابل افزودن نیست: ' . View::e((string) ($chk['error'] ?? $chk['code'] ?? 'نامشخص'))]],
                ['op_form' => $old, 'op_check' => $chk]];
        }
        if (!$create) {
            return [[['ok', 'دامنه ' . View::ltr($domain) . ' آزاد است و می‌تواند به‌عنوان دامنهٔ اپراتور افزوده شود.']], ['op_form' => $old, 'op_check' => $chk]];
        }
        $body = ['domain' => $domain, 'plan' => $t[$old['template']][1], 'operator' => true];
        if ($old['origin_ip'] !== '') {
            $body['origin_ip'] = $old['origin_ip'];
        }
        if ($note !== '') {
            $body[self::NOTE_FIELD] = $note;
        }
        try {
            $site = $api->post(self::CREATE, $body);
        } catch (\Throwable $e) {
            Env::log('operator site ' . $domain . ' could not be added (' . $e->getMessage() . ') — ' . Env::adminLabel());
            $code = $e instanceof ApiException ? $e->getCode() : 0;
            return [[['bad', View::e(($code === 409 ? 'این دامنه قبلاً روی CDN ثبت شده است: ' : 'افزودن ' . $domain . ' ناموفق بود: ') . $e->getMessage())]], ['op_form' => $old]];
        }
        self::remember($domain, $old['template'], $admin);
        Env::log('operator site ' . $domain . ' added (template «' . $old['template'] . '»' . ($old['origin_ip'] !== '' ? ', origin ' . $old['origin_ip'] : '')
            . ') by ' . Env::adminLabel());
        Pages::reset();
        return [[['ok', 'دامنهٔ اپراتور ' . View::ltr($domain) . ' افزوده شد. نیم‌سرورهای زیر را در ثبت‌کنندهٔ دامنه تنظیم کنید.']],
            ['op_added' => is_array($site) ? $site : ['domain' => $domain]]];
    }

    // ------------------------------------------------------------------ page

    public static function page(array $get, array $state): string
    {
        $ping = Pages::ping();
        $h = View::alert('info', 'دامنه‌های خود پلتفرم (مثل سایت شرکت یا پنل‌ها) را بدون سرویس WHMCS روی CDN بیاورید. این سایت‌ها '
            . '<strong>هرگز صورت‌حساب، کسر از کیف پول، ترافیک اضافه، صورت‌حساب فضای ذخیره‌سازی، معرفی یا دورهٔ آزمایشی</strong> ندارند و در گزارش '
            . 'همگام‌سازی «بدون سرویس» شمرده نمی‌شوند؛ سقف ترافیک کنترلر (اگر تعیین شود) همچنان اعمال می‌شود.');
        if (!$ping['ok']) {
            return $h . Pages::ctlError($ping);
        }
        if (!empty($state['op_added'])) {
            $h .= self::nsCard((array) $state['op_added']);
        }
        $h .= self::addForm((array) ($state['op_form'] ?? []), $state['op_check'] ?? null);
        $r = Pages::fetch([self::LIST]);
        if (!Pages::ok($r[self::LIST])) {
            return $h . View::card('دامنه‌های اپراتور', View::alert('bad', 'فهرست دامنه‌های اپراتور از کنترلر دریافت نشد: ' . View::e((string) ($r[self::LIST]['error'] ?? ''))
                . ' (کنترلر پیش از SPEC §19 این فهرست را ندارد.)'), '', '', 'globe');
        }
        // rows without owner_kind = operator (an older controller ignoring ?owner=) are never listed here
        $sites = array_values(array_filter((array) $r[self::LIST]['data'], [Data::class, 'isOperator']));
        $paths = [];
        foreach ($sites as $s) {
            $paths[strtolower((string) $s['domain'])] = ApiClient::site((string) $s['domain']);
        }
        $det = $paths ? Pages::fetch(array_values($paths)) : [];
        return $h . self::listCard($sites, $paths, $det);
    }

    private static function url(array $q = []): string
    {
        return View::url(['page' => 'operator'] + $q);
    }

    private static function addForm(array $old, $check): string
    {
        $opts = [];
        foreach (self::templates() as $k => [$label]) {
            $opts[$k] = $label;
        }
        $res = '';
        if (is_array($check)) {
            $res = '<p class="' . (!empty($check['ok']) ? 'pcdna-okline' : 'pcdna-err') . '" data-op-check="' . (!empty($check['ok']) ? 'ok' : 'bad') . '">'
                . View::icon(!empty($check['ok']) ? 'check' : 'x') . '<span>' . (!empty($check['ok']) ? 'این دامنه آزاد است.'
                    : View::e((string) ($check['error'] ?? 'قابل افزودن نیست'))) . '</span></p>';
        }
        $form = '<form method="post" action="' . self::url() . '" class="pcdna-form" autocomplete="off" data-op-add="1">' . View::csrf()
            . '<div class="pcdna-form-grid">'
            . '<label><span>دامنه</span><input class="pcdna-input" name="domain" dir="ltr" required maxlength="253" placeholder="example.ir" value="' . View::e($old['domain'] ?? '') . '">'
            . '<small>نام دامنهٔ اصلی بدون http و www؛ ابتدا با «بررسی دامنه» آزاد بودن آن روی CDN را بسنجید.</small></label>'
            . '<label><span>IP سرور اصلی (اختیاری)</span><input class="pcdna-input" name="origin_ip" dir="ltr" maxlength="15" placeholder="185.1.2.3" value="' . View::e($old['origin_ip'] ?? '') . '">'
            . '<small>در صورت ورود، رکوردهای @ و www با پروکسی CDN ساخته می‌شوند.</small></label>'
            . '<label><span>قالب پلن</span>' . View::select('template', $opts, $old['template'] ?? 'internal') . '</label>'
            . '<label><span>یادداشت (فقط برای مدیران)</span><input class="pcdna-input" name="note" maxlength="' . self::NOTE_MAX . '" placeholder="مثلاً سایت اصلی شرکت" value="' . View::e($old['note'] ?? '') . '"></label>'
            . '</div>' . $res . '<div class="pcdna-form-actions">'
            . '<button type="submit" name="a" value="op_check" class="pcdna-btn" formnovalidate>' . View::icon('search') . '<span>بررسی دامنه</span></button>'
            . '<button type="submit" name="a" value="op_add" class="pcdna-btn pcdna-btn-primary">' . View::icon('plus') . '<span>افزودن دامنهٔ اپراتور</span></button>'
            . '</div></form>';
        return View::card('افزودن دامنهٔ اپراتور', $form, '', '', 'plus');
    }

    private static function nsCard(array $site): string
    {
        $ns = array_values(array_filter((array) ($site['nameservers'] ?? []), 'is_string')) ?: Env::DEFAULT_NS;
        $b = '<p>در پنل ثبت‌کنندهٔ دامنهٔ ' . View::ltr((string) ($site['domain'] ?? '')) . ' نیم‌سرورها را به این مقادیر تغییر دهید:</p>';
        foreach ($ns as $n) {
            $b .= View::copyable($n);
        }
        $b .= '<p class="pcdna-muted pcdna-small">وضعیت فعلی NS: ' . (!empty($site['ns_verified']) ? View::badge('تأیید شده', 'ok')
                : View::badge('در انتظار تغییر NS', 'warn') . ' فعلی: ' . (View::ltr(implode(', ', (array) ($site['ns_found'] ?? []))) ?: '—'))
            . '. پس از تغییر، از فهرست زیر «بررسی مجدد NS» را بزنید (کنترلر هم به‌طور خودکار بررسی می‌کند).</p>';
        return View::card('نیم‌سرورهای ' . (string) ($site['domain'] ?? ''), $b, '', '', 'server');
    }

    private static function listCard(array $sites, array $paths, array $det): string
    {
        if (!$sites) {
            return View::card('دامنه‌های اپراتور', View::emptyState('هنوز دامنهٔ اپراتوری ثبت نشده است', 'از فرم بالا اولین دامنه را بیفزایید.', 'globe'), '', '', 'globe');
        }
        $tpl = [];
        foreach (self::templates() as $k => [$label]) {
            $tpl[$k] = $label;
        }
        $t = '<div class="pcdna-table-wrap pcdna-sites-wrap"><table class="pcdna-table pcdna-sites pcdna-op-sites"><thead><tr><th>دامنه</th><th>وضعیت</th><th>NS</th><th>SSL</th>'
            . '<th>ترافیک این ماه</th><th>پلن</th><th>یادداشت</th><th><span class="pcdna-sr">عملیات</span></th></tr></thead><tbody>';
        foreach ($sites as $row) {
            $domain = strtolower((string) $row['domain']);
            $p = $paths[$domain] ?? '';
            $d = isset($det[$p]) && Pages::ok($det[$p]) ? (array) $det[$p]['data'] : [];
            $s = $d + $row;
            $st = (string) ($s['status'] ?? '');
            $ns = $d ? (!empty($d['ns_verified']) ? '<span class="pcdna-yes" title="تأیید شده">' . View::icon('check') . '</span>'
                : '<span class="pcdna-no" title="' . View::e('فعلی: ' . implode(', ', (array) ($d['ns_found'] ?? []))) . '">' . View::icon('x') . '</span>')
                : '<span class="pcdna-muted">—</span>';
            $sslSt = (string) ($d['ssl']['status'] ?? '');
            $ssl = $sslSt === 'active' ? View::badge('فعال', 'ok') : ($sslSt === 'pending' ? View::badge('در حال صدور', 'warn')
                : ($sslSt === 'failed' ? View::badge('ناموفق', 'bad') : ($sslSt === '' ? '<span class="pcdna-muted">—</span>' : View::badge('ندارد', 'muted'))));
            $gb = isset($d['usage_month']['bytes']) ? (float) $d['usage_month']['bytes'] / 1073741824 : (isset($d['usage_month']['gb']) ? (float) $d['usage_month']['gb'] : null);
            $limit = (float) ($d['plan']['bandwidth_limit_gb'] ?? 0);
            $traffic = $gb === null ? '<span class="pcdna-muted">—</span>' : '<span class="pcdna-num">' . View::n($gb, $gb < 10 ? 2 : 1)
                . ($limit > 0 ? ' از ' . View::n($limit) : '') . ' GB</span>' . ($limit > 0 ? View::meter($gb / $limit) : '<span class="pcdna-small pcdna-muted">نامحدود</span>');
            $note = (string) ($s[self::NOTE_FIELD] ?? '');
            $q = ['page' => 'operator'];
            $menu = View::postButton($q, 'op_nscheck', ['domain' => $domain], 'بررسی مجدد NS', 'pcdna-menu-item', '', 'sync')
                . View::postButton($q, 'op_purge', ['domain' => $domain], 'پاکسازی کل کش', 'pcdna-menu-item', 'کل کش ' . $domain . ' پاکسازی شود؟', 'refresh')
                . ($st === 'suspended'
                    ? View::postButton($q, 'op_unsuspend', ['domain' => $domain], 'رفع تعلیق', 'pcdna-menu-item', 'تعلیق ' . $domain . ' برداشته شود؟', 'power')
                    : View::postButton($q, 'op_suspend', ['domain' => $domain], 'تعلیق', 'pcdna-menu-item is-danger', 'سایت ' . $domain . ' معلق شود؟ بازدیدکنندگان صفحه تعلیق را می‌بینند.', 'power'))
                . '<a class="pcdna-menu-item" href="' . View::url(['page' => 'transfer', 'domain' => $domain]) . '">' . View::icon('users') . '<span>انتقال دامنه</span></a>';
            $plan = '<form method="post" action="' . self::url() . '" class="pcdna-form-inline pcdna-op-plan">' . View::csrf()
                . '<input type="hidden" name="a" value="op_plan"><input type="hidden" name="domain" value="' . View::e($domain) . '">'
                . View::select('template', $tpl, '', ' aria-label="قالب پلن جدید"')
                . '<button type="submit" class="pcdna-btn pcdna-btn-sm">تغییر پلن</button></form>';
            $noteForm = '<form method="post" action="' . self::url() . '" class="pcdna-form-inline pcdna-op-note">' . View::csrf()
                . '<input type="hidden" name="a" value="op_note"><input type="hidden" name="domain" value="' . View::e($domain) . '">'
                . '<input class="pcdna-input" name="note" maxlength="' . self::NOTE_MAX . '" value="' . View::e($note) . '" aria-label="یادداشت">'
                . '<button type="submit" class="pcdna-btn pcdna-btn-sm">ذخیره یادداشت</button></form>';
            $shares = self::shareBox($domain);
            $del = '<form method="post" action="' . self::url() . '" class="pcdna-form-inline pcdna-op-delete">' . View::csrf()
                . '<input type="hidden" name="a" value="op_delete"><input type="hidden" name="domain" value="' . View::e($domain) . '">'
                . '<label class="pcdna-small">برای حذف، نام دامنه را تایپ کنید: <input class="pcdna-input" name="confirm" dir="ltr" autocomplete="off" placeholder="' . View::e($domain) . '" aria-label="تأیید حذف"></label>'
                . '<button type="submit" class="pcdna-btn pcdna-btn-sm pcdna-btn-danger">' . View::icon('trash') . '<span>حذف از CDN</span></button></form>';
            $t .= '<tr data-op-domain="' . View::e($domain) . '"><td class="pcdna-domain-cell"><a class="pcdna-domain" href="' . View::url(['page' => 'opmanage', 'domain' => $domain]) . '">'
                . View::ltr($domain) . '</a><div class="pcdna-tn-line">' . View::badge('اپراتور', 'violet') . '</div></td>'
                . '<td data-label="وضعیت">' . Pages::cdnBadge($st) . '</td><td data-label="NS">' . $ns . '</td><td data-label="SSL">' . $ssl . '</td>'
                . '<td class="pcdna-traffic" data-label="ترافیک این ماه">' . $traffic . '</td>'
                . '<td data-label="پلن"><span class="pcdna-small">' . View::e(self::templateLabel($domain, $d)) . '</span>'
                . '<details class="pcdna-op-more"><summary class="pcdna-small">تغییر</summary>' . $plan . '</details></td>'
                . '<td data-label="یادداشت"><span class="pcdna-op-note-text">' . ($note !== '' ? View::e($note) : '<span class="pcdna-muted">—</span>') . '</span>'
                . '<details class="pcdna-op-more"><summary class="pcdna-small">ویرایش</summary>' . $noteForm . '</details></td>'
                . '<td class="pcdna-actions"><a class="pcdna-btn pcdna-btn-sm pcdna-btn-primary" href="' . View::url(['page' => 'opmanage', 'domain' => $domain]) . '">'
                . View::icon('sliders') . '<span>مدیریت</span></a>'
                . '<details class="pcdna-menu"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-icon" aria-label="عملیات بیشتر" title="عملیات بیشتر">' . View::icon('more') . '</summary>'
                . '<div class="pcdna-menu-list">' . $menu . '</div></details>'
                . '<details class="pcdna-op-more pcdna-op-share"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost">' . View::icon('link') . '<span>اشتراک</span></summary>' . $shares . '</details>'
                . '<details class="pcdna-op-more pcdna-op-del"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost">' . View::icon('trash') . '<span>حذف</span></summary>' . $del . '</details>'
                . '</td></tr>';
        }
        $t .= '</tbody></table></div>';
        return View::card('دامنه‌های اپراتور (' . View::n(count($sites)) . ')', $t, '', 'pcdna-flush', 'globe');
    }

    /** SPEC §20.2: members / pending invites of an operator site + the admin's invite form. */
    private static function shareBox(string $domain): string
    {
        $rows = \PasargadCdn\Shares::forOwner(['operator_domain' => $domain]);
        $h = '<ul class="pcdna-bullets pcdna-op-members">';
        foreach ($rows as $r) {
            $h .= '<li data-share-id="' . (int) $r->id . '">' . View::ltr((string) $r->email) . ' — ' . View::e(\PasargadCdn\Shares::roleLabel((string) $r->role))
                . ($r->status === 'pending' ? ' ' . View::badge('در انتظار', 'warn') : '')
                . View::postButton(['page' => 'operator'], 'op_share_revoke', ['domain' => $domain, 'id' => (int) $r->id], 'لغو', 'pcdna-btn pcdna-btn-sm pcdna-btn-ghost',
                    'دسترسی ' . $r->email . ' لغو شود؟') . '</li>';
        }
        $h .= $rows ? '</ul>' : '<li class="pcdna-muted">هنوز با کسی به اشتراک گذاشته نشده است.</li></ul>';
        return $h . '<form method="post" action="' . self::url() . '" class="pcdna-form-inline pcdna-op-share-form">' . View::csrf()
            . '<input type="hidden" name="a" value="op_share_invite"><input type="hidden" name="domain" value="' . View::e($domain) . '">'
            . '<input class="pcdna-input" type="email" name="email" dir="ltr" required maxlength="191" placeholder="name@example.com" aria-label="ایمیل">'
            . View::select('role', ['viewer' => 'مشاهده‌گر', 'dns' => 'مدیر DNS', 'editor' => 'ویرایشگر'], 'viewer', ' aria-label="نقش"')
            . '<button type="submit" class="pcdna-btn pcdna-btn-sm pcdna-btn-primary">دعوت</button></form>';
    }

    // ------------------------------------------------------------------ manage (client app in an admin context)

    public static function manage(string $domain, string $lang): string
    {
        $back = '<p class="pcdna-back"><a href="' . self::url() . '">→ بازگشت به دامنه‌های اپراتور</a></p>';
        if (!Env::adminHasAccess()) {
            return $back . View::alert('bad', 'نقش مدیریتی شما به این ماژول دسترسی ندارد.');
        }
        $site = self::site($domain);
        if (is_string($site)) {
            return $back . View::alert('bad', View::e($site));
        }
        $server = self::server();
        if (!$server || ($server->type ?? '') !== 'pasargadcdn') {
            return $back . View::alert('bad', 'سرور CDN افزونه تنظیم نشده است.');
        }
        $domain = strtolower((string) $site['domain']);
        $token = self::bind($domain, (int) $server->id);
        $lang = $lang === 'en' ? 'en' : 'fa';
        $boot = ['serviceId' => max(1, (int) ($site['id'] ?? 1)), 'lang' => $lang, 'domain' => $domain, 'active' => true, 'site' => $site, 'error' => null,
            'billing' => null, 'wallet' => null, 'growth' => ['persist' => false],
            'admin' => ['operator' => true, 'note' => (string) ($site[self::NOTE_FIELD] ?? ''), 'backUrl' => View::url(['page' => 'operator'], false), 'status' => '']];
        $base = '../modules/servers/pasargadcdn';
        $assets = function_exists('pasargadcdn_assets') ? \pasargadcdn_assets($base, $lang) : ['css' => $base . '/assets/app.css', 'scripts' => []];
        $api = View::url(['page' => 'api', 'op' => $token] + (Env::whmcsToken() !== '' ? ['token' => Env::whmcsToken()] : []), false);
        $h = '<div class="pcdna-manage-head"><a class="pcdna-btn pcdna-btn-sm" href="' . self::url() . '">→ دامنه‌های اپراتور</a>'
            . '<h3>مدیریت کامل ' . View::ltr($domain) . '</h3><span class="pcdna-muted">' . View::badge('اپراتور', 'violet') . ' · بدون سرویس WHMCS'
            . ' · ' . Pages::cdnBadge((string) ($site['status'] ?? '')) . '</span>'
            . '<span class="pcdna-op-lang">' . ($lang === 'fa' ? '<strong>فارسی</strong>' : '<a href="' . View::url(['page' => 'opmanage', 'domain' => $domain]) . '">فارسی</a>')
            . ' · ' . ($lang === 'en' ? '<strong>English</strong>' : '<a href="' . View::url(['page' => 'opmanage', 'domain' => $domain, 'lang' => 'en']) . '" lang="en">English</a>') . '</span></div>';
        $h .= '<link rel="stylesheet" href="' . View::e($assets['css']) . '">'
            . '<div id="pcdn-app" class="pcdn" dir="' . ($lang === 'en' ? 'ltr' : 'rtl') . '" lang="' . $lang . '" data-api="' . View::e($api) . '" data-csrf="' . View::e(Env::csrf()) . '" data-admin="1" data-operator="1">'
            . '<noscript><div class="pcdn-alert pcdn-alert-danger">برای مدیریت CDN، جاوااسکریپت مرورگر را فعال کنید.</div></noscript>'
            . '<div class="pcdn-boot-loading" role="status">در حال بارگذاری پنل CDN…</div></div>'
            . '<script type="application/json" id="pcdn-boot">' . (function_exists('pasargadcdn_boot_json') ? \pasargadcdn_boot_json($boot) : '{}') . '</script>';
        foreach ($assets['scripts'] as $s) {
            $h .= '<script src="' . View::e($s) . '" defer></script>';
        }
        Env::log('operator site ' . $domain . ' opened in full management by ' . Env::adminLabel());
        return $h;
    }

    /** A new context token of this admin session for $domain (oldest dropped beyond SESSION_MAX). */
    private static function bind(string $domain, int $serverId): string
    {
        $all = isset($_SESSION[self::SESSION]) && is_array($_SESSION[self::SESSION]) ? $_SESSION[self::SESSION] : [];
        foreach ($all as $k => $c) {
            if (is_array($c) && ($c['domain'] ?? '') === $domain && (int) ($c['server'] ?? 0) === $serverId && (int) ($c['admin'] ?? 0) === Env::adminId()) {
                $all[$k]['checked'] = time();
                $_SESSION[self::SESSION] = $all;
                return (string) $k;
            }
        }
        $tok = bin2hex(random_bytes(12));
        $all[$tok] = ['domain' => $domain, 'server' => $serverId, 'admin' => Env::adminId(), 'checked' => time()];
        while (count($all) > self::SESSION_MAX) {
            array_shift($all);
        }
        $_SESSION[self::SESSION] = $all;
        return $tok;
    }

    /** The bound context of $token for this admin, re-checked against the controller every RECHECK seconds. */
    public static function context(string $token): ?array
    {
        if (!preg_match('/^[0-9a-f]{24}$/D', $token)) {
            return null;
        }
        $c = $_SESSION[self::SESSION][$token] ?? null;
        if (!is_array($c) || (int) ($c['admin'] ?? 0) !== Env::adminId() || !is_string($c['domain'] ?? null)) {
            return null;
        }
        $server = Capsule::table('tblservers')->where('id', (int) ($c['server'] ?? 0))->first();
        if (!$server || ($server->type ?? '') !== 'pasargadcdn') {
            return null;
        }
        if (time() - (int) ($c['checked'] ?? 0) > self::RECHECK) {
            try {
                $s = Env::api(10, $server)->get(ApiClient::site($c['domain']));
            } catch (\Throwable $e) {
                $s = null;
            }
            if (!Data::isOperator($s)) {
                unset($_SESSION[self::SESSION][$token]);
                return null;
            }
            $_SESSION[self::SESSION][$token]['checked'] = time();
        }
        return ['domain' => $c['domain'], 'server' => $server];
    }

    /** page=api&op=<token>: the app's calls in the operator context (JSON or a Download). */
    public static function api(array $get, string $method): array
    {
        if (!Env::adminHasAccess()) {
            return [403, ['detail' => 'نقش مدیریتی شما به این ماژول دسترسی ندارد.']];
        }
        $ctx = self::context(is_string($get['op'] ?? null) ? $get['op'] : '');
        if ($ctx === null) {
            return [404, ['detail' => 'دامنهٔ اپراتور یافت نشد یا نشست مدیریت آن منقضی شده است؛ صفحه را دوباره باز کنید.']];
        }
        $csrf = (string) ($_SERVER['HTTP_X_PCDN_CSRF'] ?? '');
        $sessionCsrf = (string) ($_SESSION['pasargadcdn_admin_csrf'] ?? '');
        if (($get['action'] ?? '') === 'client-error') {
            // SPEC §18.4 in the operator context: sanitised + rate limited + module-logged (no service → not forwarded)
            return ClientApi::clientError(['method' => $method, 'id' => '', 'admin_id' => Env::adminId(),
                'body' => $method === 'POST' ? Admin::readBody(ClientApi::CLIENT_ERROR_MAX_BODY + 1) : '',
                'csrf' => $csrf, 'session_csrf' => $sessionCsrf], $_SESSION, Admin::$apiFactory);
        }
        $path = is_string($get['path'] ?? null) ? $get['path'] : '';
        $body = $method === 'POST' || $method === 'PUT' ? Admin::readBody(ClientApi::maxBody($method, $path) + 1) : '';
        $query = $get;
        unset($query['module'], $query['page'], $query['service'], $query['id'], $query['path'], $query['token'], $query['action'], $query['op']);
        return ClientApi::handle([
            'method' => $method, 'id' => '', 'path' => $path, 'query' => $query, 'body' => $body,
            'csrf' => $csrf, 'session_csrf' => $sessionCsrf, 'client_id' => 0,
            'admin_id' => Env::adminId(), 'admin_user' => Env::adminName(),
            'context' => $ctx, 'lang' => (string) ($_SERVER['HTTP_X_PCDN_LANG'] ?? ''),
        ], Admin::$apiFactory);
    }
}
