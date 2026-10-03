<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use PasargadCdn\FeatureOverrides;
use PasargadCdn\Transfers;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\FeatureEditor', false)) {
    return;
}

/**
 * SPEC §21 — «امکانات اختصاصی»: per-domain feature overrides set by the admin (the storage and the merge into every plan
 * push live in the server module's FeatureOverrides; this is the editor).
 *
 *  - page=features: search a CDN service / operator domain + the list of every domain with overrides;
 *  - page=features&service=<id> | &domain=<operator domain>: every plan field of the controller's plan model (the four
 *    top-level ones and every key of the site's live plan.features, so new controller features appear automatically) with
 *    «طبق پلن» or an explicit value, the plan value and the effective value; quick actions «همه امکانات روشن» (every
 *    boolean on, limits untouched) and «بازگشت به پلن» (clear all);
 *  - actions (POST, CSRF checked by Admin): features_save / features_all_on / features_clear. Each stores the overrides
 *    and immediately pushes the merged plan with PATCH /api/v1/sites/{d}/plan; a refused push (controller 422) restores
 *    the previous overrides and shows the controller's message. Every change is logged with the admin's username.
 */
final class FeatureEditor
{
    const ACTIONS = ['features_save', 'features_all_on', 'features_clear'];

    /** Persian labels of the known plan fields (a field the controller adds later is shown by its key). */
    const LABELS = [
        'bandwidth_limit_gb' => 'ترافیک ماهانه (GB، ۰ = نامحدود)',
        'max_records' => 'حداکثر رکورد DNS',
        'ssl_allowed' => 'SSL رایگان',
        'rate_limit_rps' => 'محدودیت نرخ کل سایت (درخواست در ثانیه، ۰ = بدون محدودیت)',
        'features.waf' => 'فایروال برنامه وب (WAF)',
        'features.ddos' => 'محافظت DDoS',
        'features.load_balancer' => 'توزیع بار',
        'features.image_optimization' => 'بهینه‌سازی تصویر',
        'features.custom_ssl' => 'گواهی SSL اختصاصی',
        'features.dnssec' => 'DNSSEC',
        'features.max_page_rules' => 'حداکثر قوانین صفحه',
        'features.max_firewall_rules' => 'حداکثر قوانین فایروال',
        'features.max_ratelimit_rules' => 'حداکثر قوانین محدودیت نرخ',
        'features.max_pools' => 'حداکثر استخر توزیع بار',
        'features.tunnel' => 'حالت تونل (VPN)',
        'features.max_tunnel_paths' => 'حداکثر مسیر تونل',
        'features.max_tunnel_connections' => 'حداکثر اتصال تونل (۰ = نامحدود)',
        'features.tunnel_max_mbps' => 'سقف سرعت اتصال تونل (Mbps، ۰ = بدون سقف)',
        'features.max_tunnel_origins' => 'حداکثر مبدأ هر مسیر تونل',
        'features.edge_group' => 'گروه نود',
        'features.max_transform_rules' => 'حداکثر قوانین تبدیل',
        'features.max_redirects' => 'حداکثر ریدایرکت',
        'features.log_export' => 'ارسال لاگ',
        'features.max_webhooks' => 'حداکثر وب‌هوک',
        'features.sla_target' => 'هدف SLA (٪)',
        'features.l4_proxy' => 'پراکسی TCP/UDP',
        'features.max_l4_apps' => 'حداکثر برنامهٔ TCP/UDP',
        'features.storage_gb' => 'فضای ذخیره‌سازی (GB)',
        'features.edge_functions' => 'توابع لبه',
        'features.max_functions' => 'حداکثر تابع لبه',
        'features.dns_secondary' => 'DNS ثانویه',
        'features.waiting_room' => 'اتاق انتظار',
        'features.access' => 'دسترسی محافظت‌شده',
    ];
    /** Types of the top-level fields when the live plan has no value for them. */
    const TOP_TYPES = ['bandwidth_limit_gb' => 0, 'max_records' => 100, 'ssl_allowed' => false, 'rate_limit_rps' => 0];

    // ------------------------------------------------------------------ scope / plan

    /** ['kind' => service|operator, 'key', 'domain', 'sid', 'svc'] or an error string. */
    public static function scope(array $in)
    {
        $sid = (int) ($in['service'] ?? 0);
        if ($sid > 0) {
            $svc = Data::serviceQuery()->where('h.id', $sid)->first(['h.id', 'h.userid', 'h.packageid', 'h.server', 'h.domain', 'h.domainstatus',
                'p.name as product', 'c.firstname', 'c.lastname', 'c.companyname']);
            if (!$svc) {
                return 'سرویس CDN #' . $sid . ' پیدا نشد.';
            }
            if (Transfers::guarded($sid)) {
                return 'دامنهٔ سرویس #' . $sid . ' به اپراتور منتقل شده است؛ امکانات اختصاصی آن را از «دامنه‌های اپراتور» ویرایش کنید.';
            }
            $domain = Env::domain((string) $svc->domain);
            if (!Env::validHostname($domain)) {
                return 'دامنهٔ سرویس #' . $sid . ' معتبر نیست.';
            }
            if (!in_array((string) $svc->domainstatus, Data::LIVE, true)) {
                return 'امکانات اختصاصی فقط برای سرویس فعال یا معلق قابل تنظیم است (وضعیت فعلی: ' . (string) $svc->domainstatus . ').';
            }
            return ['kind' => 'service', 'key' => FeatureOverrides::serviceKey($sid), 'domain' => $domain, 'sid' => $sid, 'svc' => $svc];
        }
        $domain = Env::domain((string) ($in['domain'] ?? ''));
        if ($domain === '' || !Env::validHostname($domain)) {
            return 'دامنه یا سرویس مشخص نیست؛ از «سایت‌ها»، «دامنه‌های اپراتور» یا جستجوی همین صفحه وارد شوید.';
        }
        return ['kind' => 'operator', 'key' => FeatureOverrides::domainKey($domain), 'domain' => $domain, 'sid' => 0, 'svc' => null];
    }

    private static function server(array $sc)
    {
        if ($sc['svc']) {
            $s = Capsule::table('tblservers')->where('id', (int) $sc['svc']->server)->first();
            if ($s && $s->type === 'pasargadcdn') {
                return $s;
            }
        }
        return Env::server();
    }

    /** The live controller site of a scope (the operator site must still be an operator site), or an error string. */
    public static function live(array $sc)
    {
        if ($sc['kind'] === 'operator') {
            return Operator::site($sc['domain']);
        }
        try {
            return Env::api(10, self::server($sc))->get(ApiClient::site($sc['domain']));
        } catch (\Throwable $e) {
            return $e instanceof ApiException && $e->getCode() === 404 ? 'سایت ' . $sc['domain'] . ' روی کنترلر وجود ندارد (ابتدا آن را روی CDN بسازید).'
                : 'دریافت سایت از کنترلر ناموفق بود: ' . $e->getMessage();
        }
    }

    /** Module params of a service (product module settings + configurable options), as WHMCS passes them to the module. */
    public static function params(array $sc): array
    {
        $svc = $sc['svc'];
        $pid = (int) $svc->packageid;
        $params = ['serviceid' => (int) $svc->id, 'userid' => (int) $svc->userid, 'pid' => $pid, 'packageid' => $pid, 'domain' => $sc['domain'], 'configoptions' => []];
        $prod = Capsule::table('tblproducts')->where('id', $pid)->first();
        for ($i = 1; $i <= 24; $i++) {
            $params['configoption' . $i] = $prod ? (string) ($prod->{'configoption' . $i} ?? '') : '';
        }
        if (function_exists('pasargadcdn_config_options')) {
            $params['configoptions'] = \pasargadcdn_config_options([(int) $svc->id])[(int) $svc->id] ?? [];
        }
        return $params;
    }

    /** The bare product plan of a service (no overrides); null for an operator site (no product). */
    public static function productPlan(array $sc): ?array
    {
        return $sc['kind'] === 'service' ? \pasargadcdn_plan(['pcdn_plan_base' => true] + self::params($sc)) : null;
    }

    /** field => sample value (its type) of every plan field of the live site: the top-level four + every live feature. */
    public static function fields(array $live): array
    {
        $plan = (array) ($live['plan'] ?? []);
        $out = [];
        foreach (FeatureOverrides::TOP as $k) {
            $v = $plan[$k] ?? null;
            $out[$k] = is_scalar($v) ? $v : self::TOP_TYPES[$k];
        }
        foreach ((array) ($plan['features'] ?? []) as $k => $v) {
            $f = 'features.' . $k;
            if (is_string($k) && is_scalar($v) && preg_match(FeatureOverrides::FIELD_RE, $f)) {
                $out[$f] = $v;
            }
        }
        return $out;
    }

    private static function label(string $f): string
    {
        return self::LABELS[$f] ?? (strpos($f, 'features.') === 0 ? substr($f, 9) : $f);
    }

    private static function isBool(string $f, $like): bool
    {
        return is_bool($like) || $f === 'ssl_allowed';
    }

    private static function show($v): string
    {
        if ($v === null) {
            return '<span class="pcdna-muted">—</span>';
        }
        if (is_bool($v)) {
            return $v ? View::badge('روشن', 'ok') : View::badge('خاموش', 'muted');
        }
        if (is_float($v)) {
            return '<span class="pcdna-num">' . View::n($v, floor($v) == $v ? 0 : 2) . '</span>';
        }
        return is_int($v) ? '<span class="pcdna-num">' . View::n($v) . '</span>' : View::ltr((string) $v);
    }

    private static function plain($v): string
    {
        return is_bool($v) ? ($v ? 'on' : 'off') : (is_scalar($v) ? (string) $v : json_encode($v));
    }

    /** Badge «امکانات اختصاصی (n)» linking to the editor ('' when n = 0) — Sites list, operator list. */
    public static function badge(int $n, array $q): string
    {
        if ($n <= 0) {
            return '';
        }
        return '<a class="pcdna-fo-badge" href="' . View::url($q) . '" data-overrides="' . $n . '" title="این دامنه امکانات اختصاصی دارد (جدا از پلن محصول)">'
            . View::badge('امکانات اختصاصی (' . View::n($n) . ')', 'violet') . '</a>';
    }

    /**
     * SPEC §21: Operator «تغییر پلن» to a template — the template becomes the base of the overridden fields (clearing them
     * later restores the template's value) and the overrides stay on top. Returns the plan to PATCH.
     */
    public static function operatorTemplate(string $domain, array $tpl): array
    {
        $key = FeatureOverrides::domainKey($domain);
        $ov = FeatureOverrides::get($key);
        if (!$ov['v']) {
            return $tpl;
        }
        $base = $ov['base'];
        foreach ($ov['v'] as $f => $_) {
            $tv = FeatureOverrides::valueOf($tpl, $f);
            if ($tv !== null) {
                $base[$f] = $tv;
            }
        }
        FeatureOverrides::save($key, $ov['v'], $base, (int) $ov['admin_id']);
        return FeatureOverrides::apply($tpl, $ov['v']);
    }

    // ------------------------------------------------------------------ actions

    public static function action(string $action, array $post, int $admin): array
    {
        if (!Env::adminHasAccess()) {
            return [[['bad', 'نقش مدیریتی شما به این ماژول دسترسی ندارد.']], []];
        }
        $sc = self::scope(['service' => $post['service'] ?? 0, 'domain' => Env::input($post['domain'] ?? '')]);
        if (is_string($sc)) {
            return [[['bad', View::e($sc)]], []];
        }
        $live = self::live($sc);
        if (is_string($live)) {
            return [[['bad', View::e($live)]], []];
        }
        if (!FeatureOverrides::ensure()) {
            return [[['bad', 'جدول ' . FeatureOverrides::TABLE . ' ساخته نشد؛ دسترسی پایگاه داده را بررسی کنید.']], []];
        }
        FeatureOverrides::reset();
        $old = FeatureOverrides::get($sc['key']);
        $fields = self::fields($live);
        $errors = [];
        if ($action === 'features_clear') {
            $new = [];
        } elseif ($action === 'features_all_on') {
            $new = $old['v'];
            foreach ($fields as $f => $like) {
                if (self::isBool($f, $like) && !isset(FeatureOverrides::ENUMS[$f])) {
                    $new[$f] = true;
                }
            }
        } else {
            $in = is_array($post['ov'] ?? null) ? $post['ov'] : [];
            $new = [];
            foreach ($old['v'] as $f => $v) {
                if (!isset($fields[$f])) {
                    $new[$f] = $v;   // a field the live plan no longer lists stays as it is
                }
            }
            foreach ($fields as $f => $like) {
                $raw = $in[$f] ?? '';
                if (!is_string($raw)) {
                    continue;
                }
                $raw = Env::input($raw);
                if ($raw === '' || $raw === 'inherit') {
                    continue;
                }
                [$ok, $val] = FeatureOverrides::validate($f, $raw, $like);
                if ($ok) {
                    $new[$f] = $val;
                } else {
                    $errors[$f] = $val;
                }
            }
            if ($errors) {
                $list = [];
                foreach ($errors as $f => $m) {
                    $list[] = '«' . View::e(self::label($f)) . '»: ' . View::e($m);
                }
                return [[['bad', 'ذخیره نشد؛ مقادیر نامعتبر: ' . implode('؛ ', $list)]], ['fo_errors' => $errors, 'fo_input' => $in]];
            }
        }
        return self::apply($sc, $live, $old, $new, $action, $admin);
    }

    /** Store + push; restores the previous overrides when the controller refuses the plan. */
    private static function apply(array $sc, array $live, array $old, array $new, string $action, int $admin): array
    {
        $diff = [];
        foreach ($new as $f => $v) {
            if (!array_key_exists($f, $old['v']) || $old['v'][$f] !== $v) {
                $diff[] = $f . ': ' . (array_key_exists($f, $old['v']) ? self::plain($old['v'][$f]) : 'plan') . ' → ' . self::plain($v);
            }
        }
        foreach ($old['v'] as $f => $v) {
            if (!array_key_exists($f, $new)) {
                $diff[] = $f . ': ' . self::plain($v) . ' → plan';
            }
        }
        if (!$diff) {
            return [[['info', 'تغییری ثبت نشد؛ مقادیر همان مقادیر فعلی است.']], []];
        }
        // base: the value the site had before the field was first overridden (kept across edits)
        $base = [];
        foreach ($new as $f => $_) {
            $base[$f] = array_key_exists($f, $old['base']) ? $old['base'][$f] : FeatureOverrides::valueOf((array) ($live['plan'] ?? []), $f);
        }
        $base = array_filter($base, function ($v) {
            return $v !== null;
        });
        FeatureOverrides::save($sc['key'], $new, $base, $admin);
        FeatureOverrides::reset();
        try {
            $payload = self::payload($sc, $old, $new);
            if ($payload) {
                Env::api(15, self::server($sc))->patch(ApiClient::site($sc['domain']) . '/plan', $payload);
            }
        } catch (\Throwable $e) {
            FeatureOverrides::save($sc['key'], $old['v'], $old['base'], (int) $old['admin_id']);
            FeatureOverrides::reset();
            Env::log('feature overrides of ' . $sc['domain'] . ' (' . $sc['key'] . ') NOT changed — controller refused the plan: ' . $e->getMessage() . ' — '
                . Env::adminLabel(), $sc['svc'] ? (int) $sc['svc']->userid : 0);
            $msg = $e instanceof ApiException && $e->getCode() === 422 ? 'کنترلر مقدارها را نپذیرفت (۴۲۲): ' : 'ارسال پلن به کنترلر ناموفق بود: ';
            return [[['bad', View::e($msg . $e->getMessage()) . ' — هیچ تغییری ذخیره نشد.']], []];
        }
        $what = ['features_clear' => 'cleared (back to the plan)', 'features_all_on' => 'all features on', 'features_save' => 'saved'][$action];
        Env::log('feature overrides of ' . $sc['domain'] . ' (' . $sc['key'] . ') ' . $what . ': ' . implode(', ', $diff) . ' — ' . Env::adminLabel(),
            $sc['svc'] ? (int) $sc['svc']->userid : 0);
        Pages::reset();
        $n = count($new);
        $done = $action === 'features_clear' ? 'امکانات اختصاصی ' . View::ltr($sc['domain']) . ' حذف شد و پلن ' . ($sc['kind'] === 'service' ? 'محصول' : 'قبلی') . ' دوباره اعمال شد.'
            : 'امکانات اختصاصی ' . View::ltr($sc['domain']) . ' ذخیره و روی CDN اعمال شد (' . View::n($n) . ' مورد اختصاصی).';
        return [[['ok', $done]], []];
    }

    /**
     * The plan to PATCH: for a service the same plan Create / ChangePackage send (product + options + top-ups, the new
     * overrides merged by pasargadcdn_plan()); for an operator site only the overridden fields. A field whose override was
     * removed and that the product plan does not send (or any field of an operator site) gets its stored base value back.
     */
    public static function payload(array $sc, array $old, array $new): array
    {
        $prod = null;
        if ($sc['kind'] === 'service') {
            $payload = \pasargadcdn_cap_plan(self::params($sc));
            $prod = self::productPlan($sc);
        } else {
            $payload = FeatureOverrides::apply([], $new);
        }
        foreach ($old['v'] as $f => $_) {
            if (array_key_exists($f, $new) || ($prod !== null && FeatureOverrides::valueOf($prod, $f) !== null)) {
                continue;
            }
            if (array_key_exists($f, $old['base'])) {
                $payload = FeatureOverrides::apply($payload, [$f => $old['base'][$f]]);
            }
        }
        return $payload;
    }

    /**
     * SPEC §21 / §19: after a transfer with «حذف امکانات اختصاصی» the dropped values are replaced on the controller: by
     * the destination service's plan (client destination) or by their base values (operator destination). Best effort.
     */
    public static function restoreAfterDrop(string $domain, array $dropped, int $sid): ?string
    {
        if (!$dropped['v']) {
            return null;
        }
        try {
            if ($sid > 0) {
                $sc = self::scope(['service' => $sid]);
                if (is_string($sc)) {
                    return $sc;
                }
                $payload = self::payload($sc, $dropped, []);
                $server = self::server($sc);
            } else {
                $payload = self::payload(['kind' => 'operator'], $dropped, []);
                $server = Env::server();
            }
            if ($payload) {
                Env::api(15, $server)->patch(ApiClient::site($domain) . '/plan', $payload);
            }
            return null;
        } catch (\Throwable $e) {
            return $e->getMessage();
        }
    }

    // ------------------------------------------------------------------ pages

    public static function page(array $get, array $state): string
    {
        if (!Env::adminHasAccess()) {
            return View::alert('bad', 'نقش مدیریتی شما به این ماژول دسترسی ندارد.');
        }
        $in = ['service' => (int) ($get['service'] ?? 0), 'domain' => Env::input($get['domain'] ?? '')];
        if ($in['service'] <= 0 && $in['domain'] === '') {
            return self::startPage(Env::input($get['q'] ?? ''));
        }
        $back = '<p class="pcdna-back"><a href="' . View::url(['page' => 'features']) . '">→ بازگشت به امکانات اختصاصی</a></p>';
        $sc = self::scope($in);
        if (is_string($sc)) {
            return $back . View::alert('bad', View::e($sc));
        }
        $ping = Pages::ping();
        if (!$ping['ok']) {
            return $back . Pages::ctlError($ping);
        }
        $live = self::live($sc);
        if (is_string($live)) {
            return $back . View::alert('bad', View::e($live));
        }
        FeatureOverrides::reset();
        return $back . self::editor($sc, $live, $state);
    }

    private static function startPage(string $term): string
    {
        $intro = '<p class="pcdna-muted">هر امکان پلن (مثل اتاق انتظار، دسترسی محافظت‌شده، تونل یا سقف قوانین) را می‌توانید فقط برای یک دامنه، جدا از پلن محصول، '
            . 'روشن یا تغییر دهید. مقدار اختصاصی در همهٔ ارسال‌های بعدی پلن (ارتقا، تمدید، شارژ ترافیک، انتقال) حفظ می‌شود تا آن را به «طبق پلن» برگردانید. '
            . 'امکانات اختصاصی هیچ فاکتوری نمی‌سازند.</p>';
        $f = '<form method="get" action="' . View::e((string) (parse_url(View::$link, PHP_URL_PATH) ?: 'addonmodules.php')) . '" class="pcdna-filters" role="search" data-features-search="1">'
            . '<input type="hidden" name="module" value="' . View::e(Env::MODULE) . '"><input type="hidden" name="page" value="features">'
            . '<label class="pcdna-search">' . View::icon('search') . '<input type="search" name="q" class="pcdna-input" value="' . View::e($term)
            . '" placeholder="دامنه، #شناسهٔ سرویس، نام یا ایمیل مشتری" aria-label="جستجوی دامنه برای امکانات اختصاصی"></label>'
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('search') . '<span>جستجو</span></button></form>';
        if ($term !== '') {
            [$rows] = Data::services(['q' => $term], 1, 25);
            $ops = [];
            foreach (array_keys(Data::operatorDomains()) as $d) {
                if (stripos($d, $term) !== false) {
                    $ops[] = $d;
                }
            }
            if (!$rows && !$ops) {
                $f .= '<p class="pcdna-muted" data-features-none="1">دامنه‌ای پیدا نشد.</p>';
            } else {
                $f .= '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-fo-list" data-features-results="1"><thead><tr><th>دامنه</th><th>مالک</th><th>سرویس</th><th>وضعیت</th><th><span class="pcdna-sr">عملیات</span></th></tr></thead><tbody>';
                foreach ($rows as $r) {
                    $live = in_array((string) $r->domainstatus, Data::LIVE, true);
                    $f .= '<tr data-result-service="' . (int) $r->id . '"><td data-label="دامنه">' . View::ltr((string) $r->domain) . '</td><td data-label="مالک"><a href="'
                        . View::e(Data::clientUrl((int) $r->userid)) . '">' . View::e(Data::clientName($r)) . '</a></td><td data-label="سرویس">#' . View::n((int) $r->id) . ' · '
                        . View::e((string) $r->product) . '</td><td data-label="وضعیت">' . Pages::whmcsBadge((string) $r->domainstatus) . '</td><td class="pcdna-actions">'
                        . ($live ? '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-primary" href="' . View::url(['page' => 'features', 'service' => (int) $r->id]) . '">'
                            . View::icon('sliders') . '<span>امکانات</span></a>' : View::badge('فقط سرویس فعال یا معلق', 'muted')) . '</td></tr>';
                }
                foreach ($ops as $d) {
                    $f .= '<tr data-result-operator="' . View::e($d) . '"><td data-label="دامنه">' . View::ltr($d) . '</td><td data-label="مالک">' . View::badge('اپراتور', 'violet')
                        . '</td><td data-label="سرویس">—</td><td data-label="وضعیت">—</td><td class="pcdna-actions"><a class="pcdna-btn pcdna-btn-sm pcdna-btn-primary" href="'
                        . View::url(['page' => 'features', 'domain' => $d]) . '">' . View::icon('sliders') . '<span>امکانات</span></a></td></tr>';
                }
                $f .= '</tbody></table></div>';
            }
        }
        return View::card('امکانات اختصاصی دامنه', $intro . $f, '', '', 'sliders') . self::listCard();
    }

    /** Every domain with overrides (newest first). */
    private static function listCard(): string
    {
        $rows = [];
        try {
            if (Env::hasTable(FeatureOverrides::TABLE)) {
                $rows = Capsule::table(FeatureOverrides::TABLE)->orderBy('updated_at', 'desc')->orderBy('id', 'desc')->limit(200)->get()->all();
            }
        } catch (\Throwable $e) {
            $rows = [];
        }
        if (!$rows) {
            return View::card('دامنه‌های دارای امکانات اختصاصی', View::emptyState('هنوز برای هیچ دامنه‌ای امکان اختصاصی تنظیم نشده است',
                'دامنه را جستجو کنید یا از منوی «سایت‌ها» / «دامنه‌های اپراتور» گزینهٔ «امکانات اختصاصی» را بزنید.', 'sliders'), '', '', 'history');
        }
        $sids = [];
        $admins = [];
        foreach ($rows as $r) {
            if (strpos((string) $r->key, 'service:') === 0) {
                $sids[] = (int) substr((string) $r->key, 8);
            }
            $admins[] = (int) $r->admin_id;
        }
        $svcs = $sids ? Data::serviceQuery()->whereIn('h.id', $sids)->get(['h.id', 'h.userid', 'h.domain', 'c.firstname', 'c.lastname', 'c.companyname'])->keyBy('id')->all() : [];
        $names = [];
        try {
            $names = Capsule::table('tbladmins')->whereIn('id', array_unique($admins) ?: [0])->pluck('username', 'id')->all();
        } catch (\Throwable $e) {
            $names = [];
        }
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-fo-list" data-features-list="1"><thead><tr><th>دامنه</th><th>مالک</th><th>امکانات اختصاصی</th><th>آخرین تغییر</th><th><span class="pcdna-sr">عملیات</span></th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $j = json_decode((string) $r->overrides, true);
            $v = is_array($j['v'] ?? null) ? $j['v'] : [];
            $key = (string) $r->key;
            if (strpos($key, 'service:') === 0) {
                $sid = (int) substr($key, 8);
                $s = $svcs[$sid] ?? null;
                $domain = $s ? (string) $s->domain : '—';
                $owner = $s ? '<a href="' . View::e(Data::clientUrl((int) $s->userid)) . '">' . View::e(Data::clientName($s)) . '</a> · <a href="'
                    . View::e(Data::serviceUrl((int) $s->userid, $sid)) . '">#' . View::n($sid) . '</a>' : 'سرویس #' . View::n($sid);
                $q = ['page' => 'features', 'service' => $sid];
            } else {
                $domain = substr($key, 7);
                $owner = View::badge('اپراتور', 'violet');
                $q = ['page' => 'features', 'domain' => $domain];
            }
            $list = [];
            foreach ($v as $f => $val) {
                $list[] = self::label((string) $f) . ' = ' . (is_bool($val) ? ($val ? 'روشن' : 'خاموش') : (string) $val);
            }
            $who = (int) $r->admin_id > 0 ? 'مدیر ' . ($names[(int) $r->admin_id] ?? '#' . View::n((int) $r->admin_id)) : '';
            $t .= '<tr data-fo-key="' . View::e($key) . '"><td data-label="دامنه">' . View::ltr($domain) . '</td><td data-label="مالک">' . $owner . '</td>'
                . '<td data-label="امکانات اختصاصی">' . View::badge(View::n(count($v)) . ' مورد', 'violet') . '<div class="pcdna-small pcdna-muted">' . View::e(implode('، ', array_slice($list, 0, 6))
                    . (count($list) > 6 ? '، …' : '')) . '</div></td>'
                . '<td data-label="آخرین تغییر"><span class="pcdna-small">' . View::date((string) $r->updated_at, true) . '</span>' . ($who !== '' ? '<div class="pcdna-small pcdna-muted">' . View::e($who) . '</div>' : '') . '</td>'
                . '<td class="pcdna-actions"><a class="pcdna-btn pcdna-btn-sm" href="' . View::url($q) . '">' . View::icon('sliders') . '<span>ویرایش</span></a></td></tr>';
        }
        $t .= '</tbody></table></div>';
        return View::card('دامنه‌های دارای امکانات اختصاصی (' . View::n(count($rows)) . ')', $t, '', 'pcdna-flush', 'history');
    }

    private static function editor(array $sc, array $live, array $state): string
    {
        $ov = FeatureOverrides::get($sc['key']);
        $prod = self::productPlan($sc);
        $plan = (array) ($live['plan'] ?? []);
        $fields = self::fields($live);
        $q = $sc['kind'] === 'service' ? ['page' => 'features', 'service' => $sc['sid']] : ['page' => 'features', 'domain' => $sc['domain']];
        $hidden = $sc['kind'] === 'service' ? ['service' => $sc['sid']] : ['domain' => $sc['domain']];
        $errors = (array) ($state['fo_errors'] ?? []);
        $input = (array) ($state['fo_input'] ?? []);

        // summary
        if ($sc['kind'] === 'service') {
            $s = $sc['svc'];
            $who = '<div><dt>سرویس</dt><dd><a href="' . View::e(Data::serviceUrl((int) $s->userid, (int) $s->id)) . '">#' . View::n((int) $s->id) . '</a> · ' . View::e((string) $s->product)
                . ' · ' . Pages::whmcsBadge((string) $s->domainstatus) . '</dd></div><div><dt>مالک</dt><dd><a href="' . View::e(Data::clientUrl((int) $s->userid)) . '">'
                . View::e(Data::clientName($s)) . '</a></dd></div>';
        } else {
            $who = '<div><dt>مالک</dt><dd>' . View::badge('اپراتور', 'violet') . '</dd></div><div><dt>قالب پلن</dt><dd>' . View::e(Operator::templateLabel($sc['domain'], $live)) . '</dd></div>';
        }
        $n = count($ov['v']);
        $last = '';
        if ($n > 0 && $ov['updated_at']) {
            $name = '';
            try {
                $name = (string) Capsule::table('tbladmins')->where('id', (int) $ov['admin_id'])->value('username');
            } catch (\Throwable $e) {
                $name = '';
            }
            $last = '<div><dt>آخرین تغییر</dt><dd>' . View::date((string) $ov['updated_at'], true) . ($name !== '' ? ' · مدیر ' . View::e($name) : '') . '</dd></div>';
        }
        $sum = '<dl class="pcdna-dl pcdna-dl-3"><div><dt>دامنه</dt><dd>' . View::ltr($sc['domain']) . '</dd></div>' . $who
            . '<div><dt>امکانات اختصاصی</dt><dd data-fo-count="' . $n . '">' . ($n > 0 ? View::badge(View::n($n) . ' مورد', 'violet') : View::badge('ندارد — همه طبق پلن', 'muted')) . '</dd></div>'
            . $last . '</dl>'
            . '<p class="pcdna-muted pcdna-small">مقدار اختصاصی روی پلن ' . ($sc['kind'] === 'service' ? 'محصول' : 'قالب') . ' این دامنه می‌نشیند و با ارتقا، تمدید، شارژ ترافیک و انتقال حفظ می‌شود. '
            . 'خاموش‌کردن یک امکان تنظیمات ذخیره‌شدهٔ آن را پاک نمی‌کند. امکانات اختصاصی فاکتوری نمی‌سازند (صورت‌حساب فضای ذخیره‌سازی و ترافیک اضافه قواعد خودش را دارد).</p>';
        $actions = View::postButton($q, 'features_all_on', $hidden, 'همه امکانات روشن', 'pcdna-btn pcdna-btn-sm',
            'همهٔ امکانات روشن/خاموش برای ' . $sc['domain'] . ' روشن شوند؟ سقف‌ها و محدودیت‌ها تغییر نمی‌کنند.', 'zap')
            . ($n > 0 ? View::postButton($q, 'features_clear', $hidden, 'بازگشت به پلن', 'pcdna-btn pcdna-btn-sm pcdna-btn-danger',
                'همهٔ امکانات اختصاصی ' . $sc['domain'] . ' حذف و پلن ' . ($sc['kind'] === 'service' ? 'محصول' : 'قبلی') . ' دوباره اعمال شود؟', 'refresh') : '');
        $h = View::card('امکانات اختصاصی — ' . $sc['domain'], $sum, $actions, 'pcdna-fo-head', 'sliders');

        // the editor
        $t = '<form method="post" action="' . View::url($q) . '" class="pcdna-form pcdna-fo-form" data-features-form="1">' . View::csrf()
            . '<input type="hidden" name="a" value="features_save">';
        foreach ($hidden as $k => $v) {
            $t .= '<input type="hidden" name="' . View::e($k) . '" value="' . View::e($v) . '">';
        }
        $t .= '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-fo-table"><thead><tr><th>امکان</th><th>' . ($sc['kind'] === 'service' ? 'پلن محصول' : 'پلن (قالب)') . '</th>'
            . '<th>مقدار اختصاصی</th><th>مؤثر</th></tr></thead><tbody>';
        foreach ($fields as $f => $like) {
            $has = array_key_exists($f, $ov['v']);
            $cur = $has ? $ov['v'][$f] : null;
            // the plan value: the product's (service), else the value before the override / the live value
            $pv = $prod !== null ? FeatureOverrides::valueOf($prod, $f) : null;
            $note = '';
            if ($pv === null) {
                $pv = $has && array_key_exists($f, $ov['base']) ? $ov['base'][$f] : FeatureOverrides::valueOf($plan, $f);
                if ($prod !== null) {
                    $note = '<div class="pcdna-small pcdna-muted">محصول این مورد را نمی‌فرستد (پیش‌فرض کنترلر)</div>';
                }
            }
            $eff = $has ? $cur : (FeatureOverrides::valueOf($plan, $f) ?? $pv);
            $id = 'fo-' . preg_replace('/[^a-z0-9_]/', '-', $f);
            $raw = array_key_exists($f, $input) && is_string($input[$f]) ? $input[$f] : null;
            if (isset(FeatureOverrides::ENUMS[$f])) {
                $opts = ['' => 'طبق پلن'];
                foreach (FeatureOverrides::ENUMS[$f] as $e) {
                    $opts[$e] = $e;
                }
                $ctl = View::select('ov[' . $f . ']', $opts, $raw ?? ($has ? (string) $cur : ''), ' id="' . $id . '" aria-label="' . View::e(self::label($f)) . '"');
            } elseif (self::isBool($f, $like)) {
                $ctl = View::select('ov[' . $f . ']', ['' => 'طبق پلن', '1' => 'روشن', '0' => 'خاموش'], $raw ?? ($has ? ($cur ? '1' : '0') : ''),
                    ' id="' . $id . '" aria-label="' . View::e(self::label($f)) . '"');
            } else {
                $range = FeatureOverrides::RANGES[$f] ?? null;
                $ctl = '<input type="text" inputmode="decimal" dir="ltr" class="pcdna-input pcdna-fo-num" name="ov[' . View::e($f) . ']" id="' . $id . '" value="'
                    . View::e($raw ?? ($has ? (string) $cur : '')) . '" placeholder="طبق پلن" aria-label="' . View::e(self::label($f)) . '"'
                    . ($range ? ' title="' . View::e('بازهٔ مجاز: ' . $range[0] . ' تا ' . $range[1]) . '"' : '') . '>'
                    . ($range ? '<div class="pcdna-small pcdna-muted">' . View::n($range[0]) . ' تا ' . View::n($range[1]) . '؛ خالی = طبق پلن</div>' : '');
            }
            if (isset($errors[$f])) {
                $ctl .= '<div class="pcdna-small pcdna-err" role="alert" data-fo-error="' . View::e($f) . '">' . View::e((string) $errors[$f]) . '</div>';
            }
            $t .= '<tr data-field="' . View::e($f) . '"' . ($has ? ' class="is-overridden" data-overridden="1"' : '') . '><td data-label="امکان"><label for="' . $id . '">' . View::e(self::label($f)) . '</label>'
                . '<div class="pcdna-small pcdna-muted">' . View::ltr($f) . '</div></td>'
                . '<td data-label="پلن" data-plan-value="' . View::e(self::plain($pv)) . '">' . self::show($pv) . $note . '</td>'
                . '<td data-label="مقدار اختصاصی">' . $ctl . '</td>'
                . '<td data-label="مؤثر" data-effective="' . View::e(self::plain($eff)) . '">' . self::show($eff) . ($has ? ' ' . View::badge('اختصاصی', 'violet') : '') . '</td></tr>';
        }
        $t .= '</tbody></table></div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('check')
            . '<span>ذخیره و اعمال روی CDN</span></button></div></form>';
        return $h . View::card('امکانات پلن این دامنه', $t, '', 'pcdna-flush', 'sliders');
    }
}
