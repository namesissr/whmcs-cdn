<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use PasargadCdn\ClientApi;
use PasargadCdn\Download;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Admin', false)) {
    return;
}

/**
 * Router of the addon output: pages, POST actions (CSRF-checked, logged) and
 * the two raw endpoints (the admin-mode JSON API and the usage CSV).
 */
final class Admin
{
    const PAGES = ['dashboard', 'sites', 'edges', 'plans', 'analytics', 'usage', 'resellers', 'events', 'status', 'health', 'audit', 'referrals', 'settings', 'manage', 'api'];

    /** @var callable|null tests: receives [status, content type, body, filename] instead of exit */
    public static $sink = null;

    public static function output(array $vars, array $get, array $post, string $method): string
    {
        // Only plain string query values are ever used (arrays like ?q[]=x are dropped).
        $get = array_filter($get, 'is_string');
        if (!empty($vars['modulelink'])) {
            View::$link = (string) $vars['modulelink'];
        }
        $page = is_string($get['page'] ?? null) && in_array($get['page'], self::PAGES, true) ? $get['page'] : 'dashboard';
        if (Env::adminId() <= 0) {
            if ($page === 'api') {
                self::emit(401, 'application/json; charset=utf-8', json_encode(['detail' => 'نشست مدیر معتبر نیست؛ دوباره وارد شوید.'], JSON_UNESCAPED_UNICODE));
                return '';
            }
            return '<div class="pcdna" dir="rtl">' . View::alert('bad', 'دسترسی فقط برای مدیران WHMCS مجاز است.') . '</div>';
        }
        if (!Env::loadServerModule()) {
            return Pages::layout($page, View::alert('bad', 'ماژول سرور Pasargad CDN پیدا نشد. پوشه <code>modules/servers/pasargadcdn</code> را آپلود کنید.'), []);
        }
        if ($page === 'api') {
            [$code, $data] = self::api($get, $method);
            if ($data instanceof Download) {
                // SPEC §18.3: a statement / audit file of the customer app in admin mode
                self::emit($code, $data->type, $data->body, $data->filename);
                return '';
            }
            self::emit($code, 'application/json; charset=utf-8', (string) json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            return '';
        }
        if ($page === 'audit' && ($get['export'] ?? '') === 'csv') {
            // SPEC §18.3: the controller's platform-wide audit export (GET /api/v1/audit/export?from&to&format=csv)
            [$code, $type, $body, $file] = Pages::auditCsv($get);
            Env::log('audit CSV exported (' . $file . ') by admin #' . Env::adminId());
            self::emit($code, $type, $body, $file);
            return '';
        }
        if ($page === 'usage' && ($get['export'] ?? '') === 'csv') {
            [$code, $type, $body, $file] = Pages::usageCsv(is_string($get['month'] ?? null) ? $get['month'] : '');
            Env::log('usage CSV exported (' . Pages::validMonth($get['month'] ?? '') . ') by admin #' . Env::adminId());
            self::emit($code, $type, $body, $file);
            return '';
        }

        $flash = [];
        $state = [];
        if ($method === 'POST') {
            $action = is_string($post['a'] ?? null) ? $post['a'] : '';
            if (!Env::checkCsrf($post['pcdn_csrf'] ?? null)) {
                $flash[] = ['bad', 'درخواست رد شد: توکن امنیتی نامعتبر یا منقضی است. صفحه را دوباره بارگذاری و دوباره تلاش کنید.'];
            } else {
                try {
                    [$flash, $state] = self::action($page, $action, $post);
                } catch (\Throwable $e) {
                    $flash[] = ['bad', 'خطا: ' . View::e($e->getMessage())];
                }
            }
        }

        switch ($page) {
            case 'sites':
                $body = Pages::sites($get);
                break;
            case 'edges':
                $body = Pages::edges($state['token'] ?? null, $state['old'] ?? [], $get, $state['batch'] ?? []);
                break;
            case 'plans':
                $body = Pages::plans($state);
                break;
            case 'analytics':
                $body = Pages::analytics($get);
                break;
            case 'usage':
                $body = Pages::usage($get);
                break;
            case 'resellers':
                $body = Pages::resellers($get, $state);
                break;
            case 'events':
                $body = Pages::events($get);
                break;
            case 'status':
                $body = Pages::status($state);
                break;
            case 'health':
                $body = Pages::health();
                break;
            case 'audit':
                $body = Pages::audit($get);
                break;
            case 'referrals':
                require_once __DIR__ . '/Referrals.php';
                $body = Referrals::adminPage($get);
                break;
            case 'settings':
                $body = Pages::settings();
                break;
            case 'manage':
                $body = Pages::manage((int) ($get['service'] ?? 0));
                break;
            default:
                $body = Pages::dashboard();
        }
        // After a POST, the browser URL is replaced with the GET URL so a refresh never re-submits.
        $clean = $method === 'POST' ? View::url(array_filter(['page' => $page, 'view' => $get['view'] ?? null, 'id' => $get['id'] ?? null,
            'q' => $get['q'] ?? null, 'status' => $get['status'] ?? null, 'pid' => $get['pid'] ?? null, 'cdn' => $get['cdn'] ?? null, 'p' => $get['p'] ?? null], 'is_string'), false) : '';
        return Pages::layout($page, $body, $flash, $clean);
    }

    // ------------------------------------------------------------------ admin-mode JSON API

    public static function api(array $get, string $method): array
    {
        $sid = is_string($get['service'] ?? null) ? $get['service'] : '';
        $id = is_string($get['id'] ?? null) ? $get['id'] : '';
        if ($sid === '' || $sid !== $id) {
            return [404, ['detail' => 'سرویس یافت نشد.']];
        }
        if (($get['action'] ?? '') === 'client-error') {
            // SPEC §18.4: a JavaScript error of the customer app opened in admin mode (same sanitising / rate limit)
            return ClientApi::clientError(['method' => $method, 'id' => $id, 'admin_id' => Env::adminId(),
                'body' => $method === 'POST' ? self::readBody(ClientApi::CLIENT_ERROR_MAX_BODY + 1) : '',
                'csrf' => (string) ($_SERVER['HTTP_X_PCDN_CSRF'] ?? ''), 'session_csrf' => (string) ($_SESSION['pasargadcdn_admin_csrf'] ?? '')],
                $_SESSION, self::$apiFactory);
        }
        $body = '';
        if ($method === 'POST' || $method === 'PUT') {
            // 256 KB, or 9 MB for PUT config/functions (SPEC §16.9 edge-function code) — ClientApi::maxBody
            $body = (string) self::readBody(ClientApi::maxBody($method, is_string($get['path'] ?? null) ? $get['path'] : '') + 1);
        }
        $query = $get;
        unset($query['module'], $query['page'], $query['service'], $query['id'], $query['path'], $query['token'], $query['action']);
        return ClientApi::handle([
            'method' => $method,
            'id' => $id,
            'path' => is_string($get['path'] ?? null) ? $get['path'] : '',
            'query' => $query,
            'body' => $body,
            'csrf' => (string) ($_SERVER['HTTP_X_PCDN_CSRF'] ?? ''),
            'session_csrf' => (string) ($_SESSION['pasargadcdn_admin_csrf'] ?? ''),
            'client_id' => 0,
            'admin_id' => Env::adminId(),
        ], self::$apiFactory);
    }

    /** @var callable|null tests */
    public static $apiFactory = null;
    /** @var string|null tests: request body */
    public static $body = null;

    private static function readBody(int $max): string
    {
        if (self::$body !== null) {
            return self::$body;
        }
        return (string) file_get_contents('php://input', false, null, 0, $max);
    }

    public static function emit(int $code, string $type, string $body, string $file = ''): void
    {
        if (self::$sink) {
            (self::$sink)([$code, $type, $body, $file]);
            return;
        }
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        if (!headers_sent()) {
            http_response_code($code);
            header('Content-Type: ' . $type);
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
            if ($file !== '') {
                header('Content-Disposition: attachment; filename="' . preg_replace('/[^A-Za-z0-9._-]/', '', $file) . '"');
            }
        }
        echo $body;
        exit;
    }

    // ------------------------------------------------------------------ actions

    /** @return array [flash list, page state] */
    public static function action(string $page, string $action, array $post): array
    {
        $admin = Env::adminId();
        switch ($action) {
            case 'purge':
            case 'nscheck':
            case 'dnssync':
            case 'ssl':
                return [[self::siteAction($action, (int) ($post['service'] ?? 0), $admin)], []];
            case 'suspend':
            case 'unsuspend':
            case 'create':
                return [[self::moduleAction($action, (int) ($post['service'] ?? 0), $admin)], []];
            case 'orphan_delete':
                return [[self::orphanDelete(Env::input($post['domain'] ?? ''), Env::input($post['confirm'] ?? ''), $admin)], []];
            case 'edge_add':
                return self::edgeAdd($post, $admin);
            case 'edge_batch':
                return self::edgeBatch($post, $admin);
            case 'edge_edit':
                return self::edgeEdit($post, $admin);
            case 'edge_shield':
                return self::edgeShield($post, $admin);
            case 'edge_toggle':
            case 'edge_rotate':
            case 'edge_delete':
                return self::edgeAction($action, (int) ($post['id'] ?? 0), (string) ($post['enabled'] ?? ''), $admin);
            case 'edge_addr_add':
                return self::edgeAddrAdd($post, $admin);
            case 'edge_addr_edit':
                return self::edgeAddrEdit($post, $admin);
            case 'edge_addr_toggle':
                return self::edgeAddrToggle($post, $admin);
            case 'edge_addr_delete':
                return self::edgeAddrDelete($post, $admin);
            case 'wizard_preview':
            case 'wizard_edit':
            case 'wizard_apply':
                return self::wizard($action, $post, $admin);
            case 'tunnel_enable':
                return [self::enableTunnelExisting($admin), []];
            case 'incident_create':
                return self::incidentCreate($post, $admin);
            case 'incident_update':
                return self::incidentUpdate($post, $admin);
            case 'incident_resolve':
                return self::incidentResolve((int) ($post['id'] ?? 0), $admin);
            case 'reseller_flag':
                return [[self::resellerFlag($post, $admin)], []];
            case 'reseller_save':
                return [[self::resellerSave($post, $admin)], []];
            case 'reseller_settings':
                return [[self::resellerSettings($post, $admin)], []];
            case 'save_server':
                $sid = (int) ($post['server'] ?? 0);
                if ($sid !== 0 && !Env::serverById($sid)) {
                    return [[['bad', 'سرور انتخاب‌شده از نوع Pasargad CDN نیست.']], []];
                }
                Env::saveSetting('server', (string) $sid);
                Env::cacheDelete(WidgetData::KEY);
                Pages::reset();
                Env::log('admin panel server set to #' . $sid . ' by admin #' . $admin);
                return [[['ok', 'سرور ذخیره شد.']], []];
            case 'owner_sync':
                return [[self::ownerSync($admin)], []];
            case 'referral_cancel':
                require_once __DIR__ . '/Referrals.php';
                $rid = (int) ($post['id'] ?? 0);
                return [[Referrals::cancel($rid, $admin) ? ['ok', 'پاداش معرفی #' . View::n($rid) . ' لغو شد.']
                    : ['bad', 'این معرفی قابل لغو نیست (پرداخت یا لغو شده است).']], []];
            case 'referral_run':
                require_once __DIR__ . '/Referrals.php';
                $r = Referrals::run();
                Env::log('referral payout run by admin #' . $admin . ': ' . count($r['paid']) . ' paid, ' . count($r['cancelled']) . ' cancelled, '
                    . count($r['deferred']) . ' deferred, ' . count($r['failed']) . ' failed');
                return [[[$r['failed'] ? 'warn' : 'ok', 'پرداخت پاداش‌ها: ' . View::n(count($r['paid'])) . ' پرداخت، ' . View::n(count($r['cancelled'])) . ' لغو، '
                    . View::n(count($r['deferred'])) . ' به ماه بعد (سقف ماهانه)، ' . View::n(count($r['failed'])) . ' ناموفق.']], []];
            case 'clear_cache':
                Env::cacheDelete(WidgetData::KEY);
                return [[['ok', 'حافظه موقت ویجت پاک شد؛ در بارگذاری بعدی صفحه اصلی داده تازه نمایش داده می‌شود.']], []];
        }
        return [[['bad', 'عملیات نامعتبر است.']], []];
    }

    /** Security review C1: «همگام‌سازی مالکیت دامنه‌ها» — the cron's owner pass, now, refusals retried. */
    private static function ownerSync(int $admin): array
    {
        require_once __DIR__ . '/OwnerSync.php';
        $r = OwnerSync::run(OwnerSync::MAX_PER_RUN * 2, true);
        Env::log('owner sync started by admin #' . $admin . ': ' . count($r['fixed']) . ' set, ' . count($r['refused']) . ' refused, '
            . $r['remaining'] . ' remaining');
        Pages::reset();
        if ($r['unsupported'] && !$r['checked']) {
            return ['warn', 'کنترلر هنوز مالک سایت‌ها را نمی‌شناسد (نسخهٔ پیش از بازبینی امنیتی)؛ ابتدا کنترلر را به‌روز کنید.'];
        }
        $msg = 'همگام‌سازی مالکیت: ' . View::n(count($r['fixed'])) . ' سایت مالک گرفت'
            . ($r['checked'] ? '، ' . View::n($r['checked']) . ' سرویس بررسی شد' : '') . '.';
        if ($r['remaining']) {
            $msg .= ' ' . View::n($r['remaining']) . ' سایت دیگر مانده است؛ دوباره اجرا کنید (کران هم ادامه می‌دهد).';
        }
        if ($r['refused']) {
            $msg .= ' کنترلر ' . View::n(count($r['refused'])) . ' مورد را نپذیرفت (زیردامنه/والدِ سایتی با مالک دیگر): ' . implode('، ', array_map(function ($x) {
                return View::ltr($x['domain']);
            }, array_slice($r['refused'], 0, 10))) . ' — جزئیات در Activity Log.';
        }
        if ($r['errors']) {
            $msg .= ' خطا: ' . View::e(implode('؛ ', $r['errors']));
        }
        if ($r['mismatch']) {
            $msg .= ' ' . View::n(count($r['mismatch'])) . ' سایت روی کنترلر مالک دیگری دارد (سرویس جابه‌جا شده؟) و تغییر داده نشد؛ جزئیات در Activity Log.';
        }
        return [$r['errors'] || $r['refused'] ? 'warn' : 'ok', $msg];
    }

    /** Service row (CDN products only) + its server, or an error string. */
    private static function service(int $sid)
    {
        if ($sid <= 0) {
            return 'شناسه سرویس نامعتبر است.';
        }
        $svc = Data::serviceQuery()->where('h.id', $sid)->first(['h.id', 'h.userid', 'h.domain', 'h.domainstatus', 'h.server']);
        if (!$svc) {
            return 'سرویس CDN #' . $sid . ' پیدا نشد.';
        }
        return $svc;
    }

    private static function serverOf($svc)
    {
        $s = Capsule::table('tblservers')->where('id', (int) $svc->server)->first();
        return $s && $s->type === 'pasargadcdn' ? $s : Env::server();
    }

    const SITE_ACTIONS = [
        'purge' => ['/purge', 'پاکسازی کل کش', 'درخواست پاکسازی کل کش %s ثبت شد.'],
        'nscheck' => ['/ns-check', 'بررسی NS', ''],
        'dnssync' => ['/dns-sync', 'همگام‌سازی DNS', 'زون DNS دامنه %s دوباره در PowerDNS نوشته شد.'],
        'ssl' => ['/ssl', 'درخواست SSL', 'درخواست صدور گواهی SSL برای %s ثبت شد.'],
    ];

    private static function siteAction(string $action, int $sid, int $admin): array
    {
        $svc = self::service($sid);
        if (is_string($svc)) {
            return ['bad', View::e($svc)];
        }
        $domain = Env::domain((string) $svc->domain);
        if (!Env::validHostname($domain)) {
            return ['bad', 'دامنه سرویس #' . $sid . ' معتبر نیست.'];
        }
        [$suffix, $label, $okMsg] = self::SITE_ACTIONS[$action];
        try {
            $api = Env::api(10, self::serverOf($svc));
            $r = $api->post(ApiClient::site($domain) . $suffix, $action === 'purge' ? ['urls' => []] : []);
        } catch (\Throwable $e) {
            Env::log($label . ' on ' . $domain . ' (service #' . $sid . ') failed: ' . $e->getMessage() . ' — admin #' . $admin, (int) $svc->userid);
            return ['bad', View::e($label . ' برای ' . $domain . ' ناموفق بود: ' . $e->getMessage())];
        }
        Env::log($label . ' on ' . $domain . ' (service #' . $sid . ') by admin #' . $admin, (int) $svc->userid);
        if ($action === 'nscheck') {
            return !empty($r['ok']) ? ['ok', 'نیم‌سرورهای ' . View::ltr($domain) . ' تأیید شد.']
                : ['warn', 'نیم‌سرورهای ' . View::ltr($domain) . ' هنوز تغییر نکرده است. فعلی: ' . View::ltr(implode(', ', (array) ($r['found'] ?? [])) ?: '—')];
        }
        if ($action === 'dnssync' && empty($r['ok'])) {
            return ['bad', 'همگام‌سازی DNS ناموفق بود: ' . View::e((string) ($r['error'] ?? ''))];
        }
        return ['ok', sprintf(View::e($okMsg), View::ltr($domain))];
    }

    const MODULE_ACTIONS = [
        'suspend' => ['ModuleSuspend', 'تعلیق', 'سرویس #%d در WHMCS و CDN معلق شد.'],
        'unsuspend' => ['ModuleUnsuspend', 'رفع تعلیق', 'تعلیق سرویس #%d برداشته شد.'],
        'create' => ['ModuleCreate', 'ساخت روی CDN', 'سایت سرویس #%d روی کنترلر ساخته شد.'],
    ];

    /** Through WHMCS localAPI, so WHMCS status, emails and hooks stay consistent. */
    private static function moduleAction(string $action, int $sid, int $admin): array
    {
        $svc = self::service($sid);
        if (is_string($svc)) {
            return ['bad', View::e($svc)];
        }
        [$cmd, $label, $okMsg] = self::MODULE_ACTIONS[$action];
        $args = ['serviceid' => $sid];
        if ($action === 'suspend') {
            if ((string) $svc->domainstatus !== 'Active') {
                return ['bad', 'فقط سرویس فعال را می‌توان معلق کرد.'];
            }
            $args['suspendreason'] = 'تعلیق توسط مدیر از پنل CDN';
        } elseif ($action === 'unsuspend' && (string) $svc->domainstatus !== 'Suspended') {
            return ['bad', 'این سرویس معلق نیست.'];
        } elseif ($action === 'create' && !in_array((string) $svc->domainstatus, ['Active', 'Suspended', 'Pending'], true)) {
            return ['bad', 'برای سرویس با وضعیت ' . View::e($svc->domainstatus) . ' نمی‌توان سایت ساخت.'];
        }
        $r = Env::localApi($cmd, $args);
        $ok = ($r['result'] ?? '') === 'success';
        Env::log($label . ' (' . $cmd . ') service #' . $sid . ' by admin #' . $admin . ': ' . ($ok ? 'success' : 'failed — ' . ($r['message'] ?? '')), (int) $svc->userid);
        Pages::reset();
        return $ok ? ['ok', sprintf($okMsg, $sid)] : ['bad', View::e($label . ' ناموفق بود: ' . ($r['message'] ?? 'خطای نامشخص'))];
    }

    private static function orphanDelete(string $domain, string $confirm, int $admin): array
    {
        $domain = strtolower($domain);
        if (!Env::validHostname($domain)) {
            return ['bad', 'دامنه نامعتبر است.'];
        }
        if (strtolower($confirm) !== $domain) {
            return ['bad', 'برای حذف، نام دامنه را دقیقاً تایپ کنید.'];
        }
        try {
            $api = Env::api(10);
            $sites = $api->get('/api/v1/sites');
            if (!Data::isOrphan($domain, $sites)) {
                return ['bad', 'دامنه ' . View::ltr($domain) . ' به یک سرویس فعال WHMCS تعلق دارد و حذف نشد.'];
            }
            $api->delete(ApiClient::site($domain));
        } catch (\Throwable $e) {
            return ['bad', View::e('حذف ' . $domain . ' ناموفق بود: ' . $e->getMessage())];
        }
        Env::log('orphan site ' . $domain . ' deleted from the controller by admin #' . $admin);
        Pages::reset();
        return ['ok', 'سایت ' . View::ltr($domain) . ' از کنترلر حذف شد.'];
    }

    private static function edgeAdd(array $post, int $admin): array
    {
        $old = ['name' => Env::input($post['name'] ?? ''), 'ipv4' => Env::input($post['ipv4'] ?? ''),
            'ipv6' => Env::input($post['ipv6'] ?? ''), 'region' => Env::input($post['region'] ?? ''),
            'group' => Env::input($post['group'] ?? 'general') ?: 'general', 'capacity_mbps' => trim(Env::input($post['capacity_mbps'] ?? ''))];
        $e = [];
        if (!preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $old['name'])) {
            $e[] = 'نام نود فقط می‌تواند حروف انگلیسی، عدد، نقطه، زیرخط و خط تیره باشد (حداکثر ۶۴).';
        }
        if (!filter_var($old['ipv4'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $e[] = 'IPv4 باید یک آدرس عمومی معتبر باشد.';
        }
        if ($old['ipv6'] !== '' && !filter_var($old['ipv6'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $e[] = 'IPv6 معتبر نیست.';
        }
        if (!in_array($old['region'], ['home', 'global'], true)) {
            $e[] = 'منطقه نامعتبر است.';
        }
        if (!in_array($old['group'], ['general', 'tunnel'], true)) {
            $e[] = 'گروه نود نامعتبر است.';
        }
        $cap = self::capacity($old['capacity_mbps']);
        if ($cap === null) {
            $e[] = 'ظرفیت باید عدد صحیح بین ۰ و ۱۰٬۰۰۰٬۰۰۰ مگابیت بر ثانیه باشد.';
        }
        if ($e) {
            return [array_map(function ($m) {
                return ['bad', View::e($m)];
            }, $e), ['old' => $old]];
        }
        $body = ['name' => $old['name'], 'ipv4' => $old['ipv4'], 'region' => $old['region'], 'group' => $old['group'], 'capacity_mbps' => $cap];
        if ($old['ipv6'] !== '') {
            $body['ipv6'] = $old['ipv6'];
        }
        try {
            $r = Env::api(10)->post('/api/v1/edges', $body);
        } catch (\Throwable $ex) {
            return [[['bad', View::e('افزودن نود ناموفق بود: ' . $ex->getMessage())]], ['old' => $old]];
        }
        // The token is only rendered in this response — never logged, stored or put in a redirect.
        Env::log('edge ' . $old['name'] . ' (' . $old['ipv4'] . ', ' . $old['region'] . ', group ' . $old['group'] . ', ' . $cap . ' Mbps) added by admin #' . $admin);
        Pages::reset();
        $token = is_string($r['token'] ?? null) ? $r['token'] : '';
        return [[['ok', 'نود ' . View::ltr($old['name']) . ' ثبت شد.']], $token !== ''
            ? ['token' => ['token' => $token, 'name' => $old['name'], 'title' => 'نود جدید: دستور نصب',
                'region' => $old['region'], 'role' => $old['group'] === 'tunnel' ? 'tunnel' : 'general',
                'install' => is_string($r['install'] ?? null) ? $r['install'] : '']] : []];
    }

    /** Batch add: POST /api/v1/edges/batch → N edges each with a one-time token + ready install one-liner (SPEC §11.1). */
    private static function edgeBatch(array $post, int $admin): array
    {
        $old = ['count' => trim(Env::input($post['count'] ?? '')), 'region' => Env::input($post['region'] ?? ''),
            'group' => Env::input($post['group'] ?? 'general') ?: 'general',
            'name_prefix' => trim(Env::input($post['name_prefix'] ?? '')), 'capacity_mbps' => trim(Env::input($post['capacity_mbps'] ?? ''))];
        $e = [];
        $count = self::capacity($old['count']);
        if ($count === null || $count < 1 || $count > 50) {
            $e[] = 'تعداد باید عددی بین ۱ تا ۵۰ باشد.';
        }
        if (!in_array($old['region'], ['home', 'global'], true)) {
            $e[] = 'منطقه نامعتبر است.';
        }
        if (!in_array($old['group'], ['general', 'tunnel'], true)) {
            $e[] = 'نقش (گروه) نود نامعتبر است.';
        }
        if ($old['name_prefix'] !== '' && !preg_match('/^[A-Za-z0-9_.-]{1,48}$/D', $old['name_prefix'])) {
            $e[] = 'پیشوند نام فقط می‌تواند حروف انگلیسی، عدد، نقطه، زیرخط و خط تیره باشد (حداکثر ۴۸).';
        }
        $cap = self::capacity($old['capacity_mbps']);
        if ($cap === null) {
            $e[] = 'ظرفیت باید عدد صحیح بین ۰ و ۱۰٬۰۰۰٬۰۰۰ مگابیت بر ثانیه باشد.';
        }
        if ($e) {
            return [array_map(function ($m) {
                return ['bad', View::e($m)];
            }, $e), ['batch' => ['old' => $old]]];
        }
        $body = ['count' => $count, 'region' => $old['region'], 'group' => $old['group'], 'capacity_mbps' => $cap];
        if ($old['name_prefix'] !== '') {
            $body['name_prefix'] = $old['name_prefix'];
        }
        try {
            $r = Env::api(20)->post('/api/v1/edges/batch', $body);
        } catch (\Throwable $ex) {
            return [[['bad', View::e('افزودن گروهی نودها ناموفق بود: ' . $ex->getMessage())]], ['batch' => ['old' => $old]]];
        }
        $rows = is_array($r) ? array_values(array_filter($r, 'is_array')) : [];
        if (!$rows) {
            return [[['bad', 'کنترلر نودی نساخت؛ دوباره تلاش کنید.']], ['batch' => ['old' => $old]]];
        }
        // Tokens are only rendered in this response — never logged, stored or redirected.
        Env::log('batch of ' . count($rows) . ' edges (' . $old['region'] . ', group ' . $old['group'] . ', ' . $cap . ' Mbps'
            . ($old['name_prefix'] !== '' ? ', prefix ' . $old['name_prefix'] : '') . ') added by admin #' . $admin);
        Pages::reset();
        return [[['ok', View::n(count($rows)) . ' نود ساخته شد؛ دستورهای نصب یک‌بار در پایین نمایش داده می‌شوند.']],
            ['batch' => ['rows' => $rows]]];
    }

    /** '' → 0; digits (Persian digits accepted) within 0..10M → int; else null. */
    private static function capacity(string $v): ?int
    {
        $v = str_replace([',', '٬', ' '], '', strtr($v, ['۰' => '0', '۱' => '1', '۲' => '2', '۳' => '3', '۴' => '4', '۵' => '5', '۶' => '6', '۷' => '7', '۸' => '8', '۹' => '9']));
        if ($v === '') {
            return 0;
        }
        return ctype_digit($v) && strlen($v) <= 8 && (int) $v <= 10000000 ? (int) $v : null;
    }

    /** Group / capacity / region of an edge: PATCH /api/v1/edges/{id} with a JSON body (SPEC §7.4). */
    private static function edgeEdit(array $post, int $admin): array
    {
        $id = (int) ($post['id'] ?? 0);
        $group = Env::input($post['group'] ?? '');
        $region = Env::input($post['region'] ?? '');
        $cap = self::capacity(trim(Env::input($post['capacity_mbps'] ?? '')));
        if ($id <= 0) {
            return [[['bad', 'شناسه نود نامعتبر است.']], []];
        }
        if (!in_array($group, ['general', 'tunnel'], true) || !in_array($region, ['home', 'global'], true) || $cap === null) {
            return [[['bad', 'گروه، منطقه یا ظرفیت نامعتبر است (ظرفیت: عدد صحیح ۰ تا ۱۰٬۰۰۰٬۰۰۰ مگابیت بر ثانیه).']], []];
        }
        try {
            $r = Env::api(10)->request('PATCH', '/api/v1/edges/' . $id, ['group' => $group, 'capacity_mbps' => $cap, 'region' => $region]);
        } catch (\Throwable $e) {
            return [[['bad', View::e('ذخیره تنظیمات نود ناموفق بود: ' . $e->getMessage())]], []];
        }
        $name = is_array($r['edge'] ?? null) ? (string) ($r['edge']['name'] ?? '#' . $id) : '#' . $id;
        Env::log('edge ' . $name . ' set to group ' . $group . ', ' . $cap . ' Mbps, region ' . $region . ' by admin #' . $admin);
        Pages::reset();
        return [[['ok', 'تنظیمات نود ' . View::ltr($name) . ' ذخیره شد (گروه ' . ($group === 'tunnel' ? 'تونل' : 'عمومی') . '، ظرفیت '
            . ($cap ? View::n($cap) . ' Mbps' : 'نامشخص') . ').']], []];
    }

    /** Origin-shield role of an edge (SPEC §14.1): PATCH /api/v1/edges/{id} with {"shield": bool}. */
    private static function edgeShield(array $post, int $admin): array
    {
        $id = (int) ($post['id'] ?? 0);
        $v = Env::input($post['shield'] ?? '');
        if ($id <= 0) {
            return [[['bad', 'شناسه نود نامعتبر است.']], []];
        }
        if ($v !== '1' && $v !== '0') {
            return [[['bad', 'مقدار Shield نامعتبر است.']], []];
        }
        $on = $v === '1';
        try {
            $r = Env::api(10)->request('PATCH', '/api/v1/edges/' . $id, ['shield' => $on]);
        } catch (\Throwable $e) {
            return [[['bad', View::e('تغییر Shield نود ناموفق بود: ' . $e->getMessage())]], []];
        }
        $name = is_array($r['edge'] ?? null) ? (string) ($r['edge']['name'] ?? '#' . $id) : '#' . $id;
        Env::log('edge ' . $name . ' shield ' . ($on ? 'enabled' : 'disabled') . ' by admin #' . $admin);
        Pages::reset();
        return [[['ok', $on
            ? 'نود ' . View::ltr($name) . ' اکنون Shield است؛ سایت‌هایی که Origin Shield را روشن کرده‌اند فایل‌های کش‌نشده را از این نود می‌گیرند.'
            : 'نقش Shield از نود ' . View::ltr($name) . ' برداشته شد.']], []];
    }

    private static function edgeAction(string $action, int $id, string $enabled, int $admin): array
    {
        if ($id <= 0) {
            return [[['bad', 'شناسه نود نامعتبر است.']], []];
        }
        try {
            $api = Env::api(10);
            $name = '#' . $id;
            $region = 'home';
            $role = 'general';
            foreach ($api->get('/api/v1/edges') as $e) {
                if ((int) ($e['id'] ?? 0) === $id) {
                    $name = (string) $e['name'];
                    $region = ($e['region'] ?? '') === 'global' ? 'global' : 'home';
                    $role = ($e['group'] ?? '') === 'tunnel' ? 'tunnel' : 'general';
                }
            }
            if ($action === 'edge_toggle') {
                $on = $enabled === '1';
                $api->request('PATCH', '/api/v1/edges/' . $id . '?enabled=' . ($on ? 'true' : 'false'));
                Env::log('edge ' . $name . ' ' . ($on ? 'enabled' : 'disabled') . ' by admin #' . $admin);
                Pages::reset();
                return [[['ok', 'نود ' . View::ltr($name) . ($on ? ' فعال شد.' : ' غیرفعال و از DNS خارج شد.')]], []];
            }
            if ($action === 'edge_delete') {
                $api->delete('/api/v1/edges/' . $id);
                Env::log('edge ' . $name . ' deleted by admin #' . $admin);
                Pages::reset();
                return [[['ok', 'نود ' . View::ltr($name) . ' حذف شد.']], []];
            }
            $r = $api->post('/api/v1/edges/' . $id . '/rotate-token');
            Env::log('edge ' . $name . ' token rotated by admin #' . $admin);
            $token = is_string($r['token'] ?? null) ? $r['token'] : '';
            return [[['ok', 'توکن نود ' . View::ltr($name) . ' عوض شد؛ توکن قبلی دیگر کار نمی‌کند.']],
                $token !== '' ? ['token' => ['token' => $token, 'name' => $name, 'title' => 'توکن جدید نود',
                    'region' => $region, 'role' => $role]] : []];
        } catch (\Throwable $e) {
            return [[['bad', View::e('عملیات روی نود ناموفق بود: ' . $e->getMessage())]], []];
        }
    }

    // ------------------------------------------------------------------ §12 multi-address edges & health-based failover
    //
    // Address management + visibility of the AUTOMATIC health-based failover. The active address is
    // chosen automatically by the controller's health probe; there is deliberately NO "force/switch to
    // this IP now" action here — only add / edit / enable-for-maintenance / disable / remove.

    /** True when $ip is a valid public address of the given family ('4'|'6'). */
    private static function validPublicIp(string $ip, string $family): bool
    {
        if ($family === '6') {
            return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        }
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /** Add an additional address to a node: POST /api/v1/edges/{id}/addresses {family, ip, label?}. */
    private static function edgeAddrAdd(array $post, int $admin): array
    {
        $id = (int) ($post['id'] ?? 0);
        $family = Env::input($post['family'] ?? '');
        $ip = Env::input($post['ip'] ?? '');
        $label = View::clip(Env::input($post['label'] ?? ''), 64);
        $e = [];
        if ($id <= 0) {
            $e[] = 'شناسه نود نامعتبر است.';
        }
        if (!in_array($family, ['4', '6'], true)) {
            $e[] = 'نسخهٔ IP نامعتبر است (۴ یا ۶).';
        } elseif (!self::validPublicIp($ip, $family)) {
            $e[] = $family === '6' ? 'IPv6 معتبر نیست.' : 'IPv4 باید یک آدرس عمومی معتبر باشد.';
        }
        if ($e) {
            return [array_map(function ($m) {
                return ['bad', View::e($m)];
            }, $e), []];
        }
        $body = ['family' => (int) $family, 'ip' => $ip];
        if ($label !== '') {
            $body['label'] = $label;
        }
        try {
            Env::api(10)->post('/api/v1/edges/' . $id . '/addresses', $body);
        } catch (\Throwable $ex) {
            return [[['bad', View::e('افزودن آدرس ناموفق بود: ' . $ex->getMessage())]], []];
        }
        Env::log('edge #' . $id . ' additional address ' . $ip . ' (IPv' . $family . ') added by admin #' . $admin);
        Pages::reset();
        return [[['ok', 'آدرس ' . View::ltr($ip) . ' افزوده شد؛ پس از اولین بررسی سلامت به‌صورت خودکار در DNS اعلام می‌شود.']], []];
    }

    /** Edit/rename an additional address: PATCH /api/v1/edges/{id}/addresses/{aid} {ip?, label?}. */
    private static function edgeAddrEdit(array $post, int $admin): array
    {
        $id = (int) ($post['id'] ?? 0);
        $aid = (int) ($post['aid'] ?? 0);
        $ip = Env::input($post['ip'] ?? '');
        $family = Env::input($post['family'] ?? '');
        $label = View::clip(Env::input($post['label'] ?? ''), 64);
        if ($id <= 0 || $aid <= 0) {
            return [[['bad', 'شناسه آدرس نامعتبر است.']], []];
        }
        $body = [];
        if ($ip !== '') {
            $fam = in_array($family, ['4', '6'], true) ? $family : (strpos($ip, ':') !== false ? '6' : '4');
            if (!self::validPublicIp($ip, $fam)) {
                return [[['bad', $fam === '6' ? 'IPv6 معتبر نیست.' : 'IPv4 باید یک آدرس عمومی معتبر باشد.']], []];
            }
            $body['ip'] = $ip;
        }
        // label is always sent so it can also be cleared
        $body['label'] = $label;
        try {
            Env::api(10)->request('PATCH', '/api/v1/edges/' . $id . '/addresses/' . $aid, $body);
        } catch (\Throwable $ex) {
            return [[['bad', View::e('ویرایش آدرس ناموفق بود: ' . $ex->getMessage())]], []];
        }
        Env::log('edge #' . $id . ' address #' . $aid . ' edited by admin #' . $admin);
        Pages::reset();
        return [[['ok', 'آدرس به‌روزرسانی شد.']], []];
    }

    /** Enable/disable an additional address for maintenance: PATCH …/addresses/{aid} {enabled}. */
    private static function edgeAddrToggle(array $post, int $admin): array
    {
        $id = (int) ($post['id'] ?? 0);
        $aid = (int) ($post['aid'] ?? 0);
        $on = (string) ($post['enabled'] ?? '') === '1';
        if ($id <= 0 || $aid <= 0) {
            return [[['bad', 'شناسه آدرس نامعتبر است.']], []];
        }
        try {
            Env::api(10)->request('PATCH', '/api/v1/edges/' . $id . '/addresses/' . $aid, ['enabled' => $on]);
        } catch (\Throwable $ex) {
            return [[['bad', View::e('تغییر وضعیت آدرس ناموفق بود: ' . $ex->getMessage())]], []];
        }
        Env::log('edge #' . $id . ' address #' . $aid . ' ' . ($on ? 'enabled' : 'disabled for maintenance') . ' by admin #' . $admin);
        Pages::reset();
        return [[['ok', $on ? 'آدرس فعال شد؛ پس از تأیید سلامت دوباره به‌صورت خودکار در DNS اعلام می‌شود.'
            : 'آدرس برای نگهداری غیرفعال و بی‌درنگ از DNS خارج شد.']], []];
    }

    /** Remove an additional address: DELETE /api/v1/edges/{id}/addresses/{aid} (the primary cannot be deleted). */
    private static function edgeAddrDelete(array $post, int $admin): array
    {
        $id = (int) ($post['id'] ?? 0);
        $aid = (int) ($post['aid'] ?? 0);
        if ($id <= 0 || $aid <= 0) {
            return [[['bad', 'شناسه آدرس نامعتبر است.']], []];
        }
        try {
            Env::api(10)->delete('/api/v1/edges/' . $id . '/addresses/' . $aid);
        } catch (\Throwable $ex) {
            return [[['bad', View::e('حذف آدرس ناموفق بود: ' . $ex->getMessage())]], []];
        }
        Env::log('edge #' . $id . ' address #' . $aid . ' removed by admin #' . $admin);
        Pages::reset();
        return [[['ok', 'آدرس حذف شد.']], []];
    }

    private static function wizard(string $action, array $post, int $admin): array
    {
        $currencies = Data::currencies();
        [$in, $errors] = Wizard::fromPost($post, $currencies);
        if ($action === 'wizard_edit') {
            return [[], ['input' => $in]];
        }
        if ($errors) {
            return [[['bad', 'فرم ایراد دارد؛ موارد مشخص‌شده را اصلاح کنید.']], ['input' => $in, 'errors' => $errors]];
        }
        if ($action === 'wizard_preview') {
            return [[], ['preview' => true, 'input' => $in, 'post' => $post]];
        }
        try {
            $summary = Wizard::apply($in, $currencies);
        } catch (\Throwable $e) {
            Env::log('product wizard failed (rolled back) by admin #' . $admin . ': ' . $e->getMessage());
            return [[['bad', 'راه‌اندازی انجام نشد و هیچ تغییری ذخیره نشد: ' . View::e($e->getMessage())]], ['input' => $in]];
        }
        Env::reset();
        $n = ['create' => 0, 'update' => 0];
        foreach ($summary as $s) {
            if (isset($n[$s['op']])) {
                $n[$s['op']]++;
            }
        }
        Env::log('product wizard applied by admin #' . $admin . ': ' . $n['create'] . ' created, ' . $n['update'] . ' updated');
        Env::cacheDelete(WidgetData::KEY);
        return [[['ok', 'راه‌اندازی انجام شد: ' . View::n($n['create']) . ' مورد ساخته و ' . View::n($n['update']) . ' مورد به‌روزرسانی شد.']],
            ['summary' => $summary]];
    }

    /**
     * Bulk-enable tunnel on already-provisioned CDN services after the products are unified
     * (tunnel included in every plan). For every ACTIVE service on a product whose plan has tunnel on
     * (configoption15 = on) it re-pushes the plan to the controller — the same PATCH …/plan that
     * ChangePackage uses — so tunnel goes live immediately, and defensively flips any per-service tunnel
     * configurable-option override that is still off. Idempotent (safe to re-run), never touches billing.
     */
    private static function enableTunnelExisting(int $admin): array
    {
        $rows = Data::serviceQuery()->where('h.domainstatus', 'Active')->where('p.configoption15', 'on')
            ->orderBy('h.id')->get(['h.id', 'h.userid', 'h.packageid', 'h.server', 'h.domain'])->all();
        if (!$rows) {
            return [['warn', 'هیچ سرویس فعالی روی محصولی با تونل روشن پیدا نشد. ابتدا محصولات CDN را با «راه‌اندازی خودکار» (حالت به‌روزرسانی) تونل‌دار کنید.']];
        }
        $ok = 0;
        $skip = 0;
        $fail = 0;
        $cfg = 0;
        $errs = [];
        $products = [];
        foreach ($rows as $svc) {
            $sid = (int) $svc->id;
            $domain = Env::domain((string) $svc->domain);
            if (!Env::validHostname($domain)) {
                $skip++;
                continue;
            }
            $pid = (int) $svc->packageid;
            if (!array_key_exists($pid, $products)) {
                $products[$pid] = Capsule::table('tblproducts')->where('id', $pid)->first();
            }
            $prod = $products[$pid];
            if (!$prod) {
                $skip++;
                continue;
            }
            // Target limits come from the product's module settings (configoption15..19), independent of any
            // per-service configurable-option overrides — so an override cannot keep tunnel off.
            $prodFeatures = \pasargadcdn_plan(self::serviceParams(0, $prod))['features'];
            if (empty($prodFeatures['tunnel'])) {
                $skip++;
                continue;
            }
            $cfg += self::forceTunnelConfigOptions($sid, $prodFeatures);
            // Push the effective plan (product settings + per-service overrides + prepaid top-ups) so tunnel is live now.
            $plan = \pasargadcdn_cap_plan(self::serviceParams($sid, $prod));
            try {
                Env::api(15, self::serverOf($svc))->patch(ApiClient::site($domain) . '/plan', $plan);
                $ok++;
            } catch (\Throwable $e) {
                $fail++;
                if (count($errs) < 5) {
                    $errs[] = View::ltr($domain) . ': ' . $e->getMessage();
                }
            }
        }
        Env::log('bulk enable tunnel on existing CDN services by admin #' . $admin
            . ": pushed=$ok, config_options=$cfg, skipped=$skip, failed=$fail");
        Pages::reset();
        Env::cacheDelete(WidgetData::KEY);
        $flash = [];
        if ($ok > 0) {
            $flash[] = ['ok', 'تونل روی ' . View::n($ok) . ' سرویس فعال شد (پلن دوباره به کنترلر ارسال شد).'
                . ($cfg > 0 ? ' ' . View::n($cfg) . ' گزینه سفارشی تونل هم روشن شد.' : '')];
        }
        if ($skip > 0) {
            $flash[] = ['warn', View::n($skip) . ' سرویس رد شد (دامنه نامعتبر یا تونل در پلن آن روشن نیست).'];
        }
        if ($fail > 0) {
            $flash[] = ['bad', 'ارسال پلن ' . View::n($fail) . ' سرویس ناموفق بود: ' . View::e(implode('؛ ', $errs))];
        }
        return $flash ?: [['warn', 'هیچ سرویسی به‌روزرسانی نشد.']];
    }

    /** Module params (product module-settings + per-service configurable options) for the plan computation. */
    private static function serviceParams(int $sid, $prod): array
    {
        $params = ['serviceid' => $sid, 'pid' => (int) $prod->id, 'packageid' => (int) $prod->id, 'configoptions' => []];
        for ($i = 1; $i <= 24; $i++) {
            $params['configoption' . $i] = (string) ($prod->{'configoption' . $i} ?? '');
        }
        if (function_exists('pasargadcdn_config_options')) {
            $params['configoptions'] = \pasargadcdn_config_options([$sid])[$sid] ?? [];
        }
        return $params;
    }

    /**
     * Defensively raise the per-service tunnel configurable-option OVERRIDES (tblhostingconfigoptions) to
     * match the plan: turn a «Tunnel» yes/no override on and raise «Tunnel Paths/Connections/Mbps» quantity
     * overrides up to the plan value. A no-op when no such configurable options exist (the usual case, where
     * the plan lives only in the product's module settings). Returns the number of option rows changed.
     */
    private static function forceTunnelConfigOptions(int $sid, array $features): int
    {
        $changed = 0;
        try {
            if (!Env::hasTable('tblhostingconfigoptions') || !Env::hasTable('tblproductconfigoptions')) {
                return 0;
            }
            $want = [
                'Tunnel Paths' => (int) ($features['max_tunnel_paths'] ?? 0),
                'Tunnel Connections' => (int) ($features['max_tunnel_connections'] ?? 0),
                'Tunnel Mbps' => (int) ($features['tunnel_max_mbps'] ?? 0),
            ];
            $rows = Capsule::table('tblhostingconfigoptions as hco')
                ->join('tblproductconfigoptions as pco', 'pco.id', '=', 'hco.configid')
                ->where('hco.relid', $sid)
                ->get(['hco.id', 'hco.qty', 'pco.optionname', 'pco.optiontype']);
            foreach ($rows as $r) {
                $name = trim(explode('|', (string) $r->optionname)[0]);
                $type = (int) $r->optiontype;
                $cur = (int) $r->qty;
                $new = null;
                if ($name === 'Tunnel' && $type === 3 && $cur === 0) {
                    $new = 1; // yes/no override → on
                } elseif (isset($want[$name]) && $type === 4 && $cur < $want[$name]) {
                    $new = $want[$name]; // quantity override → at least the plan value
                }
                if ($new !== null && $new !== $cur) {
                    Capsule::table('tblhostingconfigoptions')->where('id', (int) $r->id)->update(['qty' => $new]);
                    $changed++;
                }
            }
        } catch (\Throwable $e) {
            // WHMCS schema differences: skip the config-option write; the controller plan-push still enables tunnel.
            return $changed;
        }
        return $changed;
    }

    // ------------------------------------------------------------------ 8. incidents / public status

    const INC_SEVERITY = ['minor', 'major', 'maintenance'];
    const INC_STATUS = ['investigating', 'identified', 'monitoring', 'resolved'];

    /** POST /api/v1/incidents {title, body, severity, status?} */
    private static function incidentCreate(array $post, int $admin): array
    {
        $old = [
            'title' => Env::input($post['title'] ?? ''),
            'body' => Env::input($post['body'] ?? ''),
            'severity' => Env::input($post['severity'] ?? ''),
            'status' => Env::input($post['status'] ?? 'investigating') ?: 'investigating',
        ];
        $e = [];
        if (function_exists('mb_strlen') ? mb_strlen($old['title']) < 3 : strlen($old['title']) < 3) {
            $e[] = 'عنوان رخداد را وارد کنید (حداقل ۳ نویسه).';
        }
        if ($old['body'] === '') {
            $e[] = 'متن رخداد را وارد کنید.';
        }
        if (!in_array($old['severity'], self::INC_SEVERITY, true)) {
            $e[] = 'شدت رخداد نامعتبر است.';
        }
        if (!in_array($old['status'], self::INC_STATUS, true)) {
            $e[] = 'وضعیت اولیه نامعتبر است.';
        }
        if ($e) {
            return [array_map(function ($m) {
                return ['bad', View::e($m)];
            }, $e), ['incident_form' => $old]];
        }
        try {
            Env::api(10)->post('/api/v1/incidents', ['title' => $old['title'], 'body' => $old['body'],
                'severity' => $old['severity'], 'status' => $old['status']]);
        } catch (\Throwable $ex) {
            return [[['bad', View::e('ثبت رخداد ناموفق بود: ' . $ex->getMessage())]], ['incident_form' => $old]];
        }
        Env::log('incident "' . $old['title'] . '" (' . $old['severity'] . '/' . $old['status'] . ') created by admin #' . $admin);
        Pages::reset();
        return [[['ok', 'رخداد «' . View::e($old['title']) . '» ثبت شد.']], []];
    }

    /** POST /api/v1/incidents/{id}/updates {status, body} — also moves the incident status. */
    private static function incidentUpdate(array $post, int $admin): array
    {
        $id = (int) ($post['id'] ?? 0);
        $status = Env::input($post['status'] ?? '');
        $body = Env::input($post['body'] ?? '');
        if ($id <= 0) {
            return [[['bad', 'شناسه رخداد نامعتبر است.']], []];
        }
        if (!in_array($status, self::INC_STATUS, true)) {
            return [[['bad', 'وضعیت به‌روزرسانی نامعتبر است.']], []];
        }
        if ($body === '') {
            return [[['bad', 'متن به‌روزرسانی را وارد کنید.']], []];
        }
        try {
            Env::api(10)->post('/api/v1/incidents/' . $id . '/updates', ['status' => $status, 'body' => $body]);
        } catch (\Throwable $ex) {
            return [[['bad', View::e('ثبت به‌روزرسانی ناموفق بود: ' . $ex->getMessage())]], []];
        }
        Env::log('incident #' . $id . ' updated to ' . $status . ' by admin #' . $admin);
        Pages::reset();
        return [[['ok', 'به‌روزرسانی رخداد #' . View::n($id) . ' ثبت شد.']], []];
    }

    // ------------------------------------------------------------------ §10.5 resellers

    private static function resellerFlag(array $post, int $admin): array
    {
        $q = Env::input($post['client'] ?? '');
        if ($q === '') {
            return ['bad', 'شناسه، ایمیل یا نام مشتری را وارد کنید.'];
        }
        $uid = Resellers::resolveClient($q);
        if ($uid <= 0) {
            return ['bad', 'مشتری یافت نشد یا بیش از یک نتیجه داشت؛ شناسه عددی یا ایمیل دقیق را وارد کنید.'];
        }
        Resellers::flag($uid);
        Pages::reset();
        Env::log('client #' . $uid . ' flagged as reseller by admin #' . $admin, $uid);
        return ['ok', 'مشتری #' . View::n($uid) . ' به‌عنوان نماینده فعال شد.'];
    }

    private static function resellerSave(array $post, int $admin): array
    {
        $uid = (int) ($post['userid'] ?? 0);
        if ($uid <= 0) {
            return ['bad', 'شناسه نماینده نامعتبر است.'];
        }
        $rateRaw = trim(str_replace([',', '٬'], '', Env::input($post['rate'] ?? '')));
        $rate = null;
        if ($rateRaw !== '') {
            if (!is_numeric($rateRaw) || (float) $rateRaw < 0) {
                return ['bad', 'قیمت هر گیگابایت نامعتبر است (خالی = نرخ سراسری).'];
            }
            $rate = (float) $rateRaw;
        }
        $maxRaw = trim(Env::input($post['max_sites'] ?? '0'));
        if ($maxRaw !== '' && !ctype_digit($maxRaw)) {
            return ['bad', 'حداکثر تعداد سایت باید عدد صحیح باشد (۰ = پیش‌فرض سراسری).'];
        }
        $max = (int) $maxRaw;
        $enabled = in_array(strtolower(Env::input($post['enabled'] ?? '0')), ['1', 'on', 'yes', 'true'], true);
        $note = Env::input($post['note'] ?? '');
        if (!Resellers::save($uid, $rate, $max, $enabled, $note)) {
            return ['bad', 'نماینده یافت نشد.'];
        }
        Pages::reset();
        Env::log('reseller #' . $uid . ' updated by admin #' . $admin . ' (rate '
            . ($rate === null ? 'global' : (string) $rate) . ', max ' . $max . ', ' . ($enabled ? 'enabled' : 'disabled') . ')', $uid);
        return ['ok', 'تنظیمات نماینده #' . View::n($uid) . ' ذخیره شد.'];
    }

    private static function resellerSettings(array $post, int $admin): array
    {
        $rateRaw = trim(str_replace([',', '٬'], '', Env::input($post['reseller_rate'] ?? '')));
        if ($rateRaw !== '' && (!is_numeric($rateRaw) || (float) $rateRaw < 0)) {
            return ['bad', 'قیمت عمده هر گیگابایت نامعتبر است.'];
        }
        $maxRaw = trim(Env::input($post['reseller_max_sites'] ?? ''));
        if ($maxRaw !== '' && !ctype_digit($maxRaw)) {
            return ['bad', 'حداکثر زیرسایت باید عدد صحیح باشد.'];
        }
        Env::saveSetting('reseller_rate', $rateRaw);
        Env::saveSetting('reseller_max_sites', $maxRaw === '' ? '0' : $maxRaw);
        if (function_exists('pasargadcdn_addon_settings')) {
            \pasargadcdn_addon_settings(true);
        }
        Pages::reset();
        Env::log('reseller global settings saved by admin #' . $admin . ' (rate ' . ($rateRaw ?: 'unset') . ', max ' . ($maxRaw ?: '0') . ')');
        return ['ok', 'تنظیمات سراسری نمایندگی ذخیره شد.'];
    }

    /** Quick resolve: posts a "resolved" update so it lands in the timeline too. */
    private static function incidentResolve(int $id, int $admin): array
    {
        if ($id <= 0) {
            return [[['bad', 'شناسه رخداد نامعتبر است.']], []];
        }
        try {
            Env::api(10)->post('/api/v1/incidents/' . $id . '/updates',
                ['status' => 'resolved', 'body' => 'این رخداد برطرف شد و سرویس‌ها به وضعیت عادی بازگشتند.']);
        } catch (\Throwable $ex) {
            return [[['bad', View::e('برطرف‌کردن رخداد ناموفق بود: ' . $ex->getMessage())]], []];
        }
        Env::log('incident #' . $id . ' resolved by admin #' . $admin);
        Pages::reset();
        return [[['ok', 'رخداد #' . View::n($id) . ' برطرف شد.']], []];
    }
}
