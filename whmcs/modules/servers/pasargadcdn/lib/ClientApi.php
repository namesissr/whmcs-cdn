<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

require_once __DIR__ . '/I18n.php';

if (class_exists(__NAMESPACE__ . '\\ClientApi', false)) {
    return;
}

/**
 * Core of api.php — the JSON proxy between the client-area app and the
 * controller. Kept free of globals so it can be tested without WHMCS:
 * api.php collects the request + session facts and calls handle().
 *
 * The site domain always comes from the service row, never from the client;
 * the client only picks one of the whitelisted sub-paths below.
 *
 * Admin mode (the addon's «مدیریت کامل» page, 'admin_id' > 0 in the request):
 * same whitelist, CSRF and domain-from-service rules, but no ownership check
 * and writes are allowed whatever the WHMCS status is; every admin write is
 * recorded with logActivity().
 *
 * Reseller mode (SPEC §10.5, 'reseller_site_id' > 0): the same whitelist, CSRF,
 * query rules and proxy, but the domain is resolved from the reseller's OWN
 * sub-site row (mod_pasargadcdn_reseller_sites) keyed by (id, userid). A reseller
 * can only ever reach a sub-site whose userid matches the logged-in client; the
 * same "not found" answer covers a missing row and one owned by someone else.
 * 'reseller_op' carries the reseller-level actions (list/create/delete/report).
 *
 * Language (SPEC §16.10): error details are written in Persian and answered in English when the
 * client app is English ('lang' => 'en', from its X-PCDN-Lang header); admin mode stays Persian.
 */
class ClientApi
{
    const MAX_BODY = 262144; // 256 KB

    /**
     * SPEC §16.9: body limit of PUT config/functions only — the whole section with every function's
     * code (up to 32 × 256 KiB of UTF-8, i.e. 8 MiB, plus JSON escaping); every other call keeps
     * MAX_BODY. See maxBody().
     */
    const MAX_BODY_FUNCTIONS = 9437184; // 9 MB

    // Wave 6B (SPEC §14.2) added transform, redirects and bots; Wave 6D (§14.3) logs and webhooks;
    // Wave 8 (§16.4/§16.5/§16.7) l4 (TCP/UDP apps), video and dns_secondary; §16.9 functions (edge functions).
    const SECTIONS = 'cache|ssl|waf|ddos|firewall|ratelimit|pagerules|pools|headers|hotlink|image|errorpages|tunnel|transform|redirects|bots|logs|webhooks|l4|video|dns_secondary|functions';

    /** Webhook ids are assigned by the controller: "wh_" + 8 hex (SPEC §14.3.3). */
    const WEBHOOK_ID = 'wh_[0-9a-f]{8}';

    /**
     * SPEC §16.8 bucket name as the controller accepts it (storage.validate_name / NAME_RE): 3–40
     * characters of a-z, 0-9 and -, starting and ending with a letter or digit. Anything else never
     * leaves WHMCS (the controller prefixes it and never lets a name choose a host).
     */
    const BUCKET = '[a-z0-9][a-z0-9-]{1,38}[a-z0-9]';

    /** method => [sub-path regex relative to /api/v1/sites/{domain}, ...] */
    const ROUTES = [
        'GET' => [
            '', 'config/(?:' . self::SECTIONS . ')', 'records', 'records/export', 'dnssec',
            'analytics', 'events', 'usage', 'tunnel/stats', 'apikeys', 'origin-pull-ca',
            // Wave 6D (SPEC §14.3.1–§14.3.4)
            'analytics/live', 'logs/status', 'webhooks/deliveries', 'sla',
            // Wave 7 (SPEC §15.3/§15.4): tunnel quality, tunnel usage and origin health — read-only
            'tunnel/quality', 'tunnel/usage', 'tunnel/health',
            // SPEC §16.8 object storage: overview + buckets (never a secret — the controller returns
            // secret_key only in the create / rotate-key answers)
            'storage', 'storage/buckets',
            // SPEC §16.9 edge functions: invocations / CPU / errors of the last `hours` (read-only)
            'functions/stats',
        ],
        'POST' => ['records', 'records/import', 'dnssec', 'purge', 'ns-check', 'ssl', 'tunnel/check', 'apikeys', 'redirects/import',
            'logs/test', 'webhooks/' . self::WEBHOOK_ID . '/(?:rotate|test)',
            // Wave 8 (SPEC §16.6): new image transform secret (returned once, never logged — ApiClient::redact)
            'image/transform-secret',
            // SPEC §16.8: new bucket / new access key — secret_key returned once, never logged (ApiClient::redact)
            'storage/buckets', 'storage/buckets/' . self::BUCKET . '/rotate-key'],
        'PUT' => ['config/(?:' . self::SECTIONS . ')', 'records/[1-9][0-9]{0,9}', 'ssl/custom', 'ssl/origin-client'],
        'DELETE' => ['records/[1-9][0-9]{0,9}', 'ssl/custom', 'apikeys/[1-9][0-9]{0,9}', 'ssl/origin-client',
            // Wave 8 (SPEC §16.6): forget the image transform secret (unsigned transforms allowed again)
            'image/transform-secret',
            // SPEC §16.8: delete an (empty, unused) bucket — 409 otherwise
            'storage/buckets/' . self::BUCKET],
    ];

    /**
     * Whitelisted sub-paths that are NOT under /api/v1/sites/{domain}: public, site-independent
     * controller files fetched server-side so the browser never needs (or learns) the controller
     * URL. Same login/CSRF/ownership rules as every other path. sub-path => controller path.
     */
    const PUBLIC_FILES = ['origin-pull-ca' => '/origin-pull-ca.pem'];
    const MAX_PEM = 65536;

    /** Query parameters the client may pass, per sub-path, with their allowed values. */
    const QUERY = [
        'analytics' => ['period' => '/^(24h|7d|30d)$/D'],
        'events' => ['limit' => '/^([1-9][0-9]{0,2}|1000)$/D'],
        'usage' => ['days' => '/^([1-9][0-9]{0,2})$/D'],
        'tunnel/stats' => ['hours' => '/^(24|168|720)$/D'],
        // Wave 6D: live minutes 1..1440 (the app uses 15/60/360/1440), deliveries limit 1..200, SLA month YYYY-MM.
        'analytics/live' => ['minutes' => '/^([1-9][0-9]{0,2}|1[0-3][0-9]{2}|14[0-3][0-9]|1440)$/D'],
        'webhooks/deliveries' => ['limit' => '/^([1-9][0-9]?|1[0-9]{2}|200)$/D'],
        'sla' => ['month' => '/^[0-9]{4}-(0[1-9]|1[0-2])$/D'],
        // Wave 7: quality hours 1..744 (the app uses 24/168/720), tunnel usage days 1..90 (the app uses 30).
        'tunnel/quality' => ['hours' => '/^([1-9]|[1-9][0-9]|[1-6][0-9]{2}|7[0-3][0-9]|74[0-4])$/D'],
        'tunnel/usage' => ['days' => '/^([1-9]|[1-8][0-9]|90)$/D'],
        // SPEC §16.9: functions stats hours 1..744 (the app uses 24 and 168)
        'functions/stats' => ['hours' => '/^([1-9]|[1-9][0-9]|[1-6][0-9]{2}|7[0-3][0-9]|74[0-4])$/D'],
    ];

    /** Answer for a write by a read-only team member (SPEC §14.3.7). */
    const READONLY_DETAIL = 'دسترسی شما به این سرویس فقط‌خواندنی است؛ برای تغییر تنظیمات از مالک حساب بخواهید دسترسی «مدیریت محصولات» را به شما بدهد.';

    /**
     * @param array $req [
     *   'method' => 'GET', 'id' => '123', 'path' => 'config/cache', 'query' => [...],
     *   'body' => raw request body, 'csrf' => X-PCDN-CSRF header,
     *   'session_csrf' => token stored in the session, 'client_id' => logged-in client id or 0,
     *   'admin_id' => WHMCS admin id (admin mode only — set by the addon, never from input),
     *   'readonly' => true for a WHMCS user without the manage-products permission (TeamAccess, §14.3.7):
     *                 every non-GET call is refused with 403 before anything else happens,
     *   'lang' => 'fa' | 'en' — language of the error details (§16.10; ignored in admin mode),
     * ]
     * @param callable|null $clientFactory fn(array $serverParams): ApiClient (tests)
     * @return array [http status, response array]
     */
    public static function handle(array $req, ?callable $clientFactory = null): array
    {
        $method = strtoupper((string) ($req['method'] ?? 'GET'));
        $path = (string) ($req['path'] ?? '');

        $adminId = (int) ($req['admin_id'] ?? 0);
        $admin = $adminId > 0;
        I18n::$current = !$admin && ($req['lang'] ?? '') === 'en' ? 'en' : 'fa';
        if (!$admin && (int) ($req['client_id'] ?? 0) <= 0) {
            return self::fail(401, 'لطفاً دوباره وارد حساب کاربری شوید.');
        }
        $sessionToken = (string) ($req['session_csrf'] ?? '');
        if ($sessionToken === '' || !hash_equals($sessionToken, (string) ($req['csrf'] ?? ''))) {
            return self::fail(403, 'درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.');
        }
        // Team access (SPEC §14.3.7): a read-only WHMCS user may only read — this covers config
        // writes, purges, records, API keys, webhook tests/rotation and the reseller ops alike,
        // whatever the UI shows. Admin mode is never read-only.
        if (!$admin && !empty($req['readonly']) && $method !== 'GET') {
            return self::fail(403, self::READONLY_DETAIL);
        }
        // Reseller-level operations (list / create / delete sub-site, rolled-up report).
        // Not tied to a controller sub-path, so handled before the site whitelist.
        $rop = (string) ($req['reseller_op'] ?? '');
        if ($rop !== '') {
            return self::resellerOp($rop, $req, $clientFactory);
        }
        if (!self::allowed($method, $path)) {
            return self::fail(404, 'مسیر نامعتبر است.');
        }

        // Reseller mode (SPEC §10.5): manage one of the logged-in client's OWN sub-sites.
        // The domain is resolved from mod_pasargadcdn_reseller_sites by (id, userid) — never
        // from client input — so a reseller can only ever reach a sub-site it owns.
        $rsid = (int) ($req['reseller_site_id'] ?? 0);
        if ($rsid > 0) {
            if ($admin) {
                return self::fail(404, 'سرویس یافت نشد.');
            }
            require_once __DIR__ . '/Reseller.php';
            $clientId = (int) ($req['client_id'] ?? 0);
            $row = Reseller::ownedSite($clientId, $rsid);
            // Same answer for "missing" and "not yours".
            if (!$row) {
                return self::fail(404, 'سرویس یافت نشد.');
            }
            // A sub-site cut by the wallet (suspended) may still be viewed, not written to.
            if ((int) $row->suspended === 1 && $method !== 'GET') {
                return self::fail(403, 'این زیرسایت به‌دلیل اتمام اعتبار نمایندگی موقتاً قطع است.');
            }
            $domain = \pasargadcdn_domain(['domain' => (string) $row->domain]);
            $server = Reseller::server();
            return self::proxy($method, $path, $domain, $server, $req, false, 0, null, $clientFactory);
        }

        $id = (string) ($req['id'] ?? '');
        if (!preg_match('/^[1-9][0-9]{0,9}$/D', $id)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }

        $svc = Capsule::table('tblhosting')->where('id', (int) $id)
            ->first(['id', 'userid', 'packageid', 'server', 'domain', 'domainstatus']);
        // Same answer for "missing" and "not yours" so ids can't be probed.
        if (!$svc || (!$admin && (int) $svc->userid !== (int) ($req['client_id'] ?? 0))) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $product = Capsule::table('tblproducts')->where('id', (int) $svc->packageid)->first(['servertype']);
        if (!$product || $product->servertype !== 'pasargadcdn') {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $status = (string) $svc->domainstatus;
        if (!$admin && ($method === 'GET' ? !in_array($status, ['Active', 'Suspended'], true) : $status !== 'Active')) {
            return self::fail(403, 'این سرویس فعال نیست.');
        }

        $domain = \pasargadcdn_domain(['domain' => $svc->domain]);
        $server = Capsule::table('tblservers')->where('id', (int) $svc->server)
            ->first(['type', 'hostname', 'ipaddress', 'secure', 'port', 'accesshash', 'password']);
        return self::proxy($method, $path, $domain, $server, $req, $admin, $adminId, $svc, $clientFactory);
    }

    /**
     * Shared controller proxy tail: validate body/query/domain/server and forward the
     * whitelisted call to the controller, returning [status, data]. Used for normal,
     * admin and reseller-site modes alike (same whitelist, CSRF and rules).
     */
    private static function proxy(string $method, string $path, string $domain, $server, array $req,
                                  bool $admin, int $adminId, $svc, ?callable $clientFactory): array
    {
        $body = null;
        if ($method === 'POST' || $method === 'PUT') {
            $raw = (string) ($req['body'] ?? '');
            if (strlen($raw) > self::maxBody($method, $path)) {
                return self::fail(413, 'حجم درخواست بیش از حد مجاز است.');
            }
            $data = $raw === '' ? [] : json_decode($raw, true, 64);
            if (!is_array($data)) {
                return self::fail(400, 'بدنه درخواست باید JSON معتبر باشد.');
            }
            // Re-encoded, so only well-formed JSON ever reaches the controller.
            $body = json_encode($data === [] ? new \stdClass() : $data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }

        $query = self::query($path, (array) ($req['query'] ?? []));
        if ($query === null) {
            return self::fail(400, 'پارامتر نامعتبر است.');
        }

        // Defence in depth: the domain is admin/order data, keep it a plain hostname.
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/D', $domain)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        if (!$server || ($server->type ?? '') !== 'pasargadcdn') {
            return self::fail(502, 'سرور CDN برای این سرویس تنظیم نشده است.');
        }

        $target = ApiClient::site($domain) . ($path === '' ? '' : '/' . $path) . $query;
        try {
            $params = [
                'serverhostname' => $server->hostname,
                'serverip' => $server->ipaddress,
                'serversecure' => $server->secure,
                'serverport' => $server->port,
                'serveraccesshash' => $server->accesshash,
                'serverpassword' => (trim((string) $server->accesshash) === '' && function_exists('decrypt'))
                    ? decrypt($server->password) : '',
            ];
            // Admin pages keep every controller call within 10 s.
            $api = $clientFactory ? $clientFactory($params) : ApiClient::fromParams($params, $admin ? 10 : 20);
            if (isset(self::PUBLIC_FILES[$path])) {
                return self::pemFile($api, self::PUBLIC_FILES[$path]);
            }
            [$code, $data] = $api->raw($method, $target, $body);
        } catch (\Throwable $e) {
            self::log($method . ' ' . $target, $e->getMessage());
            if ($admin && $method !== 'GET') {
                self::adminLog($adminId, $method, $path, $svc, 'failed: controller unreachable');
            }
            return self::fail(502, 'اتصال به سرور CDN برقرار نشد.');
        }
        if ($admin && $method !== 'GET') {
            self::adminLog($adminId, $method, $path, $svc, 'HTTP ' . $code);
        }
        if ($code >= 500 || $code < 200 || ($code >= 300 && $code < 400)) {
            self::log($method . ' ' . $target, 'HTTP ' . $code);
            return self::fail(502, I18n::tr('خطای سرور CDN (HTTP %s)', $code));
        }
        if (!is_array($data)) {
            // Empty/non-JSON body: fine for a 2xx, generic message for a 4xx.
            return $code < 300 ? [$code, ['ok' => true]] : self::fail($code, I18n::tr('درخواست توسط سرور CDN رد شد (HTTP %s)', $code));
        }
        if ($code >= 400 && isset($data['detail']) && is_string($data['detail'])) {
            // SPEC §16.10: a known controller detail (e.g. the §16.8 storage refusals) in the app's language
            $data['detail'] = I18n::controller($data['detail']);
        }
        return [$code, $data];
    }

    /**
     * A public certificate file of the controller (SPEC §14.2: the CA that signs the platform's
     * origin-pull client certificate), returned as JSON {pem, filename, fingerprint_sha256} for
     * the client app to offer as a download. Only well-formed CERTIFICATE blocks pass — anything
     * else (an HTML error page, a key) is refused.
     */
    private static function pemFile($api, string $file): array
    {
        if (!method_exists($api, 'rawText')) {
            return self::fail(502, 'دریافت گواهی از سرور CDN ممکن نشد.');
        }
        [$code, $text] = $api->rawText('GET', $file, self::MAX_PEM);
        if ($code === 404) {
            return self::fail(404, 'سرور CDN هنوز گواهی CA اتصال مبدأ را منتشر نکرده است.');
        }
        if ($code !== 200 || !is_string($text)) {
            self::log('GET ' . $file, 'HTTP ' . $code);
            return self::fail(502, I18n::tr('دریافت گواهی از سرور CDN ممکن نشد (HTTP %s)', $code));
        }
        $pem = trim(str_replace("\r\n", "\n", $text)) . "\n";
        $block = '-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+\/=\s]+?)-----END CERTIFICATE-----';
        if (strlen($pem) > self::MAX_PEM || stripos($pem, 'PRIVATE KEY') !== false
            || !preg_match('/\A(?:' . $block . '\s*)+\z/', $pem) || !preg_match('/' . $block . '/', $pem, $m)) {
            self::log('GET ' . $file, 'unexpected body');
            return self::fail(502, 'پاسخ سرور CDN گواهی معتبری نبود.');
        }
        // SHA-256 of the first certificate (DER) so the customer can check the file they install.
        $der = base64_decode((string) preg_replace('/\s+/', '', $m[1]), true);
        $fp = $der === false || $der === '' ? null : implode(':', str_split(strtoupper(hash('sha256', $der)), 2));
        return [200, ['pem' => $pem, 'filename' => 'pasargadcdn-origin-pull-ca.pem', 'fingerprint_sha256' => $fp]];
    }

    const RESELLER_OPS = ['list', 'create', 'delete', 'report'];

    /**
     * Reseller-level operations for the logged-in client (already CSRF-checked). Every op
     * verifies the client is an enabled reseller and only ever touches its own rows.
     */
    private static function resellerOp(string $op, array $req, ?callable $clientFactory): array
    {
        require_once __DIR__ . '/Reseller.php';
        $method = strtoupper((string) ($req['method'] ?? 'GET'));
        $clientId = (int) ($req['client_id'] ?? 0);
        if (!in_array($op, self::RESELLER_OPS, true)) {
            return self::fail(404, 'عملیات نامعتبر است.');
        }
        if ($clientId <= 0 || !Reseller::isReseller($clientId)) {
            // Non-resellers get the same generic answer — the panel is simply absent for them.
            return self::fail(404, 'یافت نشد.');
        }
        $factory = $clientFactory ? function ($server) use ($clientFactory) {
            return $clientFactory([
                'serverhostname' => $server->hostname, 'serverip' => $server->ipaddress,
                'serversecure' => $server->secure, 'serverport' => $server->port,
                'serveraccesshash' => $server->accesshash,
                'serverpassword' => (trim((string) ($server->accesshash ?? '')) === '' && function_exists('decrypt'))
                    ? decrypt($server->password) : '',
            ]);
        } : null;

        if ($op === 'list' && $method === 'GET') {
            $sites = [];
            foreach (Reseller::sites($clientId) as $r) {
                $sites[] = ['id' => (int) $r->id, 'domain' => (string) $r->domain, 'label' => (string) $r->label,
                    'suspended' => (int) $r->suspended === 1];
            }
            $cfg = Reseller::config($clientId);
            return [200, ['sites' => $sites, 'max_sites' => $cfg['max_sites'], 'count' => count($sites)]];
        }
        if ($op === 'report' && $method === 'GET') {
            return [200, Reseller::report($clientId, $factory)];
        }
        if ($op === 'create' && $method === 'POST') {
            $data = self::jsonBody($req);
            if ($data === null) {
                return self::fail(400, 'بدنه درخواست باید JSON معتبر باشد.');
            }
            [$ok, $res] = Reseller::createSite($clientId, (string) ($data['domain'] ?? ''),
                (string) ($data['origin_ip'] ?? ''), (string) ($data['label'] ?? ''), $factory);
            return $ok ? [201, $res] : self::fail(400, is_string($res) ? $res : 'ساخت زیرسایت ناموفق بود.');
        }
        if ($op === 'delete' && $method === 'POST') {
            $data = self::jsonBody($req);
            $rsid = (int) ($data['id'] ?? 0);
            [$ok, $msg] = Reseller::deleteSite($clientId, $rsid, $factory);
            return $ok ? [200, ['ok' => true, 'detail' => I18n::tr($msg)]] : self::fail(404, $msg);
        }
        return self::fail(405, 'متد مجاز نیست.');
    }

    /** Decode and re-validate a JSON request body ([] for empty), or null when malformed/oversized. */
    private static function jsonBody(array $req): ?array
    {
        $raw = (string) ($req['body'] ?? '');
        if (strlen($raw) > self::MAX_BODY) {
            return null;
        }
        if ($raw === '') {
            return [];
        }
        $data = json_decode($raw, true, 64);
        return is_array($data) ? $data : null;
    }

    /**
     * Largest request body accepted for this call: MAX_BODY_FUNCTIONS for PUT config/functions (the
     * edge-functions section carries every function's code, SPEC §16.9), MAX_BODY for everything else.
     * The entry points (api.php, the admin addon) read at most maxBody() + 1 bytes.
     */
    public static function maxBody(string $method, string $path): int
    {
        return strtoupper($method) === 'PUT' && $path === 'config/functions' ? self::MAX_BODY_FUNCTIONS : self::MAX_BODY;
    }

    public static function allowed(string $method, string $path): bool
    {
        foreach (self::ROUTES[$method] ?? [] as $re) {
            if (preg_match('#^' . $re . '$#D', $path)) {
                return true;
            }
        }
        return false;
    }

    /** Whitelisted query string for $path ('' when none), or null when a value is invalid. */
    private static function query(string $path, array $in): ?string
    {
        $out = [];
        foreach (self::QUERY[$path] ?? [] as $key => $re) {
            if (!isset($in[$key])) {
                continue;
            }
            if (!is_string($in[$key]) || !preg_match($re, $in[$key])) {
                return null;
            }
            $out[$key] = $in[$key];
        }
        return $out ? '?' . http_build_query($out) : '';
    }

    /** Error answer; a known Persian message is sent in the request's language (I18n::$current). */
    private static function fail(int $code, string $detail): array
    {
        return [$code, ['detail' => I18n::tr($detail)]];
    }

    private static function adminLog(int $adminId, string $method, string $path, $svc, string $result): void
    {
        if (function_exists('logActivity')) {
            // Path and service facts only — request bodies (certificates, keys) are never logged.
            logActivity(sprintf('Pasargad CDN [admin #%d, full management]: %s %s on service #%d (%s) — %s',
                $adminId, $method, $path === '' ? '/' : $path, (int) $svc->id, (string) $svc->domain, $result), (int) $svc->userid);
        }
    }

    private static function log(string $action, string $error): void
    {
        if (function_exists('logModuleCall')) {
            logModuleCall('pasargadcdn', 'clientapi ' . $action, '', $error);
        }
    }
}
