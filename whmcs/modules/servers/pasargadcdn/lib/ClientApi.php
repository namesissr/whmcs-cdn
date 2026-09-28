<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

/**
 * Core of api.php — the JSON proxy between the client-area app and the
 * controller. Kept free of globals so it can be tested without WHMCS:
 * api.php collects the request + session facts and calls handle().
 *
 * The site domain always comes from the service row, never from the client;
 * the client only picks one of the whitelisted sub-paths below.
 */
class ClientApi
{
    const MAX_BODY = 262144; // 256 KB

    const SECTIONS = 'cache|ssl|waf|ddos|firewall|ratelimit|pagerules|pools|headers|hotlink|image|errorpages';

    /** method => [sub-path regex relative to /api/v1/sites/{domain}, ...] */
    const ROUTES = [
        'GET' => [
            '', 'config/(?:' . self::SECTIONS . ')', 'records', 'records/export', 'dnssec',
            'analytics', 'events', 'usage',
        ],
        'POST' => ['records', 'records/import', 'dnssec', 'purge', 'ns-check', 'ssl'],
        'PUT' => ['config/(?:' . self::SECTIONS . ')', 'records/[1-9][0-9]{0,9}', 'ssl/custom'],
        'DELETE' => ['records/[1-9][0-9]{0,9}', 'ssl/custom'],
    ];

    /** Query parameters the client may pass, per sub-path, with their allowed values. */
    const QUERY = [
        'analytics' => ['period' => '/^(24h|7d|30d)$/D'],
        'events' => ['limit' => '/^([1-9][0-9]{0,2}|1000)$/D'],
        'usage' => ['days' => '/^([1-9][0-9]{0,2})$/D'],
    ];

    /**
     * @param array $req [
     *   'method' => 'GET', 'id' => '123', 'path' => 'config/cache', 'query' => [...],
     *   'body' => raw request body, 'csrf' => X-PCDN-CSRF header,
     *   'session_csrf' => token stored in the session, 'client_id' => logged-in client id or 0,
     * ]
     * @param callable|null $clientFactory fn(array $serverParams): ApiClient (tests)
     * @return array [http status, response array]
     */
    public static function handle(array $req, ?callable $clientFactory = null): array
    {
        $method = strtoupper((string) ($req['method'] ?? 'GET'));
        $path = (string) ($req['path'] ?? '');

        if ((int) ($req['client_id'] ?? 0) <= 0) {
            return self::fail(401, 'لطفاً دوباره وارد حساب کاربری شوید.');
        }
        $sessionToken = (string) ($req['session_csrf'] ?? '');
        if ($sessionToken === '' || !hash_equals($sessionToken, (string) ($req['csrf'] ?? ''))) {
            return self::fail(403, 'درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.');
        }
        if (!self::allowed($method, $path)) {
            return self::fail(404, 'مسیر نامعتبر است.');
        }
        $id = (string) ($req['id'] ?? '');
        if (!preg_match('/^[1-9][0-9]{0,9}$/D', $id)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }

        $svc = Capsule::table('tblhosting')->where('id', (int) $id)
            ->first(['id', 'userid', 'packageid', 'server', 'domain', 'domainstatus']);
        // Same answer for "missing" and "not yours" so ids can't be probed.
        if (!$svc || (int) $svc->userid !== (int) $req['client_id']) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $product = Capsule::table('tblproducts')->where('id', (int) $svc->packageid)->first(['servertype']);
        if (!$product || $product->servertype !== 'pasargadcdn') {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $status = (string) $svc->domainstatus;
        if ($method === 'GET' ? !in_array($status, ['Active', 'Suspended'], true) : $status !== 'Active') {
            return self::fail(403, 'این سرویس فعال نیست.');
        }

        $body = null;
        if ($method === 'POST' || $method === 'PUT') {
            $raw = (string) ($req['body'] ?? '');
            if (strlen($raw) > self::MAX_BODY) {
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

        $domain = \pasargadcdn_domain(['domain' => $svc->domain]);
        // Defence in depth: the service domain is admin/order data, keep it a plain hostname.
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/D', $domain)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $server = Capsule::table('tblservers')->where('id', (int) $svc->server)
            ->first(['type', 'hostname', 'ipaddress', 'secure', 'port', 'accesshash', 'password']);
        if (!$server || $server->type !== 'pasargadcdn') {
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
            $api = $clientFactory ? $clientFactory($params) : ApiClient::fromParams($params);
            [$code, $data] = $api->raw($method, $target, $body);
        } catch (\Throwable $e) {
            self::log($method . ' ' . $target, $e->getMessage());
            return self::fail(502, 'اتصال به سرور CDN برقرار نشد.');
        }
        if ($code >= 500 || $code < 200 || ($code >= 300 && $code < 400)) {
            self::log($method . ' ' . $target, 'HTTP ' . $code);
            return self::fail(502, 'خطای سرور CDN (HTTP ' . $code . ')');
        }
        if (!is_array($data)) {
            // Empty/non-JSON body: fine for a 2xx, generic message for a 4xx.
            return $code < 300 ? [$code, ['ok' => true]] : self::fail($code, 'درخواست توسط سرور CDN رد شد (HTTP ' . $code . ')');
        }
        return [$code, $data];
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

    private static function fail(int $code, string $detail): array
    {
        return [$code, ['detail' => $detail]];
    }

    private static function log(string $action, string $error): void
    {
        if (function_exists('logModuleCall')) {
            logModuleCall('pasargadcdn', 'clientapi ' . $action, '', $error);
        }
    }
}
