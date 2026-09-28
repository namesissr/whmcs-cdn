<?php
/**
 * Pasargad CDN — WHMCS provisioning module
 *
 * Sells the self-hosted Pasargad CDN (controller + edge nodes) from
 * my.pasargadmizban.com. Every WHMCS service = one domain on the CDN.
 *
 * Server setup in WHMCS:
 *   Hostname    : cdn-api.pasargadmizban.com   (the controller)
 *   Access Hash : ADMIN_API_KEY of the controller
 *   Secure      : ticked (https)
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/ApiClient.php';

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use WHMCS\Database\Capsule;

function pasargadcdn_MetaData()
{
    return [
        'DisplayName' => 'Pasargad CDN',
        'APIVersion' => '1.1',
        'RequiresServer' => true,
        'DefaultNonSSLPort' => '80',
        'DefaultSSLPort' => '443',
    ];
}

function pasargadcdn_ConfigOptions()
{
    return [
        'Bandwidth (GB)' => [
            'Type' => 'text', 'Size' => '8', 'Default' => '100',
            'Description' => 'ترافیک ماهانه (گیگابایت) — 0 یعنی نامحدود',
        ],
        'Max DNS records' => [
            'Type' => 'text', 'Size' => '8', 'Default' => '100',
        ],
        'Free SSL' => [
            'Type' => 'yesno', 'Default' => 'on',
            'Description' => 'صدور خودکار گواهی Let\'s Encrypt (دامنه + wildcard)',
        ],
        'Rate limit (req/s per IP)' => [
            'Type' => 'text', 'Size' => '8', 'Default' => '0',
            'Description' => 'محدودیت درخواست هر IP در ثانیه — 0 یعنی خاموش',
        ],
    ];
}

/**
 * Plan values from the product config, overridable by configurable options
 * named "Bandwidth", "DNS Records", "SSL" or "Rate Limit".
 */
function pasargadcdn_plan(array $params): array
{
    $plan = [
        'bandwidth_limit_gb' => max(0, (int) ($params['configoption1'] ?? 0)),
        'max_records' => max(1, (int) ($params['configoption2'] ?: 100)),
        'ssl_allowed' => ($params['configoption3'] ?? '') === 'on',
        'rate_limit_rps' => max(0, (int) ($params['configoption4'] ?? 0)),
    ];
    $co = $params['configoptions'] ?? [];
    if (isset($co['Bandwidth']) && $co['Bandwidth'] !== '') {
        $plan['bandwidth_limit_gb'] = max(0, (int) $co['Bandwidth']);
    }
    if (isset($co['DNS Records']) && $co['DNS Records'] !== '') {
        $plan['max_records'] = max(1, (int) $co['DNS Records']);
    }
    if (isset($co['SSL'])) {
        $plan['ssl_allowed'] = (bool) $co['SSL'];
    }
    if (isset($co['Rate Limit']) && $co['Rate Limit'] !== '') {
        $plan['rate_limit_rps'] = max(0, (int) $co['Rate Limit']);
    }
    return $plan;
}

function pasargadcdn_domain(array $params): string
{
    $d = strtolower(trim((string) ($params['domain'] ?? '')));
    $d = preg_replace('#^https?://#', '', $d);
    $d = rtrim(preg_replace('#/.*$#', '', $d), '.');
    return preg_replace('/^www\./', '', $d);
}

function pasargadcdn_call(callable $fn)
{
    try {
        $fn();
        return 'success';
    } catch (ApiException $e) {
        return $e->getMessage();
    } catch (\Throwable $e) {
        return 'خطای داخلی: ' . $e->getMessage();
    }
}

// --------------------------------------------------------------- lifecycle

function pasargadcdn_TestConnection(array $params)
{
    try {
        $r = ApiClient::fromParams($params)->get('/api/v1/ping');
        return ['success' => !empty($r['ok']), 'error' => empty($r['ok']) ? 'Unexpected response' : ''];
    } catch (\Throwable $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

function pasargadcdn_CreateAccount(array $params)
{
    return pasargadcdn_call(function () use ($params) {
        $domain = pasargadcdn_domain($params);
        if ($domain === '') {
            throw new ApiException('دامنه سرویس مشخص نشده است');
        }
        $body = [
            'domain' => $domain,
            'external_id' => (string) $params['serviceid'],
            'plan' => pasargadcdn_plan($params),
        ];
        $origin = trim((string) ($params['customfields']['Origin IP'] ?? ''));
        if ($origin !== '') {
            $body['origin_ip'] = $origin;
        }
        try {
            ApiClient::fromParams($params)->post('/api/v1/sites', $body);
        } catch (ApiException $e) {
            if ($e->getCode() !== 409) {
                throw $e;
            }
            // Re-run of Create on an existing site of the same service is fine.
            $site = ApiClient::fromParams($params)->get(ApiClient::site($domain));
            if (($site['external_id'] ?? '') !== (string) $params['serviceid']) {
                throw $e;
            }
        }
    });
}

function pasargadcdn_SuspendAccount(array $params)
{
    return pasargadcdn_call(function () use ($params) {
        ApiClient::fromParams($params)->post(ApiClient::site(pasargadcdn_domain($params)) . '/suspend');
    });
}

function pasargadcdn_UnsuspendAccount(array $params)
{
    return pasargadcdn_call(function () use ($params) {
        ApiClient::fromParams($params)->post(ApiClient::site(pasargadcdn_domain($params)) . '/unsuspend');
    });
}

function pasargadcdn_TerminateAccount(array $params)
{
    return pasargadcdn_call(function () use ($params) {
        try {
            ApiClient::fromParams($params)->delete(ApiClient::site(pasargadcdn_domain($params)));
        } catch (ApiException $e) {
            if ($e->getCode() !== 404) {
                throw $e;
            }
        }
    });
}

function pasargadcdn_ChangePackage(array $params)
{
    return pasargadcdn_call(function () use ($params) {
        ApiClient::fromParams($params)->patch(
            ApiClient::site(pasargadcdn_domain($params)) . '/plan',
            pasargadcdn_plan($params)
        );
    });
}

/**
 * Runs from the WHMCS daily cron: stores monthly bandwidth per service so
 * WHMCS overage billing and the client area usage bars work.
 */
function pasargadcdn_UsageUpdate(array $params)
{
    try {
        $data = ApiClient::fromParams($params)->get('/api/v1/usage');
    } catch (\Throwable $e) {
        return $e->getMessage();
    }
    foreach ($data['sites'] ?? [] as $site) {
        $serviceId = (int) ($site['external_id'] ?? 0);
        if ($serviceId <= 0) {
            continue;
        }
        Capsule::table('tblhosting')
            ->where('id', $serviceId)
            ->where('server', $params['serverid'])
            ->update([
                'bwusage' => (int) round(($site['bytes'] ?? 0) / 1048576),
                'bwlimit' => (int) ($site['bandwidth_limit_gb'] ?? 0) * 1024,
                'lastupdate' => date('Y-m-d H:i:s'),
            ]);
    }
    return 'success';
}

// --------------------------------------------------------------- admin area

function pasargadcdn_AdminCustomButtonArray()
{
    return [
        'بررسی NS' => 'adminCheckNs',
        'پاکسازی کل کش' => 'adminPurgeAll',
        'همگام‌سازی DNS' => 'adminDnsSync',
        'درخواست SSL' => 'adminRequestSsl',
    ];
}

function pasargadcdn_adminCheckNs(array $params)
{
    return pasargadcdn_call(function () use ($params) {
        $r = ApiClient::fromParams($params)->post(ApiClient::site(pasargadcdn_domain($params)) . '/ns-check');
        if (empty($r['ok'])) {
            throw new ApiException('NS هنوز تغییر نکرده. فعلی: ' . (implode(', ', $r['found'] ?? []) ?: '—'));
        }
    });
}

function pasargadcdn_adminPurgeAll(array $params)
{
    return pasargadcdn_call(function () use ($params) {
        ApiClient::fromParams($params)->post(ApiClient::site(pasargadcdn_domain($params)) . '/purge', ['urls' => []]);
    });
}

function pasargadcdn_adminDnsSync(array $params)
{
    return pasargadcdn_call(function () use ($params) {
        $r = ApiClient::fromParams($params)->post(ApiClient::site(pasargadcdn_domain($params)) . '/dns-sync');
        if (empty($r['ok'])) {
            throw new ApiException((string) ($r['error'] ?? 'DNS sync failed'));
        }
    });
}

function pasargadcdn_adminRequestSsl(array $params)
{
    return pasargadcdn_call(function () use ($params) {
        ApiClient::fromParams($params)->post(ApiClient::site(pasargadcdn_domain($params)) . '/ssl');
    });
}

function pasargadcdn_AdminServicesTabFields(array $params)
{
    try {
        $s = ApiClient::fromParams($params)->get(ApiClient::site(pasargadcdn_domain($params)));
    } catch (\Throwable $e) {
        return ['Pasargad CDN' => '<span style="color:#c00">' . htmlspecialchars($e->getMessage()) . '</span>'];
    }
    $h = 'htmlspecialchars';
    $u = $s['usage_month'] ?? [];
    return [
        'وضعیت CDN' => $h($s['status'] ?? '-'),
        'نیم‌سرورها' => $h(implode(' , ', $s['nameservers'] ?? []))
            . (!empty($s['ns_verified']) ? ' ✅' : ' ⏳ (فعلی: ' . $h(implode(', ', $s['ns_found'] ?? [])) . ')'),
        'SSL' => $h(($s['ssl']['status'] ?? '-') . ' ' . ($s['ssl']['expires_at'] ?? ''))
            . (!empty($s['ssl']['error']) ? '<br><small style="color:#c00">' . $h(mb_substr($s['ssl']['error'], -300)) . '</small>' : ''),
        'مصرف این ماه' => $h(($u['gb'] ?? 0) . ' GB / ' . (($s['plan']['bandwidth_limit_gb'] ?? 0) ?: '∞') . ' GB — '
            . number_format((int) ($u['requests'] ?? 0)) . ' درخواست'),
        'تعداد رکورد' => $h(count($s['records'] ?? []) . ' / ' . ($s['plan']['max_records'] ?? '-')),
    ];
}

// --------------------------------------------------------------- client area

function pasargadcdn_ClientAreaAllowedFunctions()
{
    return ['addRecord', 'updateRecord', 'deleteRecord', 'purgeCache', 'saveSettings', 'requestSsl', 'checkNs'];
}

function pasargadcdn_csrf_token(): string
{
    if (empty($_SESSION['pasargadcdn_csrf'])) {
        $_SESSION['pasargadcdn_csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['pasargadcdn_csrf'];
}

/** Guard for every state-changing client action. */
function pasargadcdn_client_action(array $params, callable $fn)
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST'
        || !hash_equals(pasargadcdn_csrf_token(), (string) ($_POST['pcdn_csrf'] ?? ''))) {
        return 'درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.';
    }
    if (($params['status'] ?? '') !== 'Active') {
        return 'این سرویس فعال نیست.';
    }
    return pasargadcdn_call(function () use ($params, $fn) {
        $fn(ApiClient::fromParams($params), ApiClient::site(pasargadcdn_domain($params)));
    });
}

function pasargadcdn_record_body(): array
{
    $prio = trim((string) ($_POST['priority'] ?? ''));
    return [
        'name' => trim((string) ($_POST['name'] ?? '@')),
        'type' => strtoupper(trim((string) ($_POST['type'] ?? ''))),
        'content' => trim((string) ($_POST['content'] ?? '')),
        'ttl' => max(60, (int) ($_POST['ttl'] ?? 300)),
        'priority' => $prio === '' ? null : (int) $prio,
        'proxied' => !empty($_POST['proxied']),
    ];
}

function pasargadcdn_addRecord(array $params)
{
    return pasargadcdn_client_action($params, function (ApiClient $api, string $site) {
        $api->post($site . '/records', pasargadcdn_record_body());
    });
}

function pasargadcdn_updateRecord(array $params)
{
    return pasargadcdn_client_action($params, function (ApiClient $api, string $site) {
        $api->put($site . '/records/' . (int) ($_POST['record_id'] ?? 0), pasargadcdn_record_body());
    });
}

function pasargadcdn_deleteRecord(array $params)
{
    return pasargadcdn_client_action($params, function (ApiClient $api, string $site) {
        $api->delete($site . '/records/' . (int) ($_POST['record_id'] ?? 0));
    });
}

function pasargadcdn_purgeCache(array $params)
{
    return pasargadcdn_client_action($params, function (ApiClient $api, string $site) {
        $urls = preg_split('/\s+/', trim((string) ($_POST['urls'] ?? '')), -1, PREG_SPLIT_NO_EMPTY);
        $api->post($site . '/purge', ['urls' => empty($_POST['purge_all']) ? $urls : []]);
    });
}

function pasargadcdn_saveSettings(array $params)
{
    return pasargadcdn_client_action($params, function (ApiClient $api, string $site) {
        $ips = preg_split('/[\s,]+/', trim((string) ($_POST['blocked_ips'] ?? '')), -1, PREG_SPLIT_NO_EMPTY);
        $api->patch($site . '/settings', [
            'cache_enabled' => !empty($_POST['cache_enabled']),
            'dev_mode' => !empty($_POST['dev_mode']),
            'force_https' => !empty($_POST['force_https']),
            'origin_protocol' => ($_POST['origin_protocol'] ?? 'http') === 'https' ? 'https' : 'http',
            'edge_cache_ttl' => max(0, (int) ($_POST['edge_cache_ttl'] ?? 86400)),
            'browser_cache_ttl' => max(0, (int) ($_POST['browser_cache_ttl'] ?? 0)),
            'blocked_ips' => $ips,
        ]);
    });
}

function pasargadcdn_requestSsl(array $params)
{
    return pasargadcdn_client_action($params, function (ApiClient $api, string $site) {
        $api->post($site . '/ssl');
    });
}

function pasargadcdn_checkNs(array $params)
{
    return pasargadcdn_client_action($params, function (ApiClient $api, string $site) {
        $r = $api->post($site . '/ns-check');
        if (empty($r['ok'])) {
            throw new ApiException('نیم‌سرورهای دامنه هنوز تغییر نکرده‌اند. تغییر NS ممکن است تا ۲۴ ساعت زمان ببرد.');
        }
    });
}

function pasargadcdn_ratio($hits, $requests): string
{
    return $requests > 0 ? round($hits * 100 / $requests) . '%' : '—';
}

function pasargadcdn_ClientArea(array $params)
{
    $vars = [
        'site' => null,
        'error' => null,
        'csrf' => pasargadcdn_csrf_token(),
        'serviceid' => (int) $params['serviceid'],
        'active' => ($params['status'] ?? '') === 'Active',
        'recordTypes' => ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA', 'NS'],
        'daily' => [],
        'view' => [],
    ];
    try {
        $api = ApiClient::fromParams($params);
        $site = ApiClient::site(pasargadcdn_domain($params));
        $s = $api->get($site);
        $usage = $api->get($site . '/usage?days=14');
        $month = $s['usage_month'] ?? [];
        $limit = (int) ($s['plan']['bandwidth_limit_gb'] ?? 0);
        // Pre-formatted here: newer Smarty in WHMCS 8.x blocks PHP functions as modifiers.
        $vars['site'] = $s;
        $vars['view'] = [
            'nsFound' => implode(', ', $s['ns_found'] ?? []),
            'blockedIps' => implode("\n", $s['settings']['blocked_ips'] ?? []),
            'recordCount' => count($s['records'] ?? []),
            'requests' => number_format((int) ($month['requests'] ?? 0)),
            'hitRatio' => pasargadcdn_ratio($month['cache_hits'] ?? 0, $month['requests'] ?? 0),
            'usagePercent' => $limit > 0 ? min(100, (int) round((float) ($month['gb'] ?? 0) * 100 / $limit)) : 0,
            'sslExpires' => substr((string) ($s['ssl']['expires_at'] ?? ''), 0, 10),
        ];
        foreach (array_reverse($usage['daily'] ?? []) as $d) {
            $vars['daily'][] = [
                'date' => $d['date'],
                'mb' => number_format($d['bytes'] / 1048576, 1),
                'requests' => number_format((int) $d['requests']),
                'hitRatio' => pasargadcdn_ratio($d['cache_hits'], $d['requests']),
            ];
        }
    } catch (\Throwable $e) {
        $vars['error'] = $e->getMessage();
    }
    return [
        'tabOverviewModuleOutputTemplate' => 'templates/clientarea.tpl',
        'templateVariables' => $vars,
    ];
}
