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
    // Order matters: WHMCS stores these as configoption1..14.
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
        'WAF' => ['Type' => 'yesno', 'Default' => 'on', 'Description' => 'فایروال برنامه وب (امضاهای OWASP)'],
        'DDoS protection' => ['Type' => 'yesno', 'Default' => 'on', 'Description' => 'چالش JS / کپچا در حملات'],
        'Load balancer' => ['Type' => 'yesno', 'Default' => 'on', 'Description' => 'توزیع بار بین چند سرور اصلی'],
        'Image optimization' => ['Type' => 'yesno', 'Default' => 'on'],
        'Custom SSL' => ['Type' => 'yesno', 'Default' => 'on', 'Description' => 'بارگذاری گواهی اختصاصی مشتری'],
        'DNSSEC' => ['Type' => 'yesno', 'Default' => 'on'],
        'Max page rules' => ['Type' => 'text', 'Size' => '8', 'Default' => '10'],
        'Max firewall rules' => ['Type' => 'text', 'Size' => '8', 'Default' => '20'],
        'Max rate-limit rules' => ['Type' => 'text', 'Size' => '8', 'Default' => '5'],
        'Max LB pools' => ['Type' => 'text', 'Size' => '8', 'Default' => '3'],
    ];
}

/**
 * Plan (SPEC §1) from the product config, overridable per service by
 * configurable options with these exact names:
 *   Bandwidth, DNS Records, Rate Limit, Page Rules, Firewall Rules,
 *   Rate Limit Rules, LB Pools            — quantity / text (number)
 *   SSL, WAF, DDoS, Load Balancer, Image Optimization, Custom SSL, DNSSEC
 *                                         — yes/no
 * Products saved before v2 have empty configoption5..14, i.e. every v2
 * feature off / 0 until the admin ticks them.
 */
function pasargadcdn_plan(array $params): array
{
    $opt = function (int $n) use ($params) {
        return $params['configoption' . $n] ?? '';
    };
    $plan = [
        'bandwidth_limit_gb' => max(0, (int) $opt(1)),
        'max_records' => max(1, (int) ($opt(2) ?: 100)),
        'ssl_allowed' => $opt(3) === 'on',
        'rate_limit_rps' => max(0, (int) $opt(4)),
        'features' => [
            'waf' => $opt(5) === 'on',
            'ddos' => $opt(6) === 'on',
            'load_balancer' => $opt(7) === 'on',
            'image_optimization' => $opt(8) === 'on',
            'custom_ssl' => $opt(9) === 'on',
            'dnssec' => $opt(10) === 'on',
            'max_page_rules' => max(0, (int) $opt(11)),
            'max_firewall_rules' => max(0, (int) $opt(12)),
            'max_ratelimit_rules' => max(0, (int) $opt(13)),
            'max_pools' => max(0, (int) $opt(14)),
        ],
    ];
    $co = $params['configoptions'] ?? [];
    $numbers = [
        'Bandwidth' => ['bandwidth_limit_gb', 0], 'DNS Records' => ['max_records', 1],
        'Rate Limit' => ['rate_limit_rps', 0], 'Page Rules' => ['features.max_page_rules', 0],
        'Firewall Rules' => ['features.max_firewall_rules', 0],
        'Rate Limit Rules' => ['features.max_ratelimit_rules', 0], 'LB Pools' => ['features.max_pools', 0],
    ];
    $flags = [
        'SSL' => 'ssl_allowed', 'WAF' => 'features.waf', 'DDoS' => 'features.ddos',
        'Load Balancer' => 'features.load_balancer', 'Image Optimization' => 'features.image_optimization',
        'Custom SSL' => 'features.custom_ssl', 'DNSSEC' => 'features.dnssec',
    ];
    $set = function (string $key, $value) use (&$plan) {
        $k = explode('.', $key);
        if (count($k) === 2) {
            $plan[$k[0]][$k[1]] = $value;
        } else {
            $plan[$k[0]] = $value;
        }
    };
    foreach ($numbers as $name => [$key, $min]) {
        if (isset($co[$name]) && $co[$name] !== '') {
            $set($key, max($min, (int) $co[$name]));
        }
    }
    foreach ($flags as $name => $key) {
        if (isset($co[$name])) {
            $set($key, (bool) $co[$name]);
        }
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
        'WAF / DDoS' => $h('WAF: ' . ($s['config']['waf']['mode'] ?? '-') . ' — DDoS: ' . ($s['config']['ddos']['mode'] ?? '-')),
        'DNSSEC' => $h(pasargadcdn_admin_dnssec($params)),
        'امکانات پلن' => $h(pasargadcdn_features_text($s['plan']['features'] ?? [])),
    ];
}

function pasargadcdn_admin_dnssec(array $params): string
{
    try {
        $d = ApiClient::fromParams($params)->get(ApiClient::site(pasargadcdn_domain($params)) . '/dnssec');
    } catch (\Throwable $e) {
        return '-';
    }
    return empty($d['enabled']) ? 'خاموش' : 'روشن — DS: ' . implode(' | ', $d['ds'] ?? []);
}

function pasargadcdn_features_text(array $f): string
{
    if (!$f) {
        return '-';
    }
    $on = [];
    foreach (['waf' => 'WAF', 'ddos' => 'DDoS', 'load_balancer' => 'LB', 'image_optimization' => 'Image',
                 'custom_ssl' => 'Custom SSL', 'dnssec' => 'DNSSEC'] as $k => $label) {
        if (!empty($f[$k])) {
            $on[] = $label;
        }
    }
    return (implode(', ', $on) ?: '—') . sprintf(' · page rules %d · firewall %d · rate-limit %d · pools %d',
        $f['max_page_rules'] ?? 0, $f['max_firewall_rules'] ?? 0, $f['max_ratelimit_rules'] ?? 0, $f['max_pools'] ?? 0);
}

// --------------------------------------------------------------- client area
//
// The client area is a small vanilla-JS app (assets/app.js) that talks to
// api.php, a JSON proxy restricted to this service's own domain.

function pasargadcdn_csrf_token(): string
{
    if (empty($_SESSION['pasargadcdn_csrf'])) {
        $_SESSION['pasargadcdn_csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['pasargadcdn_csrf'];
}

/** Web path of this module dir, e.g. "/billing/modules/servers/pasargadcdn". */
function pasargadcdn_module_url(): string
{
    // Client area pages (clientarea.php, index.php?rm=...) live in the WHMCS root.
    $root = str_replace('\\', '/', dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php')));
    return rtrim($root, '/.') . '/modules/servers/pasargadcdn';
}

function pasargadcdn_ClientArea(array $params)
{
    $active = ($params['status'] ?? '') === 'Active';
    $boot = [
        'serviceId' => (int) $params['serviceid'],
        'domain' => pasargadcdn_domain($params),
        'active' => $active,
        'site' => null,
        'error' => null,
    ];
    try {
        $boot['site'] = ApiClient::fromParams($params)->get(ApiClient::site($boot['domain']));
    } catch (\Throwable $e) {
        $boot['error'] = $e->getMessage();
    }
    $base = pasargadcdn_module_url();
    $ver = function (string $f) {
        return (string) @filemtime(__DIR__ . '/' . $f);
    };
    return [
        'tabOverviewModuleOutputTemplate' => 'templates/clientarea.tpl',
        'templateVariables' => [
            'pcdnCsrf' => pasargadcdn_csrf_token(),
            'pcdnApiUrl' => $base . '/api.php',
            'pcdnCssUrl' => $base . '/assets/app.css?v=' . $ver('assets/app.css'),
            'pcdnJsUrl' => $base . '/assets/app.js?v=' . $ver('assets/app.js'),
            // Loaded in this order (all deferred); app.js boots last.
            'pcdnScripts' => array_map(function ($f) use ($base, $ver) {
                return $base . '/assets/' . $f . '?v=' . $ver('assets/' . $f);
            }, ['ui.js', 'pages.js', 'reports.js', 'tutorials.js', 'app.js']),
            // Safe inside <script type="application/json">: no raw < > & ' "
            'pcdnBoot' => json_encode($boot, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
                | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_PARTIAL_OUTPUT_ON_ERROR),
        ],
    ];
}
