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

require_once __DIR__ . '/lib/I18n.php';
require_once __DIR__ . '/lib/ApiClient.php';
require_once __DIR__ . '/lib/Reseller.php';
require_once __DIR__ . '/lib/TeamAccess.php';

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use PasargadCdn\I18n;
use PasargadCdn\Reseller;
use PasargadCdn\TeamAccess;
use WHMCS\Database\Capsule;

/** SPEC §10.5 — is this WHMCS client an enabled reseller? Exposed for the client-app bootstrap. */
function pasargadcdn_is_reseller(int $userid): bool
{
    return Reseller::isReseller($userid);
}

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
    // Order matters: WHMCS stores these as configoption1..19.
    return [
        'Bandwidth (GB)' => [
            'Type' => 'text', 'Size' => '8', 'Default' => '100',
            'Description' => 'سقف ترافیک ماهانه روی CDN (گیگابایت) — 0 یعنی نامحدود. با صورتحساب ترافیک اضافه، ترافیک پلن همان Overage Soft Limit تب Other است و این عدد سقف قطع سرویس است',
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
        // Tunnel mode (SPEC §7): Xray/V2Ray/sing-box over WebSocket, HTTPUpgrade, gRPC, XHTTP, h2.
        'Tunnel (VPN over CDN)' => ['Type' => 'yesno', 'Default' => '',
            'Description' => 'حالت تونل: عبور Xray / V2Ray (WebSocket، gRPC، XHTTP، HTTPUpgrade، h2) از CDN'],
        'Max tunnel paths' => ['Type' => 'text', 'Size' => '8', 'Default' => '10', 'Description' => 'حداکثر مسیر تونل (۰ تا ۵۰)'],
        'Max tunnel connections' => ['Type' => 'text', 'Size' => '8', 'Default' => '0',
            'Description' => 'اتصال همزمان تونل هر سایت روی هر نود — 0 یعنی نامحدود'],
        'Tunnel max Mbps per connection' => ['Type' => 'text', 'Size' => '8', 'Default' => '0',
            'Description' => 'سقف سرعت هر اتصال تونل (مگابیت بر ثانیه) — 0 یعنی بدون سقف. فعلاً نودها آن را روی جریان‌های تونل اعمال نمی‌کنند'],
        'Edge group' => ['Type' => 'dropdown', 'Options' => 'general,tunnel', 'Default' => 'general',
            'Description' => 'پاسخ DNS سایت‌های این محصول از کدام گروه نودها باشد (general = نودهای وب، tunnel = نودهای مخصوص تونل)'],
    ];
}

/**
 * Plan (SPEC §1) from the product config, overridable per service by
 * configurable options with these exact names:
 *   Bandwidth, DNS Records, Rate Limit, Page Rules, Firewall Rules,
 *   Rate Limit Rules, LB Pools            — quantity / text (number)
 *   SSL, WAF, DDoS, Load Balancer, Image Optimization, Custom SSL, DNSSEC
 *                                         — yes/no
 *   Tunnel Paths, Tunnel Connections, Tunnel Mbps — number; Tunnel — yes/no;
 *   Edge Group — "general" | "tunnel"
 * Products saved before v2 have empty configoption5..14, i.e. every v2
 * feature off / 0 until the admin ticks them; likewise products saved before
 * tunnel mode (configoption15..19 empty) get tunnel off, group "general".
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
            'tunnel' => $opt(15) === 'on',
            'max_tunnel_paths' => (int) $opt(16),
            'max_tunnel_connections' => (int) $opt(17),
            'tunnel_max_mbps' => (int) $opt(18),
            'edge_group' => $opt(19) === 'tunnel' ? 'tunnel' : 'general',
        ],
    ];
    $co = $params['configoptions'] ?? [];
    $numbers = [
        'Bandwidth' => ['bandwidth_limit_gb', 0], 'DNS Records' => ['max_records', 1],
        'Rate Limit' => ['rate_limit_rps', 0], 'Page Rules' => ['features.max_page_rules', 0],
        'Firewall Rules' => ['features.max_firewall_rules', 0],
        'Rate Limit Rules' => ['features.max_ratelimit_rules', 0], 'LB Pools' => ['features.max_pools', 0],
        'Tunnel Paths' => ['features.max_tunnel_paths', 0], 'Tunnel Connections' => ['features.max_tunnel_connections', 0],
        'Tunnel Mbps' => ['features.tunnel_max_mbps', 0],
    ];
    $flags = [
        'SSL' => 'ssl_allowed', 'WAF' => 'features.waf', 'DDoS' => 'features.ddos',
        'Load Balancer' => 'features.load_balancer', 'Image Optimization' => 'features.image_optimization',
        'Custom SSL' => 'features.custom_ssl', 'DNSSEC' => 'features.dnssec', 'Tunnel' => 'features.tunnel',
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
    if (isset($co['Edge Group']) && in_array($co['Edge Group'], ['general', 'tunnel'], true)) {
        $plan['features']['edge_group'] = $co['Edge Group'];
    }
    // Wave 8 (SPEC §16.4) TCP/UDP proxy: configurable options only — the keys are sent ONLY when the
    // product has the option, so an older controller (Features extra="forbid") never receives them;
    // without the options the controller defaults apply (l4_proxy off, 0 apps).
    if (isset($co['L4 Proxy'])) {
        $plan['features']['l4_proxy'] = (bool) $co['L4 Proxy'];
    }
    if (isset($co['L4 Apps']) && $co['L4 Apps'] !== '') {
        $plan['features']['max_l4_apps'] = min(100, max(0, (int) $co['L4 Apps']));
    }
    // Controller ranges (SPEC §7.1) — out-of-range values would make Create/ChangePackage fail.
    $f = &$plan['features'];
    $f['max_tunnel_paths'] = min(50, max(0, $f['max_tunnel_paths']));
    $f['max_tunnel_connections'] = min(1000000, max(0, $f['max_tunnel_connections']));
    $f['tunnel_max_mbps'] = min(100000, max(0, $f['tunnel_max_mbps']));
    unset($f);
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
            'plan' => pasargadcdn_cap_plan($params),
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
            // Re-run of Create on an existing site of the same service is fine
            // (e.g. a retry after a timeout): bring its plan up to date.
            $api = ApiClient::fromParams($params);
            $site = $api->get(ApiClient::site($domain));
            if ((string) ($site['external_id'] ?? '') !== (string) $params['serviceid']) {
                throw new ApiException('دامنه ' . $domain . ' از قبل روی CDN و برای سرویس دیگری ('
                    . (($site['external_id'] ?? '') !== '' ? '#' . $site['external_id'] : 'بدون شناسه')
                    . ') ثبت شده است. از بخش «همگام‌سازی» ماژول مدیریت CDN آن را بررسی کنید.', 409);
            }
            $api->patch(ApiClient::site($domain) . '/plan', pasargadcdn_cap_plan($params));
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
        $api = ApiClient::fromParams($params);
        $site = ApiClient::site(pasargadcdn_domain($params));
        $api->post($site . '/unsuspend');
        // Prepaid: re-assert plan + this month's top-ups (a month may have rolled over while suspended).
        $row = pasargadcdn_product_row((int) ($params['pid'] ?? 0));
        if ($row && pasargadcdn_prepaid($row, (array) ($params['configoptions'] ?? [])) !== null) {
            $api->patch($site . '/plan', pasargadcdn_cap_plan($params));
        }
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
            pasargadcdn_cap_plan($params)
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
    // With overage billing the product's soft limit (included traffic) is the
    // limit WHMCS shows and bills against; the controller limit is the hard cap.
    $included = [];
    $packageOf = [];
    try {
        foreach (Capsule::table('tblproducts')->where('servertype', 'pasargadcdn')
                     ->get(['id', 'overagesenabled', 'overagesbwlimit', 'overagesbwprice']) as $p) {
            $o = pasargadcdn_overage((array) $p);
            if ($o !== null) {
                $included[(int) $p->id] = (int) round($o['included_gb'] * 1024);
            }
        }
        if ($included) {
            $packageOf = Capsule::table('tblhosting')->where('server', $params['serverid'])
                ->whereIn('packageid', array_keys($included))->pluck('packageid', 'id')->all();
        }
    } catch (\Throwable $e) {
        $included = [];
    }
    foreach ($data['sites'] ?? [] as $site) {
        $serviceId = (int) ($site['external_id'] ?? 0);
        if ($serviceId <= 0) {
            continue;
        }
        $limitMb = (int) ($site['bandwidth_limit_gb'] ?? 0) * 1024;
        if (isset($packageOf[$serviceId], $included[(int) $packageOf[$serviceId]])) {
            // included traffic + this month's «بسته‌ی ترافیک افزوده» add-ons (SPEC §15.7) are not overage
            $limitMb = $included[(int) $packageOf[$serviceId]] + pasargadcdn_addon_gb($serviceId) * 1024;
        }
        Capsule::table('tblhosting')
            ->where('id', $serviceId)
            ->where('server', $params['serverid'])
            ->update([
                'bwusage' => (int) round(($site['bytes'] ?? 0) / 1048576),
                'bwlimit' => $limitMb,
                'lastupdate' => date('Y-m-d H:i:s'),
            ]);
    }
    return 'success';
}

/**
 * Overage settings of a product row (overagesenabled "1[,diskunit,bwunit]",
 * overagesbwlimit and overagesbwprice in bwunit, MB by default).
 * Returns null when bandwidth overage billing is off.
 *
 * @return array{included_gb: float, price_per_gb: float}|null
 */
function pasargadcdn_overage(array $p): ?array
{
    $parts = explode(',', (string) ($p['overagesenabled'] ?? ''));
    if (trim($parts[0]) === '' || trim($parts[0]) === '0') {
        return null;
    }
    $limit = (float) ($p['overagesbwlimit'] ?? 0);
    if ($limit <= 0) {
        return null;
    }
    $unit = strtoupper(trim($parts[2] ?? 'MB'));
    $toGb = ['MB' => 1 / 1024, 'GB' => 1.0, 'TB' => 1024.0][$unit] ?? 1 / 1024;
    return [
        'included_gb' => round($limit * $toGb, 3),
        'price_per_gb' => round((float) ($p['overagesbwprice'] ?? 0) / $toGb, 4),
    ];
}

// --------------------------------------------------------------- prepaid (wallet) billing
//
// Billing mode lives in the admin addon's settings (tbladdonmodules, module
// pasargadcdn_admin). In the default «prepaid» mode the controller cap of a
// service is plan GB + the traffic blocks bought (and paid from the client's
// credit balance) this month; the addon's cron/hook engine buys the blocks.

/** Settings of the admin addon (memoised per request). Empty when the addon is not active. */
function pasargadcdn_addon_settings(bool $reset = false): array
{
    static $memo = null;
    if ($reset) {
        $memo = null;
        pasargadcdn_gb_prices(true);
        return [];
    }
    if ($memo === null) {
        $memo = [];
        try {
            foreach (Capsule::table('tbladdonmodules')->where('module', 'pasargadcdn_admin')->get(['setting', 'value']) as $r) {
                $memo[(string) $r->setting] = (string) $r->value;
            }
        } catch (\Throwable $e) {
            $memo = [];
        }
    }
    return $memo;
}

/** prepaid | overage | cut | none (addon not active). */
function pasargadcdn_billing_mode(): string
{
    $s = pasargadcdn_addon_settings();
    if (!$s) {
        return 'none';
    }
    $m = $s['billing'] ?? 'prepaid';
    return in_array($m, ['prepaid', 'overage', 'cut'], true) ? $m : 'prepaid';
}

/** Current billing month of the controller (UTC). */
function pasargadcdn_month(): string
{
    return gmdate('Y-m');
}

/** Per-product prepaid price per GB set by the wizard (pid => price), memoised per request. */
function pasargadcdn_gb_prices(bool $reset = false): array
{
    static $memo = null;
    if ($reset) {
        $memo = null;
        return [];
    }
    if ($memo === null) {
        $memo = [];
        try {
            $v = Capsule::table('mod_pasargadcdn_settings')->where('k', 'gb_prices')->value('v');
            $map = $v ? json_decode((string) $v, true) : [];
            $memo = is_array($map) ? $map : [];
        } catch (\Throwable $e) {
            $memo = [];
        }
    }
    return $memo;
}

/**
 * Configurable option values of services, keyed like $params['configoptions']:
 * [service id => [option name => value]]. The name is the part before «|»
 * (WHMCS's friendly-name syntax); dropdown/radio values are the chosen
 * sub-option's name (part before «|»), yes/no and quantity values are the qty.
 * One query for any number of services; $ids may be a subquery closure.
 *
 * @param int[]|\Closure $ids
 */
function pasargadcdn_config_options($ids): array
{
    if (is_array($ids)) {
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids))));
        if (!$ids) {
            return [];
        }
    }
    $out = [];
    try {
        $rows = Capsule::table('tblhostingconfigoptions as hco')
            ->join('tblproductconfigoptions as pco', 'pco.id', '=', 'hco.configid')
            ->leftJoin('tblproductconfigoptionssub as pcos', 'pcos.id', '=', 'hco.optionid')
            ->whereIn('hco.relid', $ids)
            ->get(['hco.relid', 'hco.qty', 'pco.optionname', 'pco.optiontype', 'pcos.optionname as subname']);
        foreach ($rows as $r) {
            $name = trim(explode('|', (string) $r->optionname)[0]);
            if ($name === '') {
                continue;
            }
            $type = (int) $r->optiontype;
            // 1 dropdown, 2 radio → chosen sub-option; 3 yes/no, 4 quantity → qty
            $value = in_array($type, [3, 4], true) || $r->subname === null
                ? (string) (int) $r->qty
                : trim(explode('|', (string) $r->subname)[0]);
            $out[(int) $r->relid][$name] = $value;
        }
    } catch (\Throwable $e) {
        return [];
    }
    return $out;
}

/**
 * Prepaid settings of a product row (needs id, configoption1, overagesenabled,
 * overagesbwlimit, overagesbwprice) for a service with the given configurable
 * option values, or null when it is not prepaid: mode is not «prepaid», the
 * effective plan is unlimited, or WHMCS overage billing is on for the product
 * (billed at month end instead — never both). plan_gb is the same effective
 * bandwidth pasargadcdn_plan() sends (a «Bandwidth» configurable option wins).
 *
 * @return array{plan_gb:int, block_gb:int, price_per_gb:?float, max_blocks:int, warn:bool}|null
 */
function pasargadcdn_prepaid(array $p, array $configoptions = []): ?array
{
    if (pasargadcdn_billing_mode() !== 'prepaid' || pasargadcdn_overage($p) !== null) {
        return null;
    }
    $planGb = pasargadcdn_plan(['configoption1' => $p['configoption1'] ?? '', 'configoptions' => $configoptions])['bandwidth_limit_gb'];
    if ($planGb <= 0) {
        return null;
    }
    $s = pasargadcdn_addon_settings();
    $block = (int) ($s['block_gb'] ?? 10);
    $max = (int) ($s['max_blocks'] ?? 20);
    $price = null;
    $override = trim(str_replace(',', '', (string) ($s['gb_price'] ?? '')));
    if ($override !== '' && is_numeric($override) && (float) $override > 0) {
        $price = (float) $override;
    } else {
        $map = pasargadcdn_gb_prices();
        $pid = (string) (int) ($p['id'] ?? 0);
        if (isset($map[$pid]) && (float) $map[$pid] > 0) {
            $price = (float) $map[$pid];
        }
    }
    return [
        'plan_gb' => $planGb,
        'block_gb' => $block > 0 ? min($block, 100000) : 10,
        'price_per_gb' => $price,
        'max_blocks' => $max >= 0 ? $max : 20,
        'warn' => !in_array(strtolower((string) ($s['warn_email'] ?? 'on')), ['', 'off', '0', 'no'], true),
    ];
}

/** GB of paid traffic top-ups of a service for $month (default: this month). */
function pasargadcdn_topup_gb(int $serviceId, ?string $month = null): int
{
    try {
        return (int) Capsule::table('mod_pasargadcdn_topups')->where('service_id', $serviceId)
            ->where('month', $month ?: pasargadcdn_month())->where('status', 'paid')->sum('gb');
    } catch (\Throwable $e) {
        return 0;
    }
}

/**
 * GB of «بسته‌ی ترافیک افزوده» add-ons paid for a service in $month (SPEC §15.7). They are stored
 * in mod_pasargadcdn_topups like prepaid purchases but with blocks = 0, so they raise the cap
 * without counting toward the monthly auto-purchase limit.
 */
function pasargadcdn_addon_gb(int $serviceId, ?string $month = null): int
{
    try {
        return (int) Capsule::table('mod_pasargadcdn_topups')->where('service_id', $serviceId)
            ->where('month', $month ?: pasargadcdn_month())->where('status', 'paid')->where('blocks', 0)->sum('gb');
    } catch (\Throwable $e) {
        return 0;
    }
}

/** Product row for the prepaid decision of a service (by pid), or []. */
function pasargadcdn_product_row(int $pid): array
{
    if ($pid <= 0) {
        return [];
    }
    try {
        $p = Capsule::table('tblproducts')->where('id', $pid)
            ->first(['id', 'configoption1', 'overagesenabled', 'overagesbwlimit', 'overagesbwprice', 'tax']);
        return $p ? (array) $p : [];
    } catch (\Throwable $e) {
        return [];
    }
}

/**
 * Wallet facts for the client app (prepaid products only, else null): plan and
 * bought traffic, block size/price and credit in the client's currency, and
 * how much more traffic the current credit buys.
 */
function pasargadcdn_wallet(array $params): ?array
{
    try {
        $row = pasargadcdn_product_row((int) ($params['pid'] ?? $params['packageid'] ?? 0));
        $sid = (int) ($params['serviceid'] ?? 0);
        $co = isset($params['configoptions']) && is_array($params['configoptions']) ? $params['configoptions']
            : (pasargadcdn_config_options([$sid])[$sid] ?? []);
        $pp = $row ? pasargadcdn_prepaid($row, $co) : null;
        if ($pp === null) {
            return null;
        }
        $client = Capsule::table('tblclients')->where('id', (int) ($params['userid'] ?? 0))->first(['credit', 'currency']);
        $cur = $client ? Capsule::table('tblcurrencies')->where('id', (int) $client->currency)->first(['code', 'suffix', 'prefix', 'rate']) : null;
        $rate = $cur && (float) $cur->rate > 0 ? (float) $cur->rate : 1.0;
        $credit = $client ? round((float) $client->credit, 2) : 0.0;
        $bought = pasargadcdn_topup_gb($sid);
        $blocks = 0;
        try {
            $blocks = (int) Capsule::table('mod_pasargadcdn_topups')->where('service_id', $sid)
                ->where('month', pasargadcdn_month())->whereIn('status', ['paid', 'pending'])->sum('blocks');
        } catch (\Throwable $e) {
            $blocks = 0;
        }
        $blockPrice = $pp['price_per_gb'] !== null ? round($pp['price_per_gb'] * $pp['block_gb'] * $rate, 2) : null;
        $left = max(0, $pp['max_blocks'] - $blocks);
        $affordable = $blockPrice && $blockPrice > 0 ? min($left, (int) floor(($credit + 0.00001) / $blockPrice)) : 0;
        return [
            'plan_gb' => $pp['plan_gb'],
            'bought_gb' => $bought,
            // §15.7: the part of bought_gb that came from «بسته‌ی ترافیک افزوده» add-ons (not wallet blocks)
            'addon_gb' => pasargadcdn_addon_gb($sid),
            'cap_gb' => $pp['plan_gb'] + $bought,
            'block_gb' => $pp['block_gb'],
            'block_price' => $blockPrice,
            'price_per_gb' => $pp['price_per_gb'] !== null ? round($pp['price_per_gb'] * $rate, 2) : null,
            'credit' => $credit,
            'currency' => $cur ? (trim((string) $cur->suffix) !== '' ? trim((string) $cur->suffix) : (string) $cur->code) : '',
            'more_gb' => $affordable * $pp['block_gb'],
            'needed' => $blockPrice !== null ? max(0.0, round($blockPrice - $credit, 2)) : null,
            'limit_reached' => $left === 0,
        ];
    } catch (\Throwable $e) {
        return null;
    }
}

/** Persian (Jalali) «MMMM yyyy» label for a YYYY-MM month, or the month itself. */
function pasargadcdn_month_label(string $month): string
{
    if (class_exists('\\IntlDateFormatter')) {
        $f = new \IntlDateFormatter('fa_IR@calendar=persian', \IntlDateFormatter::NONE, \IntlDateFormatter::NONE,
            'UTC', \IntlDateFormatter::TRADITIONAL, 'MMMM yyyy');
        $s = $f->format(strtotime($month . '-15 12:00:00 UTC'));
        if (is_string($s) && $s !== '') {
            return $s;
        }
    }
    return $month;
}

/**
 * §10.4 «صورت‌حساب و مصرف» statement facts for the client app (read-only): this
 * service's traffic top-ups over the current and previous months (date, GB,
 * amount, WHMCS invoice id, status), grouped by month with paid subtotals, plus
 * the plan's included traffic for the running summary. null on any error.
 *
 * Pure DB read of mod_pasargadcdn_topups — never touches billing, caps or credit.
 */
function pasargadcdn_statement(array $params): ?array
{
    try {
        $sid = (int) ($params['serviceid'] ?? 0);
        if ($sid <= 0) {
            return null;
        }
        $row = pasargadcdn_product_row((int) ($params['pid'] ?? $params['packageid'] ?? 0));
        $co = isset($params['configoptions']) && is_array($params['configoptions']) ? $params['configoptions']
            : (pasargadcdn_config_options([$sid])[$sid] ?? []);
        $pp = $row ? pasargadcdn_prepaid($row, $co) : null;
        $o = $row ? pasargadcdn_overage($row) : null;

        $client = Capsule::table('tblclients')->where('id', (int) ($params['userid'] ?? 0))->first(['currency']);
        $cur = $client ? Capsule::table('tblcurrencies')->where('id', (int) $client->currency)->first(['code', 'suffix']) : null;
        $unit = $cur ? (trim((string) $cur->suffix) !== '' ? trim((string) $cur->suffix) : (string) $cur->code) : '';

        // Included traffic this month: prepaid plan GB, else overage included GB, else null (controller limit).
        $planGb = $pp !== null ? (float) $pp['plan_gb'] : ($o !== null ? (float) $o['included_gb'] : null);

        // The three most recent months, current first.
        $anchor = strtotime(pasargadcdn_month() . '-01 12:00:00 UTC');
        $months = [];
        for ($i = 0; $i < 3; $i++) {
            $months[] = gmdate('Y-m', strtotime('-' . $i . ' month', $anchor));
        }

        $topups = [];
        if (Capsule::schema()->hasTable('mod_pasargadcdn_topups')) {
            $topups = Capsule::table('mod_pasargadcdn_topups')->where('service_id', $sid)
                ->whereIn('month', $months)->orderBy('created_at', 'desc')->orderBy('id', 'desc')
                ->get(['month', 'gb', 'amount', 'blocks', 'status', 'invoice_id', 'created_at'])->all();
        }

        $byMonth = [];
        foreach ($months as $m) {
            $byMonth[$m] = ['month' => $m, 'label' => pasargadcdn_month_label($m), 'bought_gb' => 0, 'spent' => 0.0, 'topups' => []];
        }
        $totalGb = 0;
        $totalSpent = 0.0;
        foreach ($topups as $t) {
            $m = (string) $t->month;
            if (!isset($byMonth[$m])) {
                continue;
            }
            $byMonth[$m]['topups'][] = [
                'ts' => str_replace(' ', 'T', (string) $t->created_at),
                'gb' => (int) $t->gb,
                'amount' => round((float) $t->amount, 2),
                'invoice_id' => $t->invoice_id ? (int) $t->invoice_id : 0,
                'status' => (string) $t->status,
                // §15.7 add-on traffic rows have no wallet blocks
                'kind' => (int) $t->blocks === 0 ? 'addon' : 'auto',
            ];
            if ($t->status === 'paid') {
                $byMonth[$m]['bought_gb'] += (int) $t->gb;
                $byMonth[$m]['spent'] += (float) $t->amount;
                $totalGb += (int) $t->gb;
                $totalSpent += (float) $t->amount;
            }
        }
        foreach ($byMonth as &$mm) {
            $mm['spent'] = round($mm['spent'], 2);
        }
        unset($mm);

        return [
            'currency' => $unit,
            'plan_gb' => $planGb,
            'prepaid' => $pp !== null,
            'current_month' => pasargadcdn_month(),
            'months' => array_values($byMonth),
        'addon_gb' => pasargadcdn_addon_gb($sid),
            'total_bought_gb' => $totalGb,
            'total_spent' => round($totalSpent, 2),
            'invoice_url' => 'viewinvoice.php?id=',
        ];
    } catch (\Throwable $e) {
        return null;
    }
}

/**
 * §10.2 smart-usage banner facts for the client app: the deduped forecast /
 * upgrade markers the prepaid engine set for THIS service in the current month
 * (mod_pasargadcdn_notices). null when there is nothing to show.
 */
function pasargadcdn_suggest(array $params): ?array
{
    $sid = (int) ($params['serviceid'] ?? 0);
    if ($sid <= 0) {
        return null;
    }
    try {
        if (!Capsule::schema()->hasTable('mod_pasargadcdn_notices')) {
            return null;
        }
        $month = pasargadcdn_month();
        $kinds = Capsule::table('mod_pasargadcdn_notices')->where('service_id', $sid)->where('month', $month)
            ->whereIn('kind', ['forecast', 'upgrade'])->pluck('kind')->all();
    } catch (\Throwable $e) {
        return null;
    }
    $forecast = in_array('forecast', $kinds, true);
    $upgrade = in_array('upgrade', $kinds, true);
    if (!$forecast && !$upgrade) {
        return null;
    }
    return ['month' => $month, 'forecast' => $forecast, 'upgrade' => $upgrade];
}

/**
 * Plan to send to the controller: pasargadcdn_plan() plus this month's paid
 * top-ups for prepaid products (so Create/ChangePackage/Unsuspend never
 * undo traffic the customer already paid for).
 */
function pasargadcdn_cap_plan(array $params): array
{
    $plan = pasargadcdn_plan($params);
    if ($plan['bandwidth_limit_gb'] > 0 && !empty($params['serviceid'])) {
        $row = pasargadcdn_product_row((int) ($params['pid'] ?? $params['packageid'] ?? 0));
        if ($row && pasargadcdn_prepaid($row, (array) ($params['configoptions'] ?? [])) !== null) {
            $plan['bandwidth_limit_gb'] += pasargadcdn_topup_gb((int) $params['serviceid']);
        } else {
            // §15.7 add-on traffic also raises the cap of non-prepaid services for the month it was paid in
            $plan['bandwidth_limit_gb'] += pasargadcdn_addon_gb((int) $params['serviceid']);
        }
    }
    return $plan;
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
        return ['Pasargad CDN' => '<span style="color:#c00">' . pasargadcdn_e($e->getMessage()) . '</span>'];
    }
    $h = 'pasargadcdn_e';
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
        'تونل / VPN' => $h(pasargadcdn_tunnel_text($s)),
    ];
}

/** One-line tunnel state of a site for the admin service tab. */
function pasargadcdn_tunnel_text(array $s): string
{
    if (empty($s['plan']['features']['tunnel'])) {
        return 'در پلن فعال نیست';
    }
    $t = (array) ($s['config']['tunnel'] ?? []);
    $protos = array_count_values(array_map(function ($p) {
        return (string) ($p['protocol'] ?? '?');
    }, array_filter((array) ($t['paths'] ?? []), 'is_array')));
    $list = [];
    foreach ($protos as $k => $n) {
        $list[] = $k . '×' . $n;
    }
    return (!empty($t['enabled']) ? 'روشن' : 'خاموش') . ' — ' . count((array) ($t['paths'] ?? [])) . ' مسیر'
        . ($list ? ' (' . implode(', ', $list) . ')' : '');
}

function pasargadcdn_e($v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
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
    $txt = (implode(', ', $on) ?: '—') . sprintf(' · page rules %d · firewall %d · rate-limit %d · pools %d',
        $f['max_page_rules'] ?? 0, $f['max_firewall_rules'] ?? 0, $f['max_ratelimit_rules'] ?? 0, $f['max_pools'] ?? 0);
    if (!empty($f['tunnel'])) {
        $txt .= sprintf(' · tunnel: %d paths, %s conns, %s Mbps', $f['max_tunnel_paths'] ?? 0,
            !empty($f['max_tunnel_connections']) ? (string) $f['max_tunnel_connections'] : '∞',
            !empty($f['tunnel_max_mbps']) ? (string) $f['tunnel_max_mbps'] : '∞');
    }
    if (!empty($f['l4_proxy'])) {
        $txt .= sprintf(' · TCP/UDP: %d apps', $f['max_l4_apps'] ?? 0);
    }
    if (($f['edge_group'] ?? 'general') !== 'general') {
        $txt .= ' · edge group: ' . $f['edge_group'];
    }
    return $txt;
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
    // SPEC §16.10: Persian or English app — the viewer's in-app choice, else the WHMCS client
    // language. Controller-connection errors in the boot blob follow the same language.
    $lang = pasargadcdn_lang($params);
    $prevLang = I18n::$current;
    I18n::$current = $lang;
    $boot = [
        'serviceId' => (int) $params['serviceid'],
        'lang' => $lang,
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
    $boot['billing'] = pasargadcdn_billing($params);
    $boot['wallet'] = pasargadcdn_wallet($params);
    $boot['suggest'] = pasargadcdn_suggest($params);
    $boot['statement'] = pasargadcdn_statement($params);
    // §14.3.7 team access: read-only app for a WHMCS user without the manage-products permission
    // (api.php enforces the same decision server side for every write).
    $boot['readonly'] = TeamAccess::readonly();
    // §10.5 reseller: show the «نمایندگی» panel only to reseller accounts. The SPA fetches
    // the sub-site list + rolled-up report on demand through api.php (reseller ops).
    $uid = (int) ($params['userid'] ?? 0);
    if (Reseller::isReseller($uid)) {
        $cfg = Reseller::config($uid);
        $boot['reseller'] = [
            'enabled' => true,
            'max_sites' => $cfg['max_sites'],
            'count' => Reseller::siteCount($uid),
        ];
    }
    $base = pasargadcdn_module_url();
    $assets = pasargadcdn_assets($base, $lang);
    $noJs = I18n::tr('برای مدیریت CDN، جاوااسکریپت مرورگر را فعال کنید.');
    $loading = I18n::tr('در حال بارگذاری پنل CDN…');
    I18n::$current = $prevLang;
    return [
        'tabOverviewModuleOutputTemplate' => 'templates/clientarea.tpl',
        'templateVariables' => [
            'pcdnLang' => $lang,
            'pcdnDir' => $lang === 'en' ? 'ltr' : 'rtl',
            'pcdnNoJs' => $noJs,
            'pcdnLoading' => $loading,
            'pcdnCsrf' => pasargadcdn_csrf_token(),
            'pcdnApiUrl' => $base . '/api.php',
            'pcdnCssUrl' => $assets['css'],
            'pcdnJsUrl' => end($assets['scripts']),
            // Loaded in this order (all deferred); app.js boots last.
            'pcdnScripts' => $assets['scripts'],
            'pcdnBoot' => pasargadcdn_boot_json($boot),
        ],
    ];
}

/**
 * Language of the client app (SPEC §16.10): 'fa' | 'en' — the viewer's in-app choice (cookie),
 * else the WHMCS session / client / default language ('english' → en, anything else → fa).
 */
function pasargadcdn_lang(array $params = []): string
{
    return I18n::lang((array) ($params['clientsdetails'] ?? []));
}

/**
 * Versioned URLs of the client app under $base (the module's web path). i18n.js loads first;
 * the English dictionary (i18n-en.js, before it) only for an English page — the admin addon's
 * embed calls this without $lang and stays Persian.
 */
function pasargadcdn_assets(string $base, string $lang = 'fa'): array
{
    $ver = function (string $f) {
        return (string) @filemtime(__DIR__ . '/' . $f);
    };
    return [
        'css' => $base . '/assets/app.css?v=' . $ver('assets/app.css'),
        'scripts' => array_map(function ($f) use ($base, $ver) {
            return $base . '/assets/' . $f . '?v=' . $ver('assets/' . $f);
        }, array_merge($lang === 'en' ? ['i18n-en.js'] : [], ['i18n.js', 'ui.js', 'pages.js', 'rules.js', 'reports.js', 'platform.js', 'w8.js', 'tutorials.js', 'tunnel.js', 'tcheck.js', 'tunnelq.js', 'apikeys.js', 'usage.js', 'statement.js', 'reseller.js', 'app.js'])),
    ];
}

/** Boot JSON, safe inside <script type="application/json">: no raw < > & ' " */
function pasargadcdn_boot_json(array $boot): string
{
    return (string) json_encode($boot, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_PARTIAL_OUTPUT_ON_ERROR);
}

/**
 * Included traffic and overage price of the service's product, in the client's
 * currency, for the usage bar of the client app. null when overage billing is
 * off (the controller limit is then the whole story) or on any error.
 */
function pasargadcdn_billing(array $params): ?array
{
    try {
        $pid = (int) ($params['pid'] ?? $params['packageid'] ?? 0);
        if ($pid <= 0) {
            return null;
        }
        $p = Capsule::table('tblproducts')->where('id', $pid)
            ->first(['overagesenabled', 'overagesbwlimit', 'overagesbwprice']);
        $o = $p ? pasargadcdn_overage((array) $p) : null;
        if ($o === null) {
            return null;
        }
        $currency = '';
        $rate = 1.0;
        $cid = (int) ($params['clientsdetails']['currency'] ?? 0);
        $c = $cid > 0 ? Capsule::table('tblcurrencies')->where('id', $cid)->first(['code', 'suffix', 'rate']) : null;
        if ($c) {
            $currency = trim((string) $c->suffix) !== '' ? trim((string) $c->suffix) : (string) $c->code;
            $rate = (float) $c->rate > 0 ? (float) $c->rate : 1.0;
        }
        return [
            'included_gb' => $o['included_gb'],
            'price_per_gb' => round($o['price_per_gb'] * $rate, 2),
            'currency' => $currency,
        ];
    } catch (\Throwable $e) {
        return null;
    }
}
