<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Env', false)) {
    return;
}

/**
 * Shared plumbing for the admin addon and its hooks: settings, the selected
 * controller server, CDN product ids, CSRF, logging, caching and localAPI.
 *
 * Everything that touches the database is memoised per request, so a hook
 * that asks "is this a CDN product?" several times costs one query.
 */
final class Env
{
    const MODULE = 'pasargadcdn_admin';
    const KV_TABLE = 'mod_pasargadcdn_settings';
    const TOPUPS = 'mod_pasargadcdn_topups';
    const NOTICES = 'mod_pasargadcdn_notices';
    const USAGE = 'mod_pasargadcdn_usage';
    // Reseller feature (SPEC §10.5) — a fully separate, additive ledger.
    const RESELLERS = 'mod_pasargadcdn_resellers';
    const RESELLER_SITES = 'mod_pasargadcdn_reseller_sites';
    const RESELLER_TOPUPS = 'mod_pasargadcdn_reseller_topups';
    /** Wave 7 (SPEC §15.7): tunnel origin-down / origin-up events already handled (dedupe per event id). */
    const TUNNEL_EVENTS = 'mod_pasargadcdn_tunnel_events';
    /** Wave 7 (SPEC §15.7): «بسته‌ی ترافیک افزوده» invoice items already applied (idempotency per item). */
    const ADDON_ITEMS = 'mod_pasargadcdn_addon_items';
    /** SPEC §16.8: one storage charge per service and month (StorageBilling) */
    const STORAGE_BILLS = 'mod_pasargadcdn_storage_bills';
    /** Growth: one scheduled e-mail report per service and period (Reports cron dedupe / retry ledger). */
    const REPORTS = 'mod_pasargadcdn_reports';
    /** Wave 10 (SPEC §18.5): referral ledger — one row per referred client (Referrals). */
    const REFERRALS = 'mod_pasargadcdn_referrals';
    const DEAD_STATUSES = ['Terminated', 'Cancelled', 'Fraud'];
    const DEFAULT_NS = ['ns1.pasargadmizban.com', 'ns2.pasargadmizban.com'];

    /** @var array per-request memo */
    private static $memo = [];

    /** Forgets memoised DB/controller facts (after writes); keeps the loaded-module flag and test hooks. */
    public static function reset(): void
    {
        self::$memo = array_intersect_key(self::$memo, ['loaded' => 1, 'api_factory' => 1]);
        if (function_exists('pasargadcdn_addon_settings')) {
            \pasargadcdn_addon_settings(true);
        }
    }

    /** Per-request memo for callers outside Env (e.g. the checkout's domain-check answers); cleared by reset(). */
    public static function memoHas(string $key): bool
    {
        return array_key_exists('x:' . $key, self::$memo);
    }

    public static function memoGet(string $key, $default = null)
    {
        return array_key_exists('x:' . $key, self::$memo) ? self::$memo['x:' . $key] : $default;
    }

    public static function memoSet(string $key, $value): void
    {
        self::$memo['x:' . $key] = $value;
    }

    // ------------------------------------------------------------------ server module

    public static function serverModuleDir(): string
    {
        return dirname(__DIR__, 3) . '/servers/pasargadcdn';
    }

    /** Loads the provisioning module (ApiClient, ClientApi, pasargadcdn_* helpers). */
    public static function loadServerModule(): bool
    {
        if (array_key_exists('loaded', self::$memo)) {
            return self::$memo['loaded'];
        }
        $dir = self::serverModuleDir();
        $ok = is_file($dir . '/lib/ApiClient.php') && is_file($dir . '/pasargadcdn.php');
        if ($ok) {
            require_once $dir . '/lib/ApiClient.php';
            require_once $dir . '/lib/ClientApi.php';
            require_once $dir . '/pasargadcdn.php';
        }
        return self::$memo['loaded'] = $ok;
    }

    // ------------------------------------------------------------------ settings

    /** Addon configuration (tbladdonmodules) — one query per request. */
    public static function settings(): array
    {
        if (!isset(self::$memo['settings'])) {
            $out = [];
            try {
                foreach (Capsule::table('tbladdonmodules')->where('module', self::MODULE)->get(['setting', 'value']) as $r) {
                    $out[(string) $r->setting] = (string) $r->value;
                }
            } catch (\Throwable $e) {
                $out = [];
            }
            self::$memo['settings'] = $out;
        }
        return self::$memo['settings'];
    }

    public static function setting(string $key, string $default = ''): string
    {
        $s = self::settings();
        return array_key_exists($key, $s) ? $s[$key] : $default;
    }

    public static function enabled(string $key, bool $default = true): bool
    {
        $s = self::settings();
        if (!array_key_exists($key, $s)) {
            return $default;
        }
        return in_array(strtolower(trim($s[$key])), ['on', '1', 'yes', 'true'], true);
    }

    /** Updates one of this addon's own configuration values. */
    public static function saveSetting(string $key, string $value): void
    {
        $q = Capsule::table('tbladdonmodules')->where('module', self::MODULE)->where('setting', $key);
        if ($q->exists()) {
            $q->update(['value' => $value]);
        } else {
            Capsule::table('tbladdonmodules')->insert(['module' => self::MODULE, 'setting' => $key, 'value' => $value]);
        }
        unset(self::$memo['settings'], self::$memo['server']);
    }

    /** Reserved domains (the company's own zones), lower case. */
    public static function reservedDomains(): array
    {
        $raw = self::setting('reserved', 'pasargadmizban.com');
        $out = [];
        foreach (preg_split('/[\s,،]+/u', strtolower($raw)) ?: [] as $d) {
            $d = trim($d, " .\t");
            if ($d !== '' && preg_match('/^[a-z0-9.-]+$/', $d)) {
                $out[] = $d;
            }
        }
        return $out ?: ['pasargadmizban.com'];
    }

    // ------------------------------------------------------------------ own key/value table

    public static function kvReady(): bool
    {
        if (!isset(self::$memo['kv'])) {
            try {
                self::$memo['kv'] = Capsule::schema()->hasTable(self::KV_TABLE);
            } catch (\Throwable $e) {
                self::$memo['kv'] = false;
            }
        }
        return self::$memo['kv'];
    }

    public static function kvGet(string $key, $default = null)
    {
        if (!self::kvReady()) {
            return $default;
        }
        $v = Capsule::table(self::KV_TABLE)->where('k', $key)->value('v');
        if ($v === null) {
            return $default;
        }
        $d = json_decode((string) $v, true);
        return $d === null && $v !== 'null' ? $default : $d;
    }

    public static function kvSet(string $key, $value): void
    {
        if (!self::kvReady()) {
            return;
        }
        Capsule::table(self::KV_TABLE)->updateOrInsert(['k' => $key],
            ['v' => json_encode($value, JSON_UNESCAPED_UNICODE), 'updated_at' => date('Y-m-d H:i:s')]);
    }

    public static function ensureTable(): void
    {
        $schema = Capsule::schema();
        if (!$schema->hasTable(self::KV_TABLE)) {
            $schema->create(self::KV_TABLE, function ($t) {
                $t->string('k', 64)->primary();
                $t->mediumText('v')->nullable();
                $t->dateTime('updated_at')->nullable();
            });
        }
        self::$memo['kv'] = true;
        if (!$schema->hasTable(self::TOPUPS)) {
            $schema->create(self::TOPUPS, function ($t) {
                $t->increments('id');
                $t->integer('service_id');
                $t->integer('userid');
                $t->char('month', 7);
                $t->integer('seq');
                $t->integer('blocks')->default(1);
                $t->integer('gb');
                $t->decimal('amount', 16, 2)->default(0);
                $t->integer('currency')->default(0);
                $t->integer('invoice_id')->nullable();
                $t->string('status', 16)->default('pending');
                $t->dateTime('created_at')->nullable();
                $t->dateTime('updated_at')->nullable();
                // one row per purchase slot: two concurrent runs can never buy the same slot twice
                $t->unique(['service_id', 'month', 'seq'], 'mod_pcdn_topups_slot');
                $t->index(['month', 'status'], 'mod_pcdn_topups_month');
                $t->index('invoice_id', 'mod_pcdn_topups_invoice');
            });
        }
        if (!$schema->hasTable(self::NOTICES)) {
            $schema->create(self::NOTICES, function ($t) {
                $t->increments('id');
                $t->integer('service_id');
                $t->char('month', 7);
                $t->string('kind', 16);
                $t->dateTime('created_at')->nullable();
                $t->unique(['service_id', 'month', 'kind'], 'mod_pcdn_notices_once');
            });
        }
        if (!$schema->hasTable(self::USAGE)) {
            $schema->create(self::USAGE, function ($t) {
                // last observed month usage of services near their cap (rate-aware purchase margin)
                $t->integer('service_id')->primary();
                $t->char('month', 7);
                $t->decimal('gb', 14, 3)->default(0);
                $t->integer('observed_at')->default(0);
                $t->decimal('rate', 18, 9)->default(0);
            });
        }
        self::$memo['tbl:' . self::USAGE] = true;
        self::$memo['tbl:' . self::TOPUPS] = true;
        self::$memo['tbl:' . self::NOTICES] = true;
        // ---- reseller feature (SPEC §10.5) ----------------------------------
        if (!$schema->hasTable(self::RESELLERS)) {
            $schema->create(self::RESELLERS, function ($t) {
                $t->integer('userid')->primary();       // WHMCS client id
                $t->tinyInteger('enabled')->default(1);
                $t->decimal('rate', 18, 9)->nullable();  // per-GB wholesale override (null ⇒ global)
                $t->integer('max_sites')->default(0);    // 0 ⇒ global default
                $t->string('note', 191)->nullable();
                $t->dateTime('created_at')->nullable();
                $t->dateTime('updated_at')->nullable();
            });
        }
        if (!$schema->hasTable(self::RESELLER_SITES)) {
            $schema->create(self::RESELLER_SITES, function ($t) {
                $t->increments('id');
                $t->integer('userid');                   // owning reseller client
                $t->string('domain', 253);
                $t->string('label', 120);                // free-text end-customer label
                $t->integer('controller_site_id')->nullable();
                $t->tinyInteger('suspended')->default(0);
                $t->dateTime('created_at')->nullable();
                $t->dateTime('updated_at')->nullable();
                $t->unique('domain', 'mod_pcdn_rsite_domain');
                $t->index('userid', 'mod_pcdn_rsite_user');
            });
        }
        if (!$schema->hasTable(self::RESELLER_TOPUPS)) {
            $schema->create(self::RESELLER_TOPUPS, function ($t) {
                $t->increments('id');
                $t->integer('userid');
                $t->char('month', 7);
                $t->integer('seq');
                $t->integer('blocks')->default(1);
                $t->integer('gb');
                $t->decimal('amount', 16, 2)->default(0);
                $t->integer('currency')->default(0);
                $t->integer('invoice_id')->nullable();
                $t->string('status', 16)->default('pending');
                $t->dateTime('created_at')->nullable();
                $t->dateTime('updated_at')->nullable();
                // one row per purchase slot: two concurrent runs can never buy the same slot twice
                $t->unique(['userid', 'month', 'seq'], 'mod_pcdn_rtopups_slot');
                $t->index(['month', 'status'], 'mod_pcdn_rtopups_month');
                $t->index('invoice_id', 'mod_pcdn_rtopups_invoice');
            });
        }
        self::$memo['tbl:' . self::RESELLERS] = true;
        self::$memo['tbl:' . self::RESELLER_SITES] = true;
        self::$memo['tbl:' . self::RESELLER_TOPUPS] = true;
        // ---- Wave 7 (SPEC §15.7) -----------------------------------------------
        if (!$schema->hasTable(self::TUNNEL_EVENTS)) {
            $schema->create(self::TUNNEL_EVENTS, function ($t) {
                $t->increments('id');
                $t->integer('server_id');
                $t->string('event_id', 64);              // controller id ("evt_…"), unique per controller
                $t->string('type', 32);
                $t->string('domain', 253)->default('');
                $t->integer('service_id')->nullable();
                $t->dateTime('event_at')->nullable();     // the event's created_at (UTC)
                $t->string('status', 16)->default('new'); // sent | failed | skipped | stale | nomatch
                $t->dateTime('created_at')->nullable();
                $t->unique(['server_id', 'event_id'], 'mod_pcdn_tevents_once');
                $t->index(['service_id', 'type'], 'mod_pcdn_tevents_service');
            });
        }
        if (!$schema->hasTable(self::ADDON_ITEMS)) {
            $schema->create(self::ADDON_ITEMS, function ($t) {
                $t->integer('invoice_item_id')->primary(); // one application per paid invoice line
                $t->integer('invoice_id');
                $t->integer('service_id');
                $t->integer('hostingaddon_id')->default(0);
                $t->integer('gb')->default(0);
                $t->char('month', 7);
                $t->integer('topup_id')->nullable();
                $t->string('status', 16)->default('pending'); // applied | skipped
                $t->tinyInteger('cap_ok')->default(0);
                $t->dateTime('created_at')->nullable();
                $t->index('service_id', 'mod_pcdn_addon_service');
            });
        }
        self::$memo['tbl:' . self::TUNNEL_EVENTS] = true;
        self::$memo['tbl:' . self::ADDON_ITEMS] = true;
        // ---- SPEC §16.8 object storage billing ------------------------------------
        if (!$schema->hasTable(self::STORAGE_BILLS)) {
            $schema->create(self::STORAGE_BILLS, function ($t) {
                $t->increments('id');
                $t->integer('service_id');
                $t->integer('userid');
                $t->char('month', 7);                      // the billed (closed) month, UTC
                $t->decimal('gb_month', 14, 4)->default(0);
                $t->decimal('amount', 16, 2)->default(0);
                $t->integer('currency')->default(0);
                $t->string('mode', 16)->default('');       // invoice (prepaid) | billable (overage / cut)
                $t->integer('invoice_id')->nullable();
                $t->integer('billable_id')->nullable();
                $t->string('status', 16)->default('pending'); // pending | invoiced | billable | skipped | failed
                $t->string('note', 191)->nullable();
                $t->dateTime('created_at')->nullable();
                $t->dateTime('updated_at')->nullable();
                // the idempotency key: a service is charged at most once per month, whatever runs in parallel
                $t->unique(['service_id', 'month'], 'mod_pcdn_storage_once');
                $t->index('month', 'mod_pcdn_storage_month');
            });
        }
        self::$memo['tbl:' . self::STORAGE_BILLS] = true;
        // ---- growth: e-mail reports ledger + the server module's per-service / trial / reseller tables -------
        if (!$schema->hasTable(self::REPORTS)) {
            $schema->create(self::REPORTS, function ($t) {
                $t->increments('id');
                $t->integer('service_id');
                $t->string('period', 16);                     // W2026-39 | M2026-09
                $t->string('freq', 8)->default('');
                $t->string('lang', 2)->default('fa');
                $t->string('status', 16)->default('sending');  // sending | sent | failed | skipped
                $t->integer('attempts')->default(0);
                $t->string('error', 191)->nullable();
                $t->dateTime('created_at')->nullable();
                $t->dateTime('updated_at')->nullable();
                $t->unique(['service_id', 'period'], 'mod_pcdn_reports_once');
            });
        }
        self::$memo['tbl:' . self::REPORTS] = true;
        self::ensureReferrals();
        if (self::loadServerModule()) {
            \PasargadCdn\ServiceState::ensure();
            \PasargadCdn\Trial::ensure();
            \PasargadCdn\Reseller::ensureExtras();
        }
    }

    /**
     * Wave 10 (SPEC §18.5): creates / migrates mod_pasargadcdn_referrals idempotently (missing columns of an
     * earlier build are added; nothing is dropped). Safe to call on every activation / upgrade.
     */
    public static function ensureReferrals(): void
    {
        $schema = Capsule::schema();
        if (!$schema->hasTable(self::REFERRALS)) {
            $schema->create(self::REFERRALS, function ($t) {
                $t->increments('id');
                $t->integer('referrer_id');
                $t->integer('referred_id');
                $t->string('code', 32)->default('');
                // pending (order placed, waiting for the first CDN invoice) | qualified (paid, waiting X days)
                // | paying (payout claimed) | paid | cancelled
                $t->string('status', 16)->default('pending');
                $t->string('reason', 191)->nullable();
                $t->integer('order_id')->default(0);
                $t->integer('invoice_id')->default(0);
                $t->string('signup_ip', 45)->default('');
                $t->decimal('amount_referrer', 16, 2)->default(0);
                $t->decimal('amount_referred', 16, 2)->default(0);
                $t->boolean('credited_referrer')->default(0);
                $t->boolean('credited_referred')->default(0);
                $t->integer('cancelled_by')->default(0);
                $t->dateTime('qualified_at')->nullable();
                $t->dateTime('paid_at')->nullable();
                $t->dateTime('created_at')->nullable();
                $t->dateTime('updated_at')->nullable();
                // once per referred client, whatever runs in parallel
                $t->unique('referred_id', 'mod_pcdn_ref_once');
                $t->index(['referrer_id', 'status'], 'mod_pcdn_ref_referrer');
                $t->index(['status', 'qualified_at'], 'mod_pcdn_ref_due');
            });
        } else {
            $cols = ['code' => function ($t) { $t->string('code', 32)->default(''); },
                'reason' => function ($t) { $t->string('reason', 191)->nullable(); },
                'order_id' => function ($t) { $t->integer('order_id')->default(0); },
                'invoice_id' => function ($t) { $t->integer('invoice_id')->default(0); },
                'signup_ip' => function ($t) { $t->string('signup_ip', 45)->default(''); },
                'amount_referrer' => function ($t) { $t->decimal('amount_referrer', 16, 2)->default(0); },
                'amount_referred' => function ($t) { $t->decimal('amount_referred', 16, 2)->default(0); },
                'credited_referrer' => function ($t) { $t->boolean('credited_referrer')->default(0); },
                'credited_referred' => function ($t) { $t->boolean('credited_referred')->default(0); },
                'cancelled_by' => function ($t) { $t->integer('cancelled_by')->default(0); },
                'qualified_at' => function ($t) { $t->dateTime('qualified_at')->nullable(); },
                'paid_at' => function ($t) { $t->dateTime('paid_at')->nullable(); },
                'updated_at' => function ($t) { $t->dateTime('updated_at')->nullable(); }];
            foreach ($cols as $col => $def) {
                if (!$schema->hasColumn(self::REFERRALS, $col)) {
                    $schema->table(self::REFERRALS, $def);
                }
            }
        }
        self::$memo['tbl:' . self::REFERRALS] = true;
    }

    // ------------------------------------------------------------------ servers / controller

    /** All Pasargad CDN servers (tblservers.type = pasargadcdn). */
    public static function servers(): array
    {
        if (!isset(self::$memo['servers'])) {
            $cols = ['id', 'name', 'hostname', 'ipaddress', 'secure', 'port', 'accesshash', 'password', 'disabled'];
            try {
                self::$memo['servers'] = Capsule::table('tblservers')->where('type', 'pasargadcdn')
                    ->orderBy('disabled')->orderBy('id')->get($cols)->all();
            } catch (\Throwable $e) {
                self::$memo['servers'] = [];
            }
        }
        return self::$memo['servers'];
    }

    /** Server chosen in the addon settings, else the first enabled one. */
    public static function server()
    {
        if (array_key_exists('server', self::$memo)) {
            return self::$memo['server'];
        }
        $want = (int) self::setting('server', '0');
        $pick = null;
        foreach (self::servers() as $s) {
            if ($want > 0 && (int) $s->id === $want) {
                $pick = $s;
                break;
            }
            if ($pick === null && empty($s->disabled)) {
                $pick = $s;
            }
        }
        if ($pick === null && $want <= 0 && self::servers()) {
            $pick = self::servers()[0];
        }
        return self::$memo['server'] = $pick;
    }

    public static function serverById(int $id)
    {
        foreach (self::servers() as $s) {
            if ((int) $s->id === $id) {
                return $s;
            }
        }
        return null;
    }

    /** @throws ApiException when no server is configured */
    public static function api(int $timeout = 10, $server = null): ApiClient
    {
        self::loadServerModule();
        $server = $server ?: self::server();
        if (!$server) {
            throw new ApiException('هیچ سروری از نوع Pasargad CDN در WHMCS تعریف نشده است.');
        }
        $key = 'api:' . (int) $server->id . ':' . $timeout;
        if (!isset(self::$memo[$key])) {
            $factory = self::$memo['api_factory'] ?? null;
            self::$memo[$key] = $factory ? $factory($server, $timeout) : ApiClient::fromServerRow($server, $timeout);
        }
        return self::$memo[$key];
    }

    /** Tests: fn(object $serverRow, int $timeout): ApiClient */
    public static function setApiFactory(?callable $f): void
    {
        self::$memo['api_factory'] = $f;
    }

    /** Public base URL of the controller, e.g. https://cdn-api.pasargadmizban.com */
    public static function controllerUrl($server = null): string
    {
        $server = $server ?: self::server();
        if (!$server) {
            return '';
        }
        $host = trim((string) $server->hostname) ?: trim((string) $server->ipaddress);
        if ($host === '') {
            return '';
        }
        if (!preg_match('#^https?://#i', $host)) {
            $port = (int) $server->port;
            $host = (!empty($server->secure) ? 'https' : 'http') . '://' . $host
                . ($port && !in_array($port, [80, 443], true) ? ':' . $port : '');
        }
        return rtrim($host, '/');
    }

    // ------------------------------------------------------------------ products / services

    /** ids of products using the pasargadcdn module — ONE query per request. */
    public static function cdnProductIds(): array
    {
        if (!isset(self::$memo['pids'])) {
            try {
                self::$memo['pids'] = array_map('intval',
                    Capsule::table('tblproducts')->where('servertype', 'pasargadcdn')->pluck('id')->all());
            } catch (\Throwable $e) {
                self::$memo['pids'] = [];
            }
        }
        return self::$memo['pids'];
    }

    public static function isCdnProduct(int $pid): bool
    {
        return $pid > 0 && in_array($pid, self::cdnProductIds(), true);
    }

    /** Same normalisation as the provisioning module. */
    public static function domain(string $d): string
    {
        $d = strtolower(trim($d));
        $d = (string) preg_replace('#^[a-z][a-z0-9+.-]*://#', '', $d);
        $d = (string) preg_replace('#[/?\#].*$#', '', $d);
        $d = (string) preg_replace('#:\d+$#', '', $d);
        $d = rtrim($d, '.');
        return (string) preg_replace('/^www\./', '', $d);
    }

    public static function validHostname(string $d): bool
    {
        return (bool) preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/D', $d);
    }

    // ------------------------------------------------------------------ admin context / CSRF

    public static function adminId(): int
    {
        return (int) ($_SESSION['adminid'] ?? 0);
    }

    /** Session CSRF token of this addon (separate from WHMCS's own token). */
    public static function csrf(): string
    {
        if (empty($_SESSION['pasargadcdn_admin_csrf']) || !is_string($_SESSION['pasargadcdn_admin_csrf'])) {
            $_SESSION['pasargadcdn_admin_csrf'] = bin2hex(random_bytes(20));
        }
        return $_SESSION['pasargadcdn_admin_csrf'];
    }

    public static function checkCsrf($token): bool
    {
        $s = $_SESSION['pasargadcdn_admin_csrf'] ?? '';
        return is_string($s) && $s !== '' && is_string($token) && hash_equals($s, $token);
    }

    /** WHMCS's own admin form token, when available (sent along so WHMCS-level checks pass too). */
    public static function whmcsToken(): string
    {
        if (function_exists('generate_token')) {
            try {
                return (string) generate_token('plain');
            } catch (\Throwable $e) {
                return '';
            }
        }
        return '';
    }

    // ------------------------------------------------------------------ logging / localAPI / cache

    public static function log(string $message, int $userId = 0): void
    {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: ' . $message, $userId);
        }
    }

    /** localAPI wrapper that never throws: returns ['result' => 'error', 'message' => ...] on failure. */
    public static function localApi(string $command, array $args): array
    {
        if (!function_exists('localAPI')) {
            return ['result' => 'error', 'message' => 'localAPI در دسترس نیست'];
        }
        try {
            $r = localAPI($command, $args);
        } catch (\Throwable $e) {
            return ['result' => 'error', 'message' => $e->getMessage()];
        }
        return is_array($r) ? $r : ['result' => 'error', 'message' => 'پاسخ نامعتبر از WHMCS'];
    }

    /** Short-lived cache: WHMCS\TransientData when present, else this addon's own table. */
    public static function cacheGet(string $key)
    {
        try {
            if (class_exists('\\WHMCS\\TransientData')) {
                $raw = \WHMCS\TransientData::getInstance()->retrieve($key);
                $d = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;
                return is_array($d) ? $d : null;
            }
            $d = self::kvGet('cache:' . $key);
            if (is_array($d) && isset($d['exp'], $d['data']) && $d['exp'] > time()) {
                return $d['data'];
            }
        } catch (\Throwable $e) {
            return null;
        }
        return null;
    }

    public static function cacheSet(string $key, array $data, int $ttl): void
    {
        try {
            if (class_exists('\\WHMCS\\TransientData')) {
                \WHMCS\TransientData::getInstance()->store($key, json_encode($data, JSON_UNESCAPED_UNICODE), $ttl);
                return;
            }
            self::kvSet('cache:' . $key, ['exp' => time() + $ttl, 'data' => $data]);
        } catch (\Throwable $e) {
            // caching is best effort
        }
    }

    public static function cacheDelete(string $key): void
    {
        try {
            if (class_exists('\\WHMCS\\TransientData')) {
                \WHMCS\TransientData::getInstance()->delete($key);
                return;
            }
            if (self::kvReady()) {
                Capsule::table(self::KV_TABLE)->where('k', 'cache:' . $key)->delete();
            }
        } catch (\Throwable $e) {
            // best effort
        }
    }

    // ------------------------------------------------------------------ schema helpers

    public static function hasColumn(string $table, string $col): bool
    {
        $k = 'col:' . $table . '.' . $col;
        if (!isset(self::$memo[$k])) {
            try {
                self::$memo[$k] = Capsule::schema()->hasColumn($table, $col);
            } catch (\Throwable $e) {
                self::$memo[$k] = false;
            }
        }
        return self::$memo[$k];
    }

    public static function hasTable(string $table): bool
    {
        $k = 'tbl:' . $table;
        if (!isset(self::$memo[$k])) {
            try {
                self::$memo[$k] = Capsule::schema()->hasTable($table);
            } catch (\Throwable $e) {
                self::$memo[$k] = false;
            }
        }
        return self::$memo[$k];
    }

    /** Keeps only the keys that are real columns of $table (columns differ between WHMCS versions). */
    public static function onlyColumns(string $table, array $row): array
    {
        $out = [];
        foreach ($row as $k => $v) {
            if (self::hasColumn($table, $k)) {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    /**
     * Largest value a DECIMAL column can hold (MySQL information_schema).
     * Unknown (other drivers, no access) → WHMCS's historical decimal(6,4) for overage prices.
     */
    public static function decimalMax(string $table, string $col, float $fallback = 99.9999): float
    {
        try {
            $conn = Capsule::connection();
            if ($conn->getDriverName() !== 'mysql') {
                return $fallback;
            }
            $r = $conn->selectOne('SELECT NUMERIC_PRECISION p, NUMERIC_SCALE s FROM information_schema.COLUMNS '
                . 'WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?', [$table, $col]);
            if ($r && (int) $r->p > 0) {
                $p = (int) $r->p;
                $s = (int) $r->s;
                return (float) (str_repeat('9', max(1, $p - $s)) . ($s > 0 ? '.' . str_repeat('9', $s) : ''));
            }
        } catch (\Throwable $e) {
            return $fallback;
        }
        return $fallback;
    }

    /** Decodes WHMCS's input sanitising (it HTML-encodes request values). */
    public static function input($v): string
    {
        if (!is_string($v)) {
            return '';
        }
        return trim(html_entity_decode($v, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    }
}
