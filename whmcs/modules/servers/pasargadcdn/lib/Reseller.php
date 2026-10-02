<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

require_once __DIR__ . '/I18n.php';
require_once __DIR__ . '/DomainRules.php';

if (class_exists(__NAMESPACE__ . '\\Reseller', false)) {
    return;
}

/**
 * Reseller feature core (SPEC §10.5) — shared by the client-area proxy
 * (ClientApi), the admin addon pages and the wholesale billing pass.
 *
 * A reseller is a WHMCS client flagged in mod_pasargadcdn_resellers. They
 * provision CDN sub-sites for their OWN end-customers; each sub-site is a
 * controller Site tagged with the reseller's WHMCS client id + a free-text
 * label, recorded locally in mod_pasargadcdn_reseller_sites. Sub-sites have
 * NO tblhosting row — the domain is always resolved from the local table,
 * keyed by (id, userid), never from client input (tenant isolation).
 *
 * This class never trusts a caller-supplied domain and never crosses tenants:
 * every per-site lookup takes the logged-in client id and returns the same
 * "not found" answer for a missing row and for a row owned by someone else.
 */
class Reseller
{
    const TBL_RESELLERS = 'mod_pasargadcdn_resellers';
    const TBL_SITES = 'mod_pasargadcdn_reseller_sites';
    const TBL_TOPUPS = 'mod_pasargadcdn_reseller_topups';
    /** Growth: white-label name/logo of a reseller (shown in the client-app header for its sub-sites). */
    const TBL_BRAND = 'mod_pasargadcdn_reseller_brand';
    /** Growth: sub-sites the reseller paused by hand (bulk suspend) — kept apart from the wallet's `suspended`. */
    const TBL_HOLDS = 'mod_pasargadcdn_reseller_holds';
    const BRAND_NAME_MAX = 60;
    const LOGO_MAX = 65536; // bytes of the decoded image
    const BULK_MAX = 200;

    /** Per-sub-site controller cap (GB). Aggregate wallet + suspend/reconnect do the real cutting. */
    const SITE_CAP_GB = 1000000;
    const MAX_SITES_HARD = 1000;

    // ------------------------------------------------------------------ flags / config

    private static function has(string $table): bool
    {
        try {
            return Capsule::schema()->hasTable($table);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Is this client an enabled reseller? */
    public static function isReseller(int $userid): bool
    {
        if ($userid <= 0 || !self::has(self::TBL_RESELLERS)) {
            return false;
        }
        try {
            return (int) Capsule::table(self::TBL_RESELLERS)->where('userid', $userid)->where('enabled', 1)->count() > 0;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Reseller row (any enabled state) or null. */
    public static function row(int $userid)
    {
        if ($userid <= 0 || !self::has(self::TBL_RESELLERS)) {
            return null;
        }
        try {
            return Capsule::table(self::TBL_RESELLERS)->where('userid', $userid)->first();
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** Global default wholesale per-GB rate (addon setting), or null when unset. */
    public static function globalRate(): ?float
    {
        $s = \pasargadcdn_addon_settings();
        $v = trim(str_replace(',', '', (string) ($s['reseller_rate'] ?? '')));
        return ($v !== '' && is_numeric($v) && (float) $v > 0) ? (float) $v : null;
    }

    /** Global default max sub-sites per reseller (0 ⇒ unlimited-ish, capped by MAX_SITES_HARD). */
    public static function globalMaxSites(): int
    {
        $s = \pasargadcdn_addon_settings();
        $v = (int) ($s['reseller_max_sites'] ?? 0);
        return $v > 0 ? min($v, self::MAX_SITES_HARD) : 0;
    }

    /**
     * Effective config for a reseller: [enabled, rate (?float effective), max_sites (int, 0=global unset),
     * note]. rate falls back to the global default; max_sites to the global default.
     */
    public static function config(int $userid): array
    {
        $r = self::row($userid);
        $rate = self::globalRate();
        $max = self::globalMaxSites();
        if ($r) {
            if ($r->rate !== null && (float) $r->rate > 0) {
                $rate = (float) $r->rate;
            }
            if ((int) $r->max_sites > 0) {
                $max = min((int) $r->max_sites, self::MAX_SITES_HARD);
            }
        }
        return [
            'enabled' => $r ? (int) $r->enabled === 1 : false,
            'rate' => $rate,
            'max_sites' => $max,
            'note' => $r ? (string) $r->note : '',
        ];
    }

    /** Block size (GB) and monthly safety cap (blocks) — reuse the global prepaid settings. */
    public static function blockGb(): int
    {
        $s = \pasargadcdn_addon_settings();
        $b = (int) ($s['block_gb'] ?? 10);
        return $b > 0 ? min($b, 100000) : 10;
    }

    public static function maxBlocks(): int
    {
        $s = \pasargadcdn_addon_settings();
        $m = (int) ($s['max_blocks'] ?? 20);
        return $m >= 0 ? $m : 20;
    }

    // ------------------------------------------------------------------ local sub-site rows

    /** All of a reseller's sub-site rows (owned by $userid), newest first. */
    public static function sites(int $userid): array
    {
        if ($userid <= 0 || !self::has(self::TBL_SITES)) {
            return [];
        }
        try {
            return Capsule::table(self::TBL_SITES)->where('userid', $userid)->orderBy('id', 'desc')->get()->all();
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function siteCount(int $userid): int
    {
        if ($userid <= 0 || !self::has(self::TBL_SITES)) {
            return 0;
        }
        try {
            return (int) Capsule::table(self::TBL_SITES)->where('userid', $userid)->count();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * One sub-site row, ONLY when it belongs to $userid. Same answer (null) for a
     * missing row and for a row owned by someone else — ids can't be probed.
     */
    public static function ownedSite(int $userid, int $rsid)
    {
        if ($userid <= 0 || $rsid <= 0 || !self::has(self::TBL_SITES)) {
            return null;
        }
        try {
            return Capsule::table(self::TBL_SITES)->where('id', $rsid)->where('userid', $userid)->first();
        } catch (\Throwable $e) {
            return null;
        }
    }

    // ------------------------------------------------------------------ controller server

    /** The tblservers row (pasargadcdn) reseller sub-sites live on: addon-selected, else first enabled. */
    public static function server()
    {
        try {
            $want = 0;
            $s = \pasargadcdn_addon_settings();
            $want = (int) ($s['server'] ?? 0);
            $rows = Capsule::table('tblservers')->where('type', 'pasargadcdn')->orderBy('disabled')->orderBy('id')->get()->all();
            $pick = null;
            foreach ($rows as $row) {
                if ($want > 0 && (int) $row->id === $want) {
                    return $row;
                }
                if ($pick === null && empty($row->disabled)) {
                    $pick = $row;
                }
            }
            return $pick ?: ($rows[0] ?? null);
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** ApiClient for the reseller controller server. */
    public static function api($server = null, int $timeout = 15, ?callable $factory = null): ApiClient
    {
        $server = $server ?: self::server();
        if (!$server) {
            throw new ApiException(I18n::tr('هیچ سروری از نوع Pasargad CDN تنظیم نشده است.'));
        }
        return $factory ? $factory($server) : ApiClient::fromServerRow($server, $timeout);
    }

    // ------------------------------------------------------------------ validation

    public static function validDomain(string $d): bool
    {
        return (bool) preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/D', $d);
    }

    public static function validOrigin(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    // ------------------------------------------------------------------ create / delete

    /**
     * Provision a sub-site for a reseller: enforce the enabled flag + max-sites cap,
     * create the Site on the controller tagged with the reseller's client id + label,
     * and record the local row. Returns [bool ok, string|array result].
     *
     * @param callable|null $factory fn($serverRow): ApiClient (tests)
     */
    public static function createSite(int $userid, string $domain, string $originIp, string $label, ?callable $factory = null): array
    {
        if (!self::has(self::TBL_SITES)) {
            return [false, I18n::tr('جدول نمایندگان آماده نیست.')];
        }
        $cfg = self::config($userid);
        if (!$cfg['enabled']) {
            return [false, I18n::tr('حساب شما به‌عنوان نماینده فعال نیست.')];
        }
        $domain = \pasargadcdn_domain(['domain' => $domain]);
        $label = trim(mb_substr($label, 0, 120));
        if (!self::validDomain($domain)) {
            return [false, I18n::tr('دامنه معتبر نیست.')];
        }
        // C1: never a public suffix, never nested in / around another client's CDN domain
        if (DomainRules::isPublicSuffix($domain)) {
            return [false, I18n::tr('«%s» یک پسوند عمومی دامنه است و نمی‌توان آن را به‌عنوان سایت روی CDN ثبت کرد؛ نام کامل دامنه خود را وارد کنید (مثلاً example.ir).', $domain)];
        }
        try {
            $pids = array_map('intval', Capsule::table('tblproducts')->where('servertype', 'pasargadcdn')->pluck('id')->all());
            if (DomainRules::foreignNested($domain, $userid, DomainRules::related($domain, $pids)) !== null) {
                return [false, I18n::tr('دامنه %s زیردامنه یا دامنه اصلی سایتی است که متعلق به مشتری دیگری روی CDN است و قابل ثبت نیست. اگر مالک دامنه هستید با پشتیبانی تماس بگیرید.', $domain)];
            }
        } catch (\Throwable $e) {
            // the controller enforces the same rule
        }
        if (!self::validOrigin($originIp)) {
            return [false, I18n::tr('آی‌پی سرور اصلی (Origin) باید یک IPv4 عمومی معتبر باشد.')];
        }
        if ($label === '') {
            return [false, I18n::tr('نام مشتری نهایی را وارد کنید.')];
        }
        $max = $cfg['max_sites'];
        if ($max > 0 && self::siteCount($userid) >= $max) {
            return [false, I18n::tr('به سقف تعداد سایت‌های مجاز (%s) رسیده‌اید.', $max)];
        }
        // Domain already taken (by any reseller / normal service)?
        if (Capsule::table(self::TBL_SITES)->where('domain', $domain)->exists()) {
            return [false, I18n::tr('این دامنه قبلاً به‌عنوان زیرسایت نمایندگی ثبت شده است.')];
        }
        try {
            if (Capsule::table('tblhosting')->whereRaw('LOWER(domain) = ?', [$domain])->exists()) {
                return [false, I18n::tr('این دامنه به یک سرویس WHMCS تعلق دارد و به‌عنوان زیرسایت نمایندگی قابل ثبت نیست.')];
            }
        } catch (\Throwable $e) {
            // best effort
        }
        $server = self::server();
        if (!$server) {
            return [false, I18n::tr('سرور CDN تنظیم نشده است؛ با پشتیبانی تماس بگیرید.')];
        }
        $plan = self::wholesalePlan();
        $body = [
            'domain' => $domain,
            'origin_ip' => $originIp,
            'reseller_client_id' => $userid,
            'reseller_label' => $label,
            'plan' => $plan,
        ];
        try {
            $r = self::api($server, 15, $factory)->post('/api/v1/sites', $body);
        } catch (\Throwable $e) {
            return [false, I18n::tr('ساخت سایت روی کنترلر ناموفق بود: %s', $e->getMessage())];
        }
        $ctlId = (int) ($r['id'] ?? 0);
        $now = date('Y-m-d H:i:s');
        try {
            $id = (int) Capsule::table(self::TBL_SITES)->insertGetId([
                'userid' => $userid, 'domain' => $domain, 'label' => $label,
                'controller_site_id' => $ctlId ?: null, 'suspended' => 0,
                'created_at' => $now, 'updated_at' => $now,
            ]);
        } catch (\Throwable $e) {
            return [false, I18n::tr('ثبت محلی زیرسایت ناموفق بود: %s', $e->getMessage())];
        }
        self::log('reseller sub-site ' . $domain . ' created for client #' . $userid . ' (' . $label . ')', $userid);
        return [true, ['id' => $id, 'domain' => $domain, 'label' => $label, 'controller_site_id' => $ctlId]];
    }

    /** Default wholesale plan for a new sub-site (cap managed by the aggregate wallet, so generous). */
    public static function wholesalePlan(): array
    {
        return [
            'bandwidth_limit_gb' => self::SITE_CAP_GB,
            'ssl_allowed' => true,
            'features' => ['waf' => true, 'ddos' => true],
        ];
    }

    /**
     * Remove a sub-site: delete on the controller, then the local row. Ownership-checked.
     * @return array [bool ok, string message]
     */
    public static function deleteSite(int $userid, int $rsid, ?callable $factory = null): array
    {
        $row = self::ownedSite($userid, $rsid);
        if (!$row) {
            return [false, I18n::tr('زیرسایت یافت نشد.')];
        }
        $domain = \pasargadcdn_domain(['domain' => (string) $row->domain]);
        $server = self::server();
        if ($server && self::validDomain($domain)) {
            try {
                self::api($server, 15, $factory)->delete(ApiClient::site($domain));
            } catch (\Throwable $e) {
                // A 404 on the controller is fine (already gone); other errors abort so nothing is orphaned.
                if (!($e instanceof ApiException && $e->getCode() === 404)) {
                    return [false, I18n::tr('حذف سایت از کنترلر ناموفق بود: %s', $e->getMessage())];
                }
            }
        }
        try {
            Capsule::table(self::TBL_SITES)->where('id', $rsid)->where('userid', $userid)->delete();
        } catch (\Throwable $e) {
            return [false, I18n::tr('حذف رکورد محلی ناموفق بود: %s', $e->getMessage())];
        }
        self::log('reseller sub-site ' . $domain . ' removed by client #' . $userid, $userid);
        return [true, I18n::tr('زیرسایت حذف شد.')];
    }

    // ------------------------------------------------------------------ rolled-up usage & cost report

    /**
     * Current-month usage & wholesale cost across a reseller's sub-sites.
     * Read-only: one GET /api/v1/usage to the controller, matched to local rows by domain.
     *
     * @return array {
     *   sites: [ {id, domain, label, gb, cost, suspended} ],
     *   total_gb, total_cost, rate, currency, credit, month,
     *   block_gb, error(?string)
     * }
     */
    public static function report(int $userid, ?callable $factory = null): array
    {
        $cfg = self::config($userid);
        $rate = $cfg['rate'] ?? 0.0;
        $month = \pasargadcdn_month();
        $rows = self::sites($userid);
        [$credit, $currency, $crate] = self::credit($userid);
        $rateLocal = $rate !== null ? round($rate * $crate, 2) : 0.0;
        $out = [
            'sites' => [], 'total_gb' => 0.0, 'total_cost' => 0.0,
            'rate' => $rateLocal, 'rate_base' => $rate, 'currency' => $currency,
            'credit' => $credit, 'month' => $month, 'block_gb' => self::blockGb(), 'error' => null,
        ];
        $usageByDomain = [];
        if ($rows) {
            $server = self::server();
            if ($server) {
                try {
                    $data = self::api($server, 15, $factory)->get('/api/v1/usage?month=' . $month);
                    foreach ((array) ($data['sites'] ?? []) as $s) {
                        $d = strtolower((string) ($s['domain'] ?? ''));
                        if ($d !== '') {
                            $usageByDomain[$d] = (float) ($s['bytes'] ?? 0) / 1073741824;
                        }
                    }
                } catch (\Throwable $e) {
                    $out['error'] = $e->getMessage();
                }
            } else {
                $out['error'] = I18n::tr('سرور CDN تنظیم نشده است.');
            }
        }
        $held = array_flip(self::heldIds($userid));
        foreach ($rows as $r) {
            $d = strtolower(\pasargadcdn_domain(['domain' => (string) $r->domain]));
            $gb = $usageByDomain[$d] ?? 0.0;
            $cost = round($gb * $rateLocal, 2);
            $out['sites'][] = [
                'id' => (int) $r->id, 'domain' => $d, 'label' => (string) $r->label,
                'gb' => round($gb, 3), 'cost' => $cost, 'suspended' => (int) $r->suspended === 1,
                'held' => isset($held[(int) $r->id]),
            ];
            $out['total_gb'] += $gb;
            $out['total_cost'] += $cost;
        }
        $out['total_gb'] = round($out['total_gb'], 3);
        $out['total_cost'] = round($out['total_cost'], 2);
        $out['limits'] = self::limits($userid, count($rows));
        return $out;
    }

    // ------------------------------------------------------------------ growth: limits, white-label, holds, bulk, export

    /** Creates the brand / holds tables when missing (also run by the addon's Env::ensureTable()). Never throws. */
    public static function ensureExtras(): bool
    {
        try {
            $schema = Capsule::schema();
            if (!$schema->hasTable(self::TBL_BRAND)) {
                $schema->create(self::TBL_BRAND, function ($t) {
                    $t->integer('userid')->primary();
                    $t->string('name', 120)->default('');
                    $t->mediumText('logo')->nullable();   // data:image/(png|jpeg|webp|gif);base64,… (no SVG: scripts)
                    $t->dateTime('updated_at')->nullable();
                });
            }
            if (!$schema->hasTable(self::TBL_HOLDS)) {
                $schema->create(self::TBL_HOLDS, function ($t) {
                    $t->integer('site_id')->primary();     // mod_pasargadcdn_reseller_sites.id
                    $t->integer('userid');
                    $t->dateTime('created_at')->nullable();
                    $t->index('userid', 'mod_pcdn_rhold_user');
                });
            }
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** What this reseller may do and has used: sub-site cap, wholesale rate, top-up block size / monthly cap, sub-site plan. */
    public static function limits(int $userid, ?int $count = null): array
    {
        $cfg = self::config($userid);
        $bought = 0;
        try {
            if (self::has(self::TBL_TOPUPS)) {
                $bought = (int) Capsule::table(self::TBL_TOPUPS)->where('userid', $userid)->where('month', \pasargadcdn_month())
                    ->where('status', 'paid')->sum('blocks');
            }
        } catch (\Throwable $e) {
            $bought = 0;
        }
        $plan = self::wholesalePlan();
        return [
            'max_sites' => $cfg['max_sites'], 'sites' => $count ?? self::siteCount($userid), 'hard_max_sites' => self::MAX_SITES_HARD,
            'rate' => $cfg['rate'], 'block_gb' => self::blockGb(), 'max_blocks' => self::maxBlocks(), 'blocks_month' => $bought,
            'held' => count(self::heldIds($userid)),
            'site_plan' => ['ssl' => !empty($plan['ssl_allowed']), 'waf' => !empty($plan['features']['waf']), 'ddos' => !empty($plan['features']['ddos'])],
        ];
    }

    /** Sub-site ids this reseller paused by hand. */
    public static function heldIds(int $userid): array
    {
        if ($userid <= 0 || !self::has(self::TBL_HOLDS)) {
            return [];
        }
        try {
            return array_map('intval', Capsule::table(self::TBL_HOLDS)->where('userid', $userid)->pluck('site_id')->all());
        } catch (\Throwable $e) {
            return [];
        }
    }

    /** Is this sub-site paused by its reseller? (the wallet reconnect must leave it suspended) */
    public static function isHeld(int $siteId): bool
    {
        if ($siteId <= 0 || !self::has(self::TBL_HOLDS)) {
            return false;
        }
        try {
            return Capsule::table(self::TBL_HOLDS)->where('site_id', $siteId)->exists();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** White-label of a reseller: ['name' => string, 'logo' => ?data-URI] or null when none is set. */
    public static function brand(int $userid): ?array
    {
        if ($userid <= 0 || !self::has(self::TBL_BRAND)) {
            return null;
        }
        try {
            $r = Capsule::table(self::TBL_BRAND)->where('userid', $userid)->first();
        } catch (\Throwable $e) {
            return null;
        }
        if (!$r || (trim((string) $r->name) === '' && empty($r->logo))) {
            return null;
        }
        $logo = is_string($r->logo) && self::validLogo($r->logo) ? $r->logo : null;
        return ['name' => (string) $r->name, 'logo' => $logo];
    }

    /** A data URI of a small raster image (PNG / JPEG / WebP / GIF, ≤ LOGO_MAX bytes) whose bytes really are that image. */
    public static function validLogo(string $uri): bool
    {
        if (!preg_match('#^data:image/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/]+={0,2})$#D', $uri, $m)) {
            return false;
        }
        $bin = base64_decode($m[2], true);
        if ($bin === false || $bin === '' || strlen($bin) > self::LOGO_MAX) {
            return false;
        }
        $magic = ['png' => "\x89PNG\r\n\x1a\n", 'jpeg' => "\xff\xd8\xff", 'gif' => 'GIF8'];
        if ($m[1] === 'webp') {
            return substr($bin, 0, 4) === 'RIFF' && substr($bin, 8, 4) === 'WEBP';
        }
        return strncmp($bin, $magic[$m[1]], strlen($magic[$m[1]])) === 0;
    }

    /**
     * Saves the reseller's white-label ($name '' and $logo '' clear it; $logo null keeps the stored one).
     * @return array [bool ok, array|string brand-or-message]
     */
    public static function saveBrand(int $userid, string $name, ?string $logo): array
    {
        if (!self::isReseller($userid)) {
            return [false, I18n::tr('حساب شما به‌عنوان نماینده فعال نیست.')];
        }
        $name = trim(preg_replace('/[\x00-\x1f\x7f<>]+/u', ' ', $name) ?? '');
        if (mb_strlen($name) > self::BRAND_NAME_MAX) {
            return [false, I18n::tr('نام برند حداکثر %s نویسه است.', self::BRAND_NAME_MAX)];
        }
        if ($logo !== null && $logo !== '' && !self::validLogo($logo)) {
            return [false, I18n::tr('لوگو باید تصویر PNG، JPEG، WebP یا GIF و حداکثر ۶۴ کیلوبایت باشد.')];
        }
        if (!self::ensureExtras()) {
            return [false, I18n::tr('ذخیره برند ممکن نشد؛ دوباره تلاش کنید.')];
        }
        $row = ['name' => $name, 'updated_at' => date('Y-m-d H:i:s')];
        if ($logo !== null) {
            $row['logo'] = $logo === '' ? null : $logo;
        }
        try {
            Capsule::table(self::TBL_BRAND)->updateOrInsert(['userid' => $userid], $row);
        } catch (\Throwable $e) {
            return [false, I18n::tr('ذخیره برند ممکن نشد؛ دوباره تلاش کنید.')];
        }
        return [true, self::brand($userid) ?? ['name' => '', 'logo' => null]];
    }

    /**
     * Bulk pause / resume of the reseller's OWN sub-sites. Ids that are missing or owned by someone else are
     * reported as not found (never touched, never distinguished). Resume of a site the wallet cut leaves it
     * cut (only the reseller's own hold is removed). @return array {done: int[], skipped: [{id, reason}]}
     */
    public static function bulk(int $userid, array $ids, string $action, ?callable $factory = null): array
    {
        $out = ['done' => [], 'skipped' => []];
        $ids = array_values(array_unique(array_filter(array_map('intval', array_slice($ids, 0, self::BULK_MAX)), function ($x) {
            return $x > 0;
        })));
        if (!in_array($action, ['suspend', 'unsuspend'], true) || !self::ensureExtras()) {
            return $out;
        }
        $server = self::server();
        foreach ($ids as $id) {
            $row = self::ownedSite($userid, $id);
            if (!$row) {
                $out['skipped'][] = ['id' => $id, 'reason' => 'not_found'];
                continue;
            }
            $domain = \pasargadcdn_domain(['domain' => (string) $row->domain]);
            $held = self::isHeld($id);
            if (($action === 'suspend' && $held) || ($action === 'unsuspend' && !$held)) {
                $out['skipped'][] = ['id' => $id, 'reason' => 'unchanged'];
                continue;
            }
            // the controller call is skipped when the wallet already keeps the site cut (resume) / cut (pause)
            $callCtl = (int) $row->suspended !== 1;
            try {
                if ($callCtl) {
                    if (!$server || !self::validDomain($domain)) {
                        throw new ApiException(I18n::tr('سرور CDN تنظیم نشده است.'));
                    }
                    self::api($server, 15, $factory)->post(ApiClient::site($domain) . '/' . $action);
                }
                if ($action === 'suspend') {
                    Capsule::table(self::TBL_HOLDS)->insert(['site_id' => $id, 'userid' => $userid, 'created_at' => date('Y-m-d H:i:s')]);
                } else {
                    Capsule::table(self::TBL_HOLDS)->where('site_id', $id)->where('userid', $userid)->delete();
                }
                $out['done'][] = $id;
            } catch (\Throwable $e) {
                $out['skipped'][] = ['id' => $id, 'reason' => 'error'];
            }
        }
        if ($out['done']) {
            self::log('reseller bulk ' . $action . ' of ' . count($out['done']) . ' sub-site(s) by client #' . $userid, $userid);
        }
        return $out;
    }

    /** Per-sub-site usage of the current month as CSV (formula-injection safe). @return array {filename, csv, month} */
    public static function exportCsv(int $userid, ?callable $factory = null): array
    {
        $rep = self::report($userid, $factory);
        $cell = function ($v): string {
            $v = (string) $v;
            if ($v !== '' && strpos('=+-@' . "\t\r", $v[0]) !== false) {
                $v = "'" . $v;
            }
            return '"' . str_replace('"', '""', $v) . '"';
        };
        $lines = [implode(',', array_map($cell, ['domain', 'label', 'month', 'gb', 'cost', 'currency', 'rate_per_gb', 'wallet_cut', 'paused']))];
        foreach ($rep['sites'] as $s) {
            $lines[] = implode(',', array_map($cell, [$s['domain'], $s['label'], $rep['month'], number_format((float) $s['gb'], 3, '.', ''),
                number_format((float) $s['cost'], 2, '.', ''), $rep['currency'], number_format((float) $rep['rate'], 2, '.', ''),
                $s['suspended'] ? 'yes' : 'no', !empty($s['held']) ? 'yes' : 'no']));
        }
        return ['filename' => 'reseller-usage-' . $rep['month'] . '.csv', 'csv' => "\xEF\xBB\xBF" . implode("\r\n", $lines) . "\r\n",
            'month' => $rep['month'], 'rows' => count($rep['sites']), 'error' => $rep['error']];
    }

    /** [credit, currency unit, currency→default rate] for a client. */
    public static function credit(int $userid): array
    {
        try {
            $client = Capsule::table('tblclients')->where('id', $userid)->first(['credit', 'currency']);
            $credit = $client ? round((float) $client->credit, 2) : 0.0;
            $cur = $client ? Capsule::table('tblcurrencies')->where('id', (int) $client->currency)->first(['code', 'suffix', 'rate']) : null;
            $unit = $cur ? (trim((string) $cur->suffix) !== '' ? trim((string) $cur->suffix) : (string) $cur->code) : '';
            $rate = $cur && (float) $cur->rate > 0 ? (float) $cur->rate : 1.0;
            return [$credit, $unit, $rate];
        } catch (\Throwable $e) {
            return [0.0, '', 1.0];
        }
    }

    private static function log(string $msg, int $userid = 0): void
    {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: ' . $msg, $userid);
        }
    }
}
