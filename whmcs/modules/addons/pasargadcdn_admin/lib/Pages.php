<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use WHMCS\Database\Capsule;

// SPEC §19.1 (before the guard: the class below is bound at compile time, so the guard always returns)
require_once __DIR__ . '/Operator.php';

if (class_exists(__NAMESPACE__ . '\\Pages', false)) {
    return;
}

/**
 * Renderers of the admin pages. Controller calls: ≤ 10 s each, parallel where
 * possible, and a page never fails as a whole when the controller is down —
 * the WHMCS-side data is still shown with a friendly error panel.
 */
final class Pages
{
    const TABS = [
        'dashboard' => ['داشبورد', 'dashboard'],
        'sites' => ['سایت‌ها', 'globe'],
        // SPEC §19.1: the platform's own domains (no WHMCS service)
        'operator' => ['دامنه‌های اپراتور', 'zap'],
        // SPEC §19.2: the transfer wizard (pick a domain, then destination, options, preview)
        'transfer' => ['انتقال دامنه', 'users'],
        // SPEC §21: per-domain feature overrides
        'features' => ['امکانات اختصاصی', 'sliders'],
        'edges' => ['نودها', 'server'],
        'plans' => ['پلن‌ها و قیمت‌گذاری', 'tag'],
        'analytics' => ['آنالیتیکس', 'chart'],
        'usage' => ['گزارش مصرف', 'wallet'],
        'resellers' => ['نمایندگان', 'users'],
        'events' => ['رویدادهای امنیتی', 'shield'],
        'status' => ['وضعیت و رخدادها', 'activity'],
        'health' => ['سلامت سامانه', 'heart'],
        'audit' => ['حسابرسی', 'history'],
        // Wave 10 (SPEC §18.5): referral ledger
        'referrals' => ['معرفی‌ها', 'users'],
        // SPEC §20.4: domain sharing
        'shares' => ['اشتراک‌ها', 'link'],
        // SPEC §23 (wave 14): releases / backups / abuse desk / SLO / provisioning — one tab with a sub-navigation (Ops::nav)
        'releases' => ['عملیات', 'sync'],
        'settings' => ['تنظیمات و سلامت', 'settings'],
    ];

    const INC_SEVERITY = ['minor' => ['کم‌اهمیت', 'warn'], 'major' => ['پراهمیت', 'bad'], 'maintenance' => ['تعمیرات', 'brand']];
    const INC_STATUS = ['investigating' => ['در حال بررسی', 'bad'], 'identified' => ['علت شناسایی شد', 'warn'],
        'monitoring' => ['در حال پایش', 'brand'], 'resolved' => ['برطرف شد', 'ok']];
    const OVERALL_STATUS = ['operational' => ['همه‌چیز عادی است', 'ok'], 'degraded' => ['اختلال جزئی', 'warn'],
        'maintenance' => ['تعمیرات برنامه‌ریزی‌شده', 'brand'], 'major_outage' => ['قطعی گسترده', 'bad']];
    const COMPONENT_STATUS = ['operational' => ['عادی', 'ok'], 'degraded' => ['اختلال جزئی', 'warn'],
        'partial_outage' => ['اختلال جزئی', 'warn'], 'maintenance' => ['تعمیرات', 'brand'], 'major_outage' => ['قطعی', 'bad']];

    const WHMCS_STATUS = [
        'Active' => ['فعال', 'ok'], 'Suspended' => ['معلق', 'bad'], 'Pending' => ['در انتظار', 'warn'],
        'Terminated' => ['حذف‌شده', 'muted'], 'Cancelled' => ['لغوشده', 'muted'], 'Fraud' => ['تقلب', 'muted'],
        'Completed' => ['تکمیل‌شده', 'muted'],
    ];
    const CDN_STATUS = [
        'active' => ['فعال', 'ok'], 'pending_ns' => ['در انتظار NS', 'warn'], 'suspended' => ['معلق', 'bad'],
        'over_quota' => ['اتمام ترافیک', 'bad'],
    ];
    const SOURCES = ['waf' => 'WAF', 'firewall' => 'فایروال', 'ratelimit' => 'محدودیت نرخ', 'ddos' => 'DDoS', 'hotlink' => 'هات‌لینک'];
    const ACTIONS = ['block' => ['مسدود', 'bad'], 'challenge' => ['چالش JS', 'warn'], 'captcha' => ['کپچا', 'warn'], 'log' => ['ثبت', 'muted']];

    /** @var array memo of controller results for this request */
    private static $ctl = [];

    public static function reset(): void
    {
        self::$ctl = [];
        self::$multiSites = 0;
        self::$drainForce = 0;
        self::$drainForceIn = [];
    }

    // ------------------------------------------------------------------ layout

    public static function assetBase(): string
    {
        // Admin pages live in <whmcs>/<admin dir>/, one level below the WHMCS root.
        return '../modules/addons/pasargadcdn_admin/assets';
    }

    private static function assetUrl(string $f): string
    {
        return self::assetBase() . '/' . $f . '?v=' . (string) @filemtime(dirname(__DIR__) . '/assets/' . $f);
    }

    public static function layout(string $page, string $body, array $flash, string $cleanUrl = ''): string
    {
        $h = '<link rel="stylesheet" href="' . View::e(self::assetUrl('admin.css')) . '">';
        $h .= '<div class="pcdna" dir="rtl" lang="fa" data-page="' . View::e($page) . '"'
            . ($cleanUrl !== '' ? ' data-clean-url="' . View::e($cleanUrl) . '"' : '') . '>';
        $h .= '<header class="pcdna-head"><div class="pcdna-brand"><span class="pcdna-logo">' . View::icon('zap') . '</span><div>'
            . '<h2>مدیریت CDN پاسارگاد</h2><p>سایت‌ها، نودها، پلن‌ها و گزارش‌های CDN در یک‌جا</p></div></div>'
            . self::serverChip() . '</header>';
        $h .= '<nav class="pcdna-tabs" aria-label="بخش‌های مدیریت CDN">';
        foreach (self::TABS as $id => [$label, $icon]) {
            $cur = $id === $page || ($page === 'manage' && $id === 'sites') || ($page === 'opmanage' && $id === 'operator')
                || ($id === 'releases' && in_array($page, ['backups', 'abuse', 'slo', 'provisioning'], true));
            $h .= '<a class="pcdna-tab' . ($cur ? ' is-active' : '') . '" href="' . View::url(['page' => $id]) . '"'
                . ($cur ? ' aria-current="page"' : '') . '>' . View::icon($icon) . '<span>' . View::e($label) . '</span></a>';
        }
        $h .= '</nav><div class="pcdna-body">';
        foreach ($flash as [$tone, $html]) {
            $h .= View::alert($tone, $html);
        }
        $h .= $body . '</div></div>';
        $h .= '<script src="' . View::e(self::assetUrl('admin.js')) . '" defer></script>';
        return $h;
    }

    private static function serverChip(): string
    {
        $s = Env::server();
        if (!$s) {
            return '<a class="pcdna-chip pcdna-t-bad" href="configservers.php">' . View::icon('warn') . '<span>سرور CDN تعریف نشده</span></a>';
        }
        return '<span class="pcdna-chip" title="سرور WHMCS #' . (int) $s->id . '">' . View::icon('server') . '<span>'
            . View::e($s->name ?: 'Pasargad CDN') . '</span>' . View::ltr(preg_replace('#^https?://#', '', Env::controllerUrl($s))) . '</span>';
    }

    // ------------------------------------------------------------------ controller helpers

    /** GET /api/v1/ping with latency. ['ok', 'code', 'ms', 'data', 'error'] (code -1 = not configured). */
    public static function ping(): array
    {
        if (isset(self::$ctl['ping'])) {
            return self::$ctl['ping'];
        }
        try {
            $api = Env::api(10);
        } catch (\Throwable $e) {
            return self::$ctl['ping'] = ['ok' => false, 'code' => -1, 'ms' => 0, 'data' => [], 'error' => $e->getMessage()];
        }
        $t = microtime(true);
        $r = $api->getMany(['/api/v1/ping'])['/api/v1/ping'];
        $ms = (int) round((microtime(true) - $t) * 1000);
        $ok = $r['code'] === 200 && !empty($r['data']['ok']);
        $err = $r['error'];
        if (!$ok && in_array($r['code'], [401, 403], true)) {
            $err = 'کلید API نامعتبر است (کنترلر پاسخ ' . $r['code'] . ' داد). مقدار Access Hash سرور را با ADMIN_API_KEY کنترلر مقایسه کنید.';
        } elseif (!$ok && $r['code'] === 0) {
            $err = 'کنترلر در دسترس نیست: ' . ($r['error'] ?: 'بدون پاسخ');
        } elseif (!$ok) {
            $err = $err ?: 'پاسخ نامعتبر از کنترلر (HTTP ' . $r['code'] . ')';
        }
        return self::$ctl['ping'] = ['ok' => $ok, 'code' => $r['code'], 'ms' => $ms, 'data' => is_array($r['data']) ? $r['data'] : [],
            'error' => $ok ? null : $err];
    }

    /** Parallel GETs; only when ping succeeded. */
    public static function fetch(array $paths): array
    {
        $ping = self::ping();
        $out = [];
        $todo = [];
        foreach ($paths as $p) {
            if (isset(self::$ctl['get:' . $p])) {
                $out[$p] = self::$ctl['get:' . $p];
            } else {
                $todo[] = $p;
            }
        }
        if ($todo) {
            if (!$ping['ok']) {
                foreach ($todo as $p) {
                    $out[$p] = ['code' => 0, 'data' => null, 'error' => $ping['error']];
                }
                return $out;
            }
            foreach (Env::api(10)->getMany($todo) as $p => $r) {
                self::$ctl['get:' . $p] = $r;
                $out[$p] = $r;
            }
        }
        return $out;
    }

    /** SPEC §19.1: lower-case operator domains => true from a fetch() result of Operator::LIST ([] when unavailable). */
    public static function operatorSet(array $r): array
    {
        $out = [];
        if (self::ok($r)) {
            foreach ((array) $r['data'] as $x) {
                if (Data::isOperator($x) && is_string($x['domain'] ?? null)) {
                    $out[strtolower($x['domain'])] = true;
                }
            }
        }
        return $out;
    }

    public static function ok(array $r): bool
    {
        return ($r['code'] ?? 0) >= 200 && ($r['code'] ?? 0) < 300 && is_array($r['data'] ?? null);
    }

    public static function ctlError(array $ping): string
    {
        if ($ping['code'] === -1) {
            return View::alert('bad', '<strong>سرور CDN تنظیم نشده است.</strong> ' . View::e($ping['error'])
                . ' <a href="configservers.php">افزودن سرور</a> (ماژول Pasargad CDN، Access Hash = ADMIN_API_KEY).');
        }
        $hint = $ping['code'] === 401 || $ping['code'] === 403 ? '' : ' آدرس (Hostname)، تیک Secure و فایروال بین WHMCS و کنترلر را بررسی کنید.';
        return View::alert('bad', '<strong>ارتباط با کنترلر CDN برقرار نشد.</strong> ' . View::e((string) $ping['error']) . View::e($hint)
            . ' <a href="' . View::url(['page' => 'settings']) . '">بررسی سلامت</a>');
    }

    // ------------------------------------------------------------------ shared bits

    public static function whmcsBadge(string $s): string
    {
        [$t, $tone] = self::WHMCS_STATUS[$s] ?? [$s, 'muted'];
        return View::badge($t, $tone);
    }

    public static function cdnBadge(?string $s): string
    {
        if ($s === null) {
            return View::badge('روی CDN نیست', 'bad-soft');
        }
        [$t, $tone] = self::CDN_STATUS[$s] ?? [$s, 'muted'];
        return View::badge($t, $tone);
    }

    public static function manageUrl(int $sid): string
    {
        return View::url(['page' => 'manage', 'service' => $sid]);
    }

    /** Included traffic of a service row (WHMCS soft limit with overage, else the plan/controller limit). */
    private static function includedGb($svc, ?array $site): float
    {
        $o = function_exists('pasargadcdn_overage') ? \pasargadcdn_overage((array) $svc) : null;
        if ($o !== null) {
            return (float) $o['included_gb'];
        }
        if ($site && isset($site['bandwidth_limit_gb'])) {
            return (float) $site['bandwidth_limit_gb'];
        }
        return (float) ($svc->plan_gb ?? 0);
    }

    /**
     * Configuration warnings shown on the dashboard.
     * @return array list of [tone, html]
     */
    public static function warnings(array $ping, ?array $overview, ?array $sites): array
    {
        $w = [];
        if (!Env::server()) {
            $w[] = ['bad', 'هیچ سروری از نوع Pasargad CDN تعریف نشده است. <a href="configservers.php">افزودن سرور</a>'];
        } elseif (!$ping['ok']) {
            $w[] = ['bad', $ping['code'] === 401 || $ping['code'] === 403 ? 'کلید API سرور CDN نامعتبر است.' : 'کنترلر CDN در دسترس نیست.'];
        }
        $products = Data::products();
        if (!$products) {
            $w[] = ['warn', 'هنوز محصولی با ماژول Pasargad CDN ساخته نشده است. <a href="' . View::url(['page' => 'plans']) . '#wizard">راه‌اندازی خودکار محصولات</a>'];
        }
        foreach ($products as $p) {
            if ((int) $p->servergroup <= 0) {
                $w[] = ['warn', 'محصول «' . View::e($p->name) . '» گروه سرور ندارد؛ سفارش‌های آن روی CDN ساخته نمی‌شوند. <a href="configproducts.php?action=edit&amp;id='
                    . (int) $p->id . '">ویرایش محصول</a> (تب Module Settings)'];
            }
        }
        if ($overview) {
            $e = $overview['edges'] ?? [];
            if ((int) ($e['online'] ?? 0) === 0) {
                $w[] = ['bad', 'هیچ نود آنلاینی وجود ندارد؛ رکوردهای پروکسی سایت‌ها به هیچ نودی اشاره نمی‌کنند. <a href="' . View::url(['page' => 'edges']) . '">نودها</a>'];
            } elseif ((int) ($e['online'] ?? 0) < (int) ($e['enabled'] ?? 0)) {
                $w[] = ['warn', View::n((int) $e['enabled'] - (int) $e['online']) . ' نود فعال آفلاین است. <a href="' . View::url(['page' => 'edges']) . '">بررسی نودها</a>'];
            }
            if ((int) ($e['with_errors'] ?? 0) > 0) {
                $w[] = ['warn', View::n($e['with_errors']) . ' نود خطای اعمال تنظیمات دارد (last_error).'];
            }
        }
        if ($sites !== null && ($cut = self::cutForCredit($sites))) {
            $w[] = ['warn', View::n($cut) . ' سرویس پیش‌پرداخت به‌دلیل اعتبار ناکافی کیف پول قطع است (پس از شارژ مشتری خودکار وصل می‌شود). <a href="'
                . View::url(['page' => 'sites', 'cdn' => 'over_quota']) . '">مشاهده</a>'];
        }
        if ($sites !== null) {
            $sync = Data::sync($sites);
            if ($sync['missing']) {
                $w[] = ['warn', View::n(count($sync['missing'])) . ' سرویس فعال/معلق WHMCS روی کنترلر سایت ندارد. <a href="'
                    . View::url(['page' => 'sites', 'view' => 'sync']) . '">گزارش همگام‌سازی</a>'];
            }
            if ($sync['conflicts']) {
                $w[] = ['bad', View::n(count($sync['conflicts'])) . ' سرویس WHMCS دامنه‌ای دارد که روی کنترلر به سرویس دیگری تعلق دارد. <a href="'
                    . View::url(['page' => 'sites', 'view' => 'sync']) . '">گزارش همگام‌سازی</a>'];
            }
            if ($sync['orphans']) {
                $w[] = ['warn', View::n(count($sync['orphans'])) . ' سایت روی کنترلر هست که سرویس فعالی در WHMCS ندارد. <a href="'
                    . View::url(['page' => 'sites', 'view' => 'sync']) . '">گزارش همگام‌سازی</a>'];
            }
        }
        return $w;
    }

    /** Number of live prepaid services whose site is over its cap (= cut until the wallet covers a block). */
    public static function cutForCredit(array $sites): int
    {
        $ids = [];
        foreach ($sites as $s) {
            if (is_array($s) && ($s['status'] ?? '') === 'over_quota' && ctype_digit((string) ($s['external_id'] ?? ''))) {
                $ids[] = (int) $s['external_id'];
            }
        }
        if (!$ids) {
            return 0;
        }
        $n = 0;
        $rows = Data::serviceQuery()->whereIn('h.id', $ids)->where('h.domainstatus', 'Active')->get(Data::SERVICE_COLS)->all();
        $co = Data::configOptions($rows);
        foreach ($rows as $svc) {
            $n += Data::prepaid($svc, $co[(int) $svc->id] ?? []) !== null ? 1 : 0;
        }
        return $n;
    }

    // ------------------------------------------------------------------ 1. dashboard

    public static function dashboard(): string
    {
        $ping = self::ping();
        $ov = $edges = $events = $sites = $alerts = null;
        $ctlVersion = '';
        if ($ping['ok']) {
            // SPEC §23.1: /healthz carries the controller's platform version (`version`, wave 14)
            $r = self::fetch(['/api/v1/overview', '/api/v1/edges', '/api/v1/events?limit=8', '/api/v1/sites', '/api/v1/alerts/status', '/healthz',
                '/api/v1/storage/capacity']);
            $ctlVersion = self::ok($r['/healthz']) && is_string($r['/healthz']['data']['version'] ?? null) ? (string) $r['/healthz']['data']['version'] : '';
            $ov = self::ok($r['/api/v1/overview']) ? $r['/api/v1/overview']['data'] : null;
            $edges = self::ok($r['/api/v1/edges']) ? $r['/api/v1/edges']['data'] : null;
            $events = self::ok($r['/api/v1/events?limit=8']) ? $r['/api/v1/events?limit=8']['data'] : null;
            $sites = self::ok($r['/api/v1/sites']) ? $r['/api/v1/sites']['data'] : null;
            $alerts = self::ok($r['/api/v1/alerts/status']) ? $r['/api/v1/alerts/status']['data'] : null;
            // SPEC §16.8: the storage server's own disk against the data it holds and the space sold
            $cap = self::ok($r['/api/v1/storage/capacity']) ? $r['/api/v1/storage/capacity']['data'] : null;
        }
        $counts = Data::statusCounts();
        $h = '';
        if (!$ping['ok']) {
            $h .= self::ctlError($ping);
        }

        // KPIs
        $by = (array) ($ov['sites']['by_status'] ?? []);
        $sec = 0;
        foreach ((array) ($ov['month']['security'] ?? []) as $v) {
            $sec += (int) $v;
        }
        $na = '<span class="pcdna-muted">—</span>';
        $h .= '<div class="pcdna-kpis">';
        // SPEC §19.1: operator sites are counted separately (they are platform sites, not customers')
        $opN = isset($ov['sites']['by_owner']['operator']) ? (int) $ov['sites']['by_owner']['operator']
            : ($sites !== null ? count(array_filter($sites, [Data::class, 'isOperator'])) : 0);
        $h .= View::kpi('globe', 'brand', 'سایت‌های روی CDN', $ov ? View::n($ov['sites']['total'] ?? 0) : $na,
            ($ov ? View::n($by['active'] ?? 0) . ' فعال · ' . View::n($by['pending_ns'] ?? 0) . ' در انتظار NS · '
                . View::n(($by['suspended'] ?? 0) + ($by['over_quota'] ?? 0)) . ' متوقف' : 'داده کنترلر در دسترس نیست')
            . ($opN ? '<br><a href="' . View::url(['page' => 'operator']) . '" data-operator-count="' . $opN . '">' . View::n($opN) . ' دامنهٔ اپراتور (بدون صورت‌حساب)</a>' : ''));
        $eOn = (int) ($ov['edges']['online'] ?? 0);
        $eEn = (int) ($ov['edges']['enabled'] ?? 0);
        $h .= View::kpi('server', $ov && $eOn > 0 && $eOn >= $eEn ? 'ok' : 'bad', 'نودهای آنلاین',
            $ov ? View::n($eOn) . ' <small>از ' . View::n($eEn) . '</small>' : $na,
            $ov ? View::n($ov['edges']['total'] ?? 0) . ' نود ثبت‌شده' : '');
        $h .= View::kpi('activity', 'violet', 'ترافیک این ماه', $ov ? View::bytes($ov['month']['bytes'] ?? 0) : $na,
            $ov ? View::n($ov['month']['requests'] ?? 0) . ' درخواست' : '');
        $h .= View::kpi('shield', 'bad', 'تهدیدهای متوقف‌شده', $ov ? View::n($sec) : $na, 'این ماه، همه سایت‌ها');
        $cutN = $sites !== null ? self::cutForCredit($sites) : 0;
        $h .= View::kpi('users', 'brand', 'سرویس‌های WHMCS', View::n($counts['Active'] ?? 0) . ' <small>فعال</small>',
            View::n($counts['Suspended'] ?? 0) . ' معلق · ' . View::n($counts['Pending'] ?? 0) . ' در انتظار'
            . ($cutN ? '<br><span class="pcdna-err" data-cut-credit="' . $cutN . '">' . View::n($cutN) . ' قطع به‌دلیل اعتبار</span>' : ''));
        $h .= '</div>';

        // tunnel mode: tunnel services (WHMCS) + live load of the tunnel edge group
        $tn = Data::tunnelServices();
        if ($tn > 0 || ($edges && self::groupTotals($edges)['tunnel']['edges'] > 0)) {
            $gt = $edges ? self::groupTotals($edges)['tunnel'] : null;
            $h .= '<div class="pcdna-kpis pcdna-kpis-tunnel" data-tunnel-kpis="1">'
                . View::kpi('zap', 'violet', 'سرویس‌های تونل فعال', View::n($tn), 'پلن‌های تونل / VPN در WHMCS')
                . View::kpi('server', $gt && $gt['online'] > 0 ? 'ok' : 'bad', 'نودهای گروه تونل', $gt ? View::n($gt['online']) . ' <small>از ' . View::n($gt['edges']) . '</small>' : $na,
                    $gt && $gt['online'] === 0 ? 'بدون نود تونل: سایت‌های تونل به همه نودها می‌روند' : 'آنلاین')
                . View::kpi('activity', 'brand', 'ترافیک لحظه‌ای تونل', $gt ? View::e('↓' . self::mbps($gt['rx']) . ' ↑' . self::mbps($gt['tx'])) : $na,
                    $gt && $gt['cap'] > 0 ? 'ظرفیت ' . View::e(self::mbps($gt['cap'])) . ' (' . View::n(max($gt['rx'], $gt['tx']) * 100 / $gt['cap']) . '٪)' : '')
                . View::kpi('users', 'brand', 'اتصال‌های همزمان تونل', $gt ? View::n($gt['conns']) : $na, 'مجموع نودهای گروه تونل')
                . '</div>';
        }

        // warnings
        $warn = self::warnings($ping, $ov, $sites);
        // SPEC §23.10: open abuse reports (overview.abuse_open, wave 14)
        if ((int) ($ov['abuse_open'] ?? 0) > 0) {
            $warn[] = ['warn', View::n((int) $ov['abuse_open']) . ' گزارش تخلف باز منتظر رسیدگی است. <a href="' . View::url(['page' => 'abuse']) . '" data-abuse-open="' . (int) $ov['abuse_open'] . '">گزارش‌های تخلف</a>'];
        }
        $capPct = is_array($cap ?? null) && is_array($cap['disk'] ?? null) ? $cap['disk']['percent_used'] ?? null : null;
        if (is_numeric($capPct) && (float) $capPct >= 85) {
            $warn[] = [(float) $capPct >= 95 ? 'bad' : 'warn', 'دیسک سرور فضای ذخیره‌سازی ' . View::n((float) $capPct, 1)
                . '٪ پر است (' . View::bytes($cap['disk']['free'] ?? 0) . ' آزاد). فضا اضافه کنید یا فروش فضای جدید را متوقف کنید.'];
        }
        foreach (self::saturated((array) $edges) as $e) {
            $warn[] = [!empty($e['shed']) ? 'bad' : 'warn', 'نود ' . View::ltr($e['name'] ?? '') . (!empty($e['shed']) ? ' اشباع شده و موقتاً از DNS خارج است.' : ' بیش از ۸۰٪ ظرفیت بار دارد.')
                . ' <a href="' . View::url(['page' => 'edges']) . '">نودها</a>'];
        }
        $wh = '';
        if ($warn) {
            $wh .= '<ul class="pcdna-warnlist">';
            foreach ($warn as [$tone, $html]) {
                $wh .= '<li class="pcdna-w-' . $tone . '">' . View::icon($tone === 'bad' ? 'x' : 'warn') . '<span>' . $html . '</span></li>';
            }
            $wh .= '</ul>';
        } else {
            $wh = '<p class="pcdna-okline">' . View::icon('check') . '<span>پیکربندی کامل است؛ هشداری وجود ندارد.</span></p>';
        }

        // controller status
        if ($ping['ok']) {
            $ns = (array) ($ov['nameservers'] ?? $ping['data']['nameservers'] ?? []);
            $st = '<dl class="pcdna-dl">'
                . '<div><dt>وضعیت</dt><dd>' . View::badge('در دسترس', 'ok') . '</dd></div>'
                . '<div><dt>زمان پاسخ</dt><dd>' . View::n($ping['ms']) . ' میلی‌ثانیه</dd></div>'
                . '<div><dt>نشانی</dt><dd>' . View::ltr(Env::controllerUrl()) . '</dd></div>'
                . ($ctlVersion !== '' ? '<div data-ctl-version="' . View::e($ctlVersion) . '"><dt>نسخهٔ کنترلر</dt><dd>' . View::ltr('v' . ltrim($ctlVersion, 'v'), 'pcdna-code') . '</dd></div>' : '')
                . '<div><dt>نیم‌سرورها</dt><dd>' . ($ns ? implode(' ', array_map(function ($n) {
                    return View::ltr($n, 'pcdna-code');
                }, $ns)) : '—') . '</dd></div></dl>';
        } else {
            $st = '<dl class="pcdna-dl"><div><dt>وضعیت</dt><dd>' . View::badge('قطع', 'bad') . '</dd></div>'
                . '<div><dt>نشانی</dt><dd>' . (Env::server() ? View::ltr(Env::controllerUrl()) : '—') . '</dd></div></dl>';
        }
        $h .= '<div class="pcdna-grid-2">' . View::card('وضعیت کنترلر', $st, '', '', 'activity')
            . View::card('هشدارهای پیکربندی', $wh, '', '', 'warn') . '</div>';

        // edges health
        $healthBody = $edges === null ? '<p class="pcdna-muted">فهرست نودها در دسترس نیست.</p>'
            : self::healthSummary($edges, $alerts) . self::edgeTable($edges, false);
        $h .= View::card('سلامت نودها', $healthBody,
            '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::url(['page' => 'edges', 'view' => 'availability']) . '">' . View::icon('activity') . '<span>گزارش در دسترس‌بودن</span></a>'
            . '<a class="pcdna-btn pcdna-btn-sm" href="' . View::url(['page' => 'edges']) . '">مدیریت نودها</a>', '', 'server');

        // SPEC §16.8: object-storage capacity — what the server has, holds and has been sold
        if (is_array($cap) && !empty($cap['available'])) {
            $h .= View::card('فضای ذخیره‌سازی (سرور S3)', self::storageCapacity($cap), '', '', 'package');
        }

        // top sites + latest events
        $byDomain = Data::servicesByDomain();
        $opDomains = [];
        foreach ((array) $sites as $x) {
            if (Data::isOperator($x)) {
                $opDomains[strtolower((string) $x['domain'])] = true;
            }
        }
        $top = '';
        if ($ov && !empty($ov['top_sites'])) {
            $top .= '<div class="pcdna-table-wrap"><table class="pcdna-table"><thead><tr><th>دامنه</th><th>ترافیک</th><th>درخواست</th><th></th></tr></thead><tbody>';
            $max = max(1, (float) ($ov['top_sites'][0]['bytes'] ?? 1));
            foreach (array_slice($ov['top_sites'], 0, 10) as $s) {
                $isOp = isset($opDomains[strtolower((string) ($s['domain'] ?? ''))]);
                $svc = $isOp ? null : ($byDomain[strtolower((string) ($s['domain'] ?? ''))] ?? null);
                $top .= '<tr><td>' . View::ltr($s['domain'] ?? '?') . '</td><td class="pcdna-num">' . View::bytes($s['bytes'] ?? 0)
                    . View::meter((float) ($s['bytes'] ?? 0) / $max, 'brand') . '</td><td class="pcdna-num">' . View::n($s['requests'] ?? 0) . '</td><td class="pcdna-actions">'
                    . ($svc ? '<a class="pcdna-btn pcdna-btn-sm" href="' . self::manageUrl((int) $svc->id) . '">مدیریت</a>'
                        . '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::e(Data::serviceUrl((int) $svc->userid, (int) $svc->id))
                        . '" title="صفحه سرویس در WHMCS">#' . (int) $svc->id . '</a>'
                        : ($isOp ? '<a class="pcdna-btn pcdna-btn-sm" href="' . View::url(['page' => 'opmanage', 'domain' => strtolower((string) $s['domain'])]) . '">مدیریت</a>'
                            . View::badge('اپراتور', 'violet') : View::badge('بدون سرویس', 'muted')))
                    . '</td></tr>';
            }
            $top .= '</tbody></table></div>';
        } else {
            $top = View::emptyState('هنوز ترافیکی ثبت نشده است', 'پس از تغییر NS مشتری‌ها و عبور ترافیک از نودها، پرترافیک‌ترین سایت‌ها اینجا نمایش داده می‌شوند.', 'chart');
        }
        $ev = $events === null ? '<p class="pcdna-muted">رویدادها در دسترس نیست.</p>' : ($events ? self::eventTable($events, $byDomain, true)
            : View::emptyState('رویدادی ثبت نشده است', '', 'shield'));
        $h .= '<div class="pcdna-grid-2">' . View::card('پرترافیک‌ترین سایت‌های این ماه', $top, '', '', 'chart')
            . View::card('آخرین رویدادهای امنیتی', $ev, '<a class="pcdna-btn pcdna-btn-sm" href="' . View::url(['page' => 'events']) . '">همه رویدادها</a>', '', 'shield')
            . '</div>';
        return $h;
    }

    // ------------------------------------------------------------------ edges table (dashboard + edges page)

    public static function edgeOnline(array $e): bool
    {
        if (empty($e['enabled']) || empty($e['last_seen_at'])) {
            return false;
        }
        $t = strtotime((string) $e['last_seen_at']);
        return $t !== false && time() - $t <= 180;
    }

    /**
     * True when the node reports a bundle version that is behind the controller's current bundle
     * (SPEC §11.1). If either version is unknown, returns false so no badge is shown.
     */
    public static function edgeOutdated(array $e, ?string $bundle): bool
    {
        $running = trim((string) ($e['bundle_version'] ?? ''));
        return $bundle !== null && $bundle !== '' && $running !== '' && $running !== $bundle;
    }

    const EDGE_GROUPS = ['general' => ['عمومی', 'muted'], 'tunnel' => ['تونل', 'violet']];

    /**
     * Load of an edge from its latest heartbeat metrics (SPEC §7.4).
     * @return array ['pct' => float|null (max(rx,tx) / capacity), 'peak' => Mbps, 'fresh' => bool, 'm' => metrics|null]
     */
    public static function edgeLoad(array $e): array
    {
        $m = is_array($e['metrics'] ?? null) ? $e['metrics'] : null;
        $t = $m && !empty($m['at']) ? strtotime((string) $m['at']) : false;
        $fresh = $m !== null && $t !== false && time() - $t <= 180;
        $peak = $m ? max((float) ($m['rx_mbps'] ?? 0), (float) ($m['tx_mbps'] ?? 0)) : 0.0;
        $cap = (int) ($e['capacity_mbps'] ?? 0);
        return ['pct' => $fresh && $cap > 0 ? $peak * 100 / $cap : null, 'peak' => $peak, 'fresh' => $fresh, 'm' => $m];
    }

    /** Edges that are shed from DNS or above 80 % of their capacity. */
    public static function saturated(array $edges): array
    {
        return array_values(array_filter($edges, function ($e) {
            if (!is_array($e) || empty($e['enabled'])) {
                return false;
            }
            $l = self::edgeLoad($e);
            return !empty($e['shed']) || ($l['pct'] !== null && $l['pct'] > 80);
        }));
    }

    private static function mbps($v): string
    {
        $v = (float) $v;
        return $v >= 1000 ? View::n($v / 1000, 1) . ' Gbps' : View::n($v, $v < 10 ? 1 : 0) . ' Mbps';
    }

    /**
     * SPEC §16.8: the object-storage server's capacity (/api/v1/storage/capacity). Three different
     * numbers on purpose — the disk is the whole filesystem (so `used` includes anything else on it
     * and is what decides when to add space), the data is the customers' objects, and the sold figure
     * is the sum of every plan's storage_gb, which may exceed the disk on purpose.
     */
    public static function storageCapacity(array $cap): string
    {
        $disk = is_array($cap['disk'] ?? null) ? $cap['disk'] : null;
        $data = (int) ($cap['data_bytes'] ?? 0);
        $sold = (int) ($cap['sold_bytes'] ?? 0);
        $h = '';
        if ($disk !== null) {
            $total = (int) ($disk['total'] ?? 0);
            $used = (int) ($disk['used'] ?? 0);
            $pct = $total > 0 ? $used / $total : 0.0;
            $h .= '<div class="pcdna-cap"><div class="pcdna-cap-head"><strong>' . View::bytes($used) . '</strong>'
                . ' <span class="pcdna-muted">از ' . View::bytes($total) . ' دیسک سرور'
                . (($disk['source'] ?? '') === 'configured' ? ' (مقدار اعلامی اپراتور)' : '') . '</span>'
                . '<span class="pcdna-cap-pct">' . View::n($pct * 100, 1) . '٪</span></div>'
                . View::meter($pct) . '</div>';
        }
        $rows = [];
        if ($disk !== null) {
            $rows['فضای آزاد دیسک'] = View::bytes($disk['free'] ?? 0);
        }
        $rows['دادهٔ مشتری‌ها'] = View::bytes($data)
            . ' <span class="pcdna-muted">(' . View::n($cap['buckets'] ?? 0) . ' باکت · '
            . View::n($cap['objects'] ?? 0) . ' فایل)</span>'
            . (!empty($cap['data_stale']) ? ' ' . View::badge('قدیمی', 'warn') : '');
        $rows['فروخته‌شده (جمع پلن‌ها)'] = View::bytes($sold)
            . ' <span class="pcdna-muted">روی ' . View::n($cap['sites_with_storage'] ?? 0) . ' سرویس</span>'
            . ($disk !== null && $sold > (int) ($disk['total'] ?? 0)
                ? ' ' . View::badge('بیش از ظرفیت دیسک', 'warn') : '');
        if (!empty($cap['endpoint'])) {
            $rows['نشانی سرور'] = View::ltr((string) $cap['endpoint'], 'pcdna-code');
        }
        $h .= '<dl class="pcdna-dl">';
        foreach ($rows as $k => $v) {
            $h .= '<div><dt>' . $k . '</dt><dd>' . $v . '</dd></div>';
        }
        $h .= '</dl>';
        if ($disk === null) {
            $h .= View::alert('warn', 'سرور ذخیره‌سازی اندازهٔ دیسکش را گزارش نکرد'
                . (!empty($cap['disk_error']) ? ' (' . View::e(View::clip((string) $cap['disk_error'], 120)) . ')' : '')
                . '. برای دیدن ظرفیت، مسیر وضعیت را روی سرور ذخیره‌سازی باز کنید '
                . '(<span class="pcdna-code" dir="ltr">STORAGE_STATUS_PATH</span>، بخش ۴ راهنمای فضای ذخیره‌سازی)'
                . ' یا ظرفیت را دستی در <span class="pcdna-code" dir="ltr">STORAGE_CAPACITY_GB</span> بنویسید.');
        }
        return $h;
    }

    private static function loadCell(array $e): string
    {
        $l = self::edgeLoad($e);
        $m = $l['m'];
        if (!$m) {
            return '<span class="pcdna-muted pcdna-small">بدون گزارش بار</span>';
        }
        $cap = (int) ($e['capacity_mbps'] ?? 0);
        $pct = $l['pct'];
        $tone = !empty($e['shed']) || ($pct !== null && $pct >= 90) ? 'bad' : ($pct !== null && $pct > 80 ? 'warn' : 'brand');
        $h = '<div class="pcdna-load" data-load="' . ($pct === null ? '' : (int) round($pct)) . '">'
            . '<div class="pcdna-load-top"><span class="pcdna-num" dir="ltr">↓' . View::e(self::mbps($m['rx_mbps'] ?? 0)) . ' ↑' . View::e(self::mbps($m['tx_mbps'] ?? 0)) . '</span>'
            . ($pct !== null ? '<strong class="pcdna-load-pct pcdna-c-' . $tone . '">' . View::n($pct, 0) . '٪</strong>' : '') . '</div>'
            . ($cap > 0 ? View::meter(min(1, $l['peak'] / $cap), $tone) : '')
            . '<div class="pcdna-small pcdna-muted">' . View::n($m['connections'] ?? 0) . ' اتصال · بار ' . View::n($m['load1'] ?? 0, 1)
            . (!empty($m['cpus']) ? '/' . View::n($m['cpus']) : '') . ' · ' . ($cap > 0 ? 'ظرفیت ' . View::e(self::mbps($cap)) : 'ظرفیت نامشخص')
            . ' · ' . View::e(View::ago($m['at'] ?? null)) . '</div>';
        if (!empty($e['shed'])) {
            $h .= View::badge('خارج از DNS (اشباع)', 'bad', ' title="بار این نود از آستانه گذشته و تا کاهش بار در پاسخ DNS قرار نمی‌گیرد" data-shed="1"');
        } elseif (!$l['fresh']) {
            $h .= View::badge('گزارش قدیمی', 'muted');
        }
        return $h . '</div>';
    }

    /** Colour token for an availability percentage (token palette only). */
    public static function uptimeTone(float $pct): string
    {
        if ($pct >= 99.9) {
            return 'ok';
        }
        if ($pct >= 99.0) {
            return 'brand';
        }
        if ($pct >= 95.0) {
            return 'warn';
        }
        return 'bad';
    }

    /**
     * 24h + 30d availability of an edge (from the edge object's `uptime`), plus an
     * optional 30-day daily sparkline when the caller supplies the daily series.
     */
    private static function uptimeCell(array $e, ?array $days = null): string
    {
        $up = is_array($e['uptime'] ?? null) ? $e['uptime'] : null;
        if ($up === null) {
            return '<span class="pcdna-muted pcdna-small">بدون داده</span>';
        }
        $h24 = (float) ($up['h24'] ?? 0);
        $d30 = (float) ($up['d30'] ?? 0);
        $h = '<div class="pcdna-uptime" data-uptime-h24="' . View::n($h24, 2) . '" data-uptime-d30="' . View::n($d30, 2) . '">'
            . '<div class="pcdna-uptime-row"><span class="pcdna-small pcdna-muted">۲۴ ساعت</span>'
            . View::badge(View::n($h24, 2) . '٪', self::uptimeTone($h24), ' title="در دسترس‌بودن ۲۴ ساعت گذشته"') . '</div>'
            . '<div class="pcdna-uptime-row"><span class="pcdna-small pcdna-muted">۳۰ روز</span>'
            . View::badge(View::n($d30, 2) . '٪', self::uptimeTone($d30), ' title="در دسترس‌بودن ۳۰ روز گذشته"') . '</div>';
        if ($days) {
            $h .= self::uptimeSpark($days);
        }
        return $h . '</div>';
    }

    /** Compact inline-SVG bar sparkline of daily uptime (last 30 days), token colours only. */
    public static function uptimeSpark(array $days): string
    {
        $days = array_slice(array_values(array_filter($days, 'is_array')), -30);
        $n = count($days);
        if ($n === 0) {
            return '';
        }
        $bw = 3;
        $gap = 1;
        $hgt = 24;
        $w = $n * ($bw + $gap);
        $bars = '';
        foreach ($days as $i => $d) {
            $v = (float) ($d['uptime'] ?? 0);
            $ratio = max(0.0, min(1.0, ($v - 90.0) / 10.0)); // 90..100% mapped to the visible range
            $bh = max(2.0, round($ratio * ($hgt - 2), 1));
            $var = $v >= 99.5 ? '--a-ok' : ($v >= 98.0 ? '--a-warn' : '--a-bad');
            $x = $i * ($bw + $gap);
            $bars .= '<rect x="' . $x . '" y="' . round($hgt - $bh, 1) . '" width="' . $bw . '" height="' . $bh . '" rx="1" fill="var(' . $var . ')">'
                . '<title>' . View::e((string) ($d['day'] ?? '') . ' — ' . View::n($v, 2) . '٪') . '</title></rect>';
        }
        return '<svg class="pcdna-spark" width="' . $w . '" height="' . $hgt . '" viewBox="0 0 ' . $w . ' ' . $hgt
            . '" role="img" aria-label="نمودار در دسترس‌بودن ۳۰ روز اخیر" preserveAspectRatio="none">' . $bars . '</svg>';
    }

    /** Node capabilities reported in the heartbeat (SPEC §14.1): key => [badge, tooltip]. */
    const EDGE_CAPS = [
        'http3' => ['HTTP/3', 'این نود HTTP/3 (QUIC) را پشتیبانی می‌کند'],
        'early_hints' => ['Early Hints', 'این نود پاسخ 103 Early Hints را برای Preload پشتیبانی می‌کند'],
        'webp_convert' => ['WebP', 'این نود تصاویر JPEG/PNG را خودش به WebP تبدیل می‌کند'],
        // SPEC §14.3: agents of Wave 6D and later
        'live_analytics' => ['آمار زنده', 'این نود آمار دقیقه‌ای (آمار زنده) را گزارش می‌کند'],
        'logship' => ['ارسال لاگ', 'این نود لاگ دسترسی سایت‌های دارای «ارسال لاگ» را می‌فرستد'],
    ];

    /**
     * Capability badges of a node (HTTP/3, Early Hints, WebP) from `capabilities` (SPEC §14.1). An older
     * controller/agent that reports no capabilities renders nothing; loaded nginx modules go in the tooltip.
     */
    public static function edgeCapBadges(array $e): string
    {
        $c = is_array($e['capabilities'] ?? null) ? $e['capabilities'] : null;
        if ($c === null || !array_intersect_key(self::EDGE_CAPS, $c)) {
            return '';  // not reported yet (or an older agent/controller): show nothing rather than guess
        }
        $b = '';
        foreach (self::EDGE_CAPS as $k => [$label, $tip]) {
            if (($c[$k] ?? false) === true) {
                $b .= View::badge($label, 'brand', ' title="' . View::e($tip) . '" data-cap="' . $k . '"');
            }
        }
        if ($b === '') {
            $b = '<span class="pcdna-small pcdna-muted" data-cap="none" title="این نود HTTP/3، Early Hints یا تبدیل WebP را گزارش نکرده است">بدون HTTP/3</span>';
        }
        $mods = [];
        foreach ((array) ($c['modules'] ?? []) as $m) {
            if (is_string($m) && preg_match('/^[A-Za-z0-9_.-]{1,64}$/', $m)) {
                $mods[] = $m;
            }
        }
        return '<div class="pcdna-badges pcdna-caps"' . ($mods ? ' title="' . View::e('ماژول‌های nginx: ' . implode('، ', array_slice($mods, 0, 30))) . '"' : '') . '>' . $b . '</div>';
    }

    /**
     * «Shield» switch of a node (SPEC §14.1): a CSRF-protected POST (edge_shield) → PATCH /api/v1/edges/{id} {shield}.
     * Rendered only when the controller reports the `shield` field (older controllers don't know it).
     */
    private static function edgeShieldToggle(array $e, int $id): string
    {
        $on = !empty($e['shield']);
        $name = (string) ($e['name'] ?? ('#' . $id));
        $confirm = $on
            ? 'نقش Shield از نود «' . $name . '» برداشته شود؟ سایت‌هایی که Origin Shield دارند از نودهای Shield دیگر یا در نبود آن‌ها مستقیم از سرور اصلی استفاده می‌کنند.'
            : 'نود «' . $name . '» به‌عنوان Shield (لایه کش میانی جلوی سرور اصلی) استفاده شود؟ برای سایت‌هایی که Origin Shield را روشن کرده‌اند، نودهای دیگر فایل‌های کش‌نشده را از این نود می‌گیرند.';
        return '<form method="post" action="' . View::url(['page' => 'edges']) . '" class="pcdna-inline pcdna-shield-form" data-confirm="' . View::e($confirm) . '">' . View::csrf()
            . '<input type="hidden" name="a" value="edge_shield"><input type="hidden" name="id" value="' . $id . '">'
            . '<input type="hidden" name="shield" value="' . ($on ? '0' : '1') . '">'
            . '<button type="submit" class="pcdna-shield-btn' . ($on ? ' is-on' : '') . '" role="switch" aria-checked="' . ($on ? 'true' : 'false') . '"'
            . ' aria-label="' . View::e('Shield نود ' . $name) . '" title="' . ($on ? 'Shield روشن است؛ برای خاموش کردن کلیک کنید' : 'Shield خاموش است؛ برای روشن کردن کلیک کنید') . '">'
            . '<span class="pcdna-sw" aria-hidden="true"></span><span>Shield</span></button></form>';
    }

    /** Explanation under the edges table: what «Shield» does + how many shield nodes are live (SPEC §14.1). */
    private static function edgePerfNote(array $edges): string
    {
        $known = false;
        $shields = 0;
        $online = 0;
        foreach ($edges as $e) {
            if (!is_array($e) || !array_key_exists('shield', $e)) {
                continue;
            }
            $known = true;
            if (!empty($e['shield']) && !empty($e['enabled'])) {
                $shields++;
                $online += self::edgeOnline($e) ? 1 : 0;
            }
        }
        if (!$known) {
            return '';
        }
        $state = $shields > 0
            ? 'اکنون ' . View::n($shields) . ' نود Shield فعال است (' . View::n($online) . ' آنلاین).'
            : 'هنوز نود Shield فعالی وجود ندارد، پس گزینهٔ Origin Shield سایت‌ها فعلاً اثری ندارد.';
        return '<p class="pcdna-small pcdna-muted pcdna-perf-note" data-shield-count="' . $shields . '">' . View::icon('info')
            . '<span><b>Shield:</b> نودی که Shield باشد، لایهٔ کش میانی جلوی سرور اصلی سایت‌هایی است که «Origin Shield» را روشن کرده‌اند؛ نودهای دیگر فایل‌های کش‌نشده را از آن می‌گیرند و اگر هیچ نود Shield در دسترس نباشد، مستقیم سراغ سرور اصلی می‌روند. '
            . $state . ' نشان‌های HTTP/3، Early Hints و WebP از آخرین گزارش هر نود خوانده می‌شوند.</span></p>';
    }

    /** Health-warning badges for an edge row (disk/memory/high load) surfaced from the latest heartbeat. */
    private static function edgeWarnBadges(array $e): string
    {
        if (!self::edgeOnline($e)) {
            return '';
        }
        $m = is_array($e['metrics'] ?? null) ? $e['metrics'] : [];
        $l = self::edgeLoad($e);
        $b = '';
        if (empty($e['shed']) && $l['pct'] !== null && $l['pct'] > 80) {
            $b .= View::badge('بار بالا', 'warn', ' title="بیش از ۸۰٪ ظرفیت" data-warn="load"');
        }
        if (isset($m['disk_pct']) && (float) $m['disk_pct'] >= 85) {
            $b .= View::badge('دیسک ' . View::n((float) $m['disk_pct'], 0) . '٪', 'bad', ' title="فضای دیسک کش/nginx رو به اتمام است" data-warn="disk"');
        }
        if (isset($m['mem_pct']) && (float) $m['mem_pct'] >= 90) {
            $b .= View::badge('حافظه ' . View::n((float) $m['mem_pct'], 0) . '٪', 'bad', ' title="مصرف حافظه نود بالاست" data-warn="mem"');
        }
        return $b !== '' ? '<div class="pcdna-badges pcdna-edge-warns">' . $b . '</div>' : '';
    }

    // ------------------------------------------------------------------ SPEC §22 (wave 13): drain, tunnel probe, reloads, tuning, HTTP/3, weights
    //
    // Every piece is feature-detected per edge object: a controller from before wave 13 returns no `drain` / `tunnel_probe` /
    // `http3_enabled` / `reloads` / `tuning` / `dns_weight` keys, and then nothing new is rendered (columns show «—», no buttons).

    /** Edge id whose drain was refused with 409 last_edge in this request (+ the submitted minutes / reason): a confirmation card with
     *  the «با این حال تخلیه کن» force checkbox is shown above the node table / on the node detail. */
    public static $drainForce = 0;
    public static $drainForceIn = [];

    /** True when the controller reports the wave-13 edge fields. */
    public static function wave13(array $edges): bool
    {
        foreach ($edges as $e) {
            if (is_array($e) && (array_key_exists('drain', $e) || array_key_exists('tunnel_probe', $e))) {
                return true;
            }
        }
        return false;
    }

    /** HH:MM (server time zone, Persian digits) of an ISO time; «—» when invalid. */
    /** SPEC §23 (wave 14): the controller reports release / display-city fields (edge_to_dict). */
    public static function wave14(array $edges): bool
    {
        foreach ($edges as $e) {
            if (is_array($e) && (array_key_exists('display_city', $e) || array_key_exists('release', $e) || array_key_exists('public_tag', $e))) {
                return true;
            }
        }
        return false;
    }

    /**
     * SPEC §23.12.5 mirror of the controller's data/cities.json (Persian → English) for the «شهر نمایشی» datalist and the live
     * label preview; any other city can be typed (its English name then defaults to the Persian one, or the admin's override).
     */
    const CITIES = ['تهران' => 'Tehran', 'مشهد' => 'Mashhad', 'شیراز' => 'Shiraz', 'تبریز' => 'Tabriz', 'اصفهان' => 'Isfahan', 'کرج' => 'Karaj',
        'اهواز' => 'Ahvaz', 'قم' => 'Qom', 'کرمانشاه' => 'Kermanshah', 'رشت' => 'Rasht', 'ارومیه' => 'Urmia', 'یزد' => 'Yazd', 'کرمان' => 'Kerman',
        'زاهدان' => 'Zahedan', 'همدان' => 'Hamadan', 'اراک' => 'Arak', 'قزوین' => 'Qazvin', 'ساری' => 'Sari', 'بندرعباس' => 'Bandar Abbas',
        'گرگان' => 'Gorgan', 'سنندج' => 'Sanandaj', 'بوشهر' => 'Bushehr', 'زنجان' => 'Zanjan', 'خرم‌آباد' => 'Khorramabad', 'اردبیل' => 'Ardabil',
        'بیرجند' => 'Birjand', 'سمنان' => 'Semnan', 'یاسوج' => 'Yasuj', 'شهرکرد' => 'Shahrekord', 'ایلام' => 'Ilam', 'بجنورد' => 'Bojnurd'];

    /** «نسخه»: the node's release (or the short bundle hash), with «≠ نسخهٔ پین‌شده (vX)» when its group has a different pin. */
    public static function releaseCell(array $e): string
    {
        $rel = is_string($e['release'] ?? null) && $e['release'] !== '' ? (string) $e['release'] : null;
        $h = $rel !== null ? View::ltr($rel, 'pcdna-code') : (!empty($e['bundle_version'])
            ? '<span class="pcdna-muted" title="نسخهٔ انتشار گزارش نشده؛ شناسهٔ بسته">' . View::ltr(substr((string) $e['bundle_version'], 0, 8), 'pcdna-code') . '</span>' : '<span class="pcdna-muted">—</span>');
        $pin = is_string($e['pinned_release'] ?? null) && $e['pinned_release'] !== '' ? (string) $e['pinned_release'] : null;
        if ($pin !== null && ($e['release_ok'] ?? null) === false) {
            $h .= '<div>' . View::badge('≠ نسخهٔ پین‌شده (' . $pin . ')', 'warn', ' data-release-diff="' . View::e($pin) . '"') . '</div>';
        }
        $up = is_array($e['upgrade'] ?? null) ? $e['upgrade'] : null;
        if ($up && in_array($up['state'] ?? '', ['downloading', 'installing', 'failed'], true)) {
            $h .= '<div class="pcdna-small' . (($up['state'] ?? '') === 'failed' ? ' pcdna-err' : ' pcdna-muted') . '">'
                . View::e(['downloading' => 'در حال دریافت ', 'installing' => 'در حال نصب ', 'failed' => 'ارتقای ناموفق '][$up['state']]) . View::ltr((string) ($up['release'] ?? '')) . '</div>';
        }
        return $h;
    }

    /** «شهر نمایشی»: the customer label, the public tag and an inline editor with a live label preview (admin.js). */
    public static function cityCell(array $e, int $id): string
    {
        $fa = is_string($e['display_city'] ?? null) ? (string) $e['display_city'] : '';
        $en = is_string($e['display_city_en'] ?? null) ? (string) $e['display_city_en'] : '';
        $label = is_string($e['display_label'] ?? null) ? (string) $e['display_label'] : '';
        $labelEn = is_string($e['display_label_en'] ?? null) ? (string) $e['display_label_en'] : '';
        $h = '<div data-display-label="' . View::e($label) . '">' . ($label !== '' ? View::e($label) : '<span class="pcdna-muted">—</span>')
            . ($labelEn !== '' ? '<div class="pcdna-small pcdna-muted" dir="ltr">' . View::e($labelEn) . '</div>' : '')
            . ($fa === '' ? '<div class="pcdna-small pcdna-muted">پیش‌فرض منطقه</div>' : '') . '</div>';
        if (!empty($e['public_tag'])) {
            $h .= '<div class="pcdna-small" title="شناسهٔ عمومی نود — همان مقدار هدر X-Served-By">' . View::ltr((string) $e['public_tag'], 'pcdna-code') . '</div>';
        }
        $q = ['page' => 'edges'];
        $h .= '<details class="pcdna-menu pcdna-city-edit"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-icon" aria-label="' . View::e('شهر نمایشی نود ' . ($e['name'] ?? '')) . '" title="شهر نمایشی">'
            . View::icon('globe') . '</summary><div class="pcdna-menu-list"><form method="post" action="' . View::url($q) . '" class="pcdna-edge-form" data-city-form="' . $id . '">' . View::csrf()
            . '<input type="hidden" name="a" value="edge_city"><input type="hidden" name="id" value="' . $id . '">'
            . '<label><span>شهر (فارسی؛ خالی = پیش‌فرض منطقه)</span><input class="pcdna-input" name="display_city" maxlength="32" list="pcdna-cities" data-city-input="1" value="' . View::e($fa) . '"></label>'
            . '<label><span>نام انگلیسی (اختیاری)</span><input class="pcdna-input" name="display_city_en" dir="ltr" maxlength="32" data-city-en="1" placeholder="Tehran" value="' . View::e($en) . '"></label>'
            . '<p class="pcdna-small">پیش‌نمایش برای مشتری: <strong data-city-preview="1">' . View::e($label !== '' ? $label : ($fa !== '' ? 'نود ' . $fa : '—')) . '</strong>'
            . ' · <span dir="ltr" data-city-preview-en="1">' . View::e($labelEn) . '</span></p>'
            . '<p class="pcdna-small pcdna-muted">اگر چند نود یک شهر داشته باشند، شماره می‌گیرند (نود تهران ۱، نود تهران ۲). نام داخلی و آی‌پی نود هرگز به مشتری نشان داده نمی‌شود.</p>'
            . '<button type="submit" class="pcdna-btn pcdna-btn-sm pcdna-btn-primary">' . View::icon('check') . '<span>ذخیره</span></button></form></div></details>';
        return $h;
    }

    /** <datalist> of the known cities (once per page) — data-en carries the English name for the preview. */
    public static function cityList(): string
    {
        $h = '<datalist id="pcdna-cities">';
        foreach (self::CITIES as $fa => $en) {
            $h .= '<option value="' . View::e($fa) . '" data-en="' . View::e($en) . '"></option>';
        }
        return $h . '</datalist>';
    }

    public static function hm($iso): string
    {
        $t = is_string($iso) && $iso !== '' ? strtotime($iso) : false;
        return $t ? View::digits(date('H:i', $t)) : '—';
    }

    /** «۱۲:۰۵ مانده» until an ISO time (the admin.js countdown keeps it live). */
    public static function remain($iso): string
    {
        $t = is_string($iso) && $iso !== '' ? strtotime($iso) : false;
        if (!$t) {
            return '';
        }
        $s = $t - time();
        if ($s <= 0) {
            return 'رو به پایان';
        }
        return View::digits(sprintf('%d:%02d', intdiv($s, 60), $s % 60)) . ' مانده';
    }

    private static function drainOf(array $e): ?array
    {
        return is_array($e['drain'] ?? null) ? $e['drain'] : null;
    }

    /** Node row badge: «در حال تخلیه (تا HH:MM)» + live countdown + connections, or «تخلیه شد». */
    public static function drainBadge(array $e): string
    {
        $d = self::drainOf($e);
        $st = $d ? (string) ($d['state'] ?? '') : '';
        if ($st === 'draining') {
            $until = is_string($d['until'] ?? null) ? (string) $d['until'] : '';
            $who = ($d['by'] ?? '') === 'edge' ? 'خود نود (به‌روزرسانی)' : 'مدیر';
            return '<div class="pcdna-drain" data-drain="draining">'
                . View::badge('در حال تخلیه' . ($until !== '' ? ' (تا ' . self::hm($until) . ')' : ''), 'warn',
                    ' title="' . View::e('از DNS خارج است و پس از مهلت DNS اتصال تونلی تازه نمی‌پذیرد؛ شروع‌کننده: ' . $who
                        . (!empty($d['reason']) ? '، دلیل: ' . $d['reason'] : '')) . '"')
                . ($until !== '' ? ' <span class="pcdna-small pcdna-muted pcdna-countdown" data-countdown="' . View::e($until) . '">' . View::e(self::remain($until)) . '</span>' : '')
                . (isset($d['conns']) && $d['conns'] !== null ? ' <span class="pcdna-small pcdna-muted" data-drain-conns="' . (int) $d['conns'] . '">· ' . View::n((int) $d['conns']) . ' اتصال</span>' : '')
                . '</div>';
        }
        if ($st === 'drained') {
            return '<div class="pcdna-drain" data-drain="drained">' . View::badge('تخلیه شد', 'muted', ' title="اتصال‌ها تمام شده‌اند؛ پس از به‌روزرسانی «لغو تخلیه» را بزنید"') . '</div>';
        }
        return '';
    }

    /** «پروب تونل» cell (SPEC §22.3): ✓ / ✗ degraded since / «پشتیبانی نمی‌شود» / «—» (old agent or no report yet). */
    public static function probeCell(array $e): string
    {
        if (!array_key_exists('tunnel_probe', $e)) {
            return '<span class="pcdna-muted" data-probe="none">—</span>';
        }
        $p = is_array($e['tunnel_probe']) ? $e['tunnel_probe'] : [];
        $last = is_array($p['last'] ?? null) ? $p['last'] : null;
        if (!empty($p['degraded'])) {
            return View::badge('✗ خراب', 'bad', ' data-probe="degraded" title="' . View::e('مسیر تونل این نود در پروب داخلی شکست خورده و برای سایت‌های تونل از DNS خارج است'
                . (!empty($p['since']) ? ' (از ' . View::date($p['since'], true) . ')' : '')) . '"')
                . (!empty($p['since']) ? '<div class="pcdna-small pcdna-muted">از ' . View::e(View::ago($p['since'])) . '</div>' : '');
        }
        if (!$last) {
            return '<span class="pcdna-muted" data-probe="none" title="agent قدیمی یا هنوز گزارشی نفرستاده است">—</span>';
        }
        $uns = function ($x) {
            return !is_array($x) || !empty($x['unsupported']);
        };
        if ($uns($last['ws'] ?? null) && $uns($last['grpc'] ?? null)) {
            return '<span class="pcdna-small pcdna-muted" data-probe="unsupported">پشتیبانی نمی‌شود</span>';
        }
        $ok = !empty($last['ok']);
        $ws = is_array($last['ws'] ?? null) ? $last['ws'] : [];
        $ms = isset($ws['setup_ms']) && is_numeric($ws['setup_ms']) ? (int) $ws['setup_ms'] : null;
        return View::badge($ok ? '✓ سالم' : '✗ ناموفق', $ok ? 'ok' : 'warn', ' data-probe="' . ($ok ? 'ok' : 'fail') . '" title="' . View::e('آخرین پروب: ' . View::ago($last['at'] ?? null)
            . (!empty($last['consecutive_fail']) ? '، ' . View::n((int) $last['consecutive_fail']) . ' شکست پیاپی' : '')) . '"')
            . ($ms !== null ? '<div class="pcdna-small pcdna-muted" dir="ltr">' . View::n($ms) . ' ms</div>' : '');
    }

    /** Per-node HTTP/3 switch (SPEC §22.9) — disabled with a tooltip when nginx on the node has no HTTP/3. */
    private static function edgeHttp3Toggle(array $e, int $id, array $q): string
    {
        if (!array_key_exists('http3_enabled', $e)) {
            return '';
        }
        $on = $e['http3_enabled'] !== false;
        $caps = is_array($e['capabilities'] ?? null) ? $e['capabilities'] : [];
        $capable = ($caps['http3'] ?? false) === true;
        $name = (string) ($e['name'] ?? ('#' . $id));
        $tip = !$capable ? 'nginx این نود HTTP/3 ندارد (نصب با install.sh --http3)' : ($on ? 'HTTP/3 روشن است؛ برای خاموش کردن کلیک کنید' : 'HTTP/3 خاموش است؛ برای روشن کردن کلیک کنید');
        return '<form method="post" action="' . View::url($q) . '" class="pcdna-inline pcdna-h3-form"' . ($capable ? ' data-confirm="' . View::e($on
                ? 'HTTP/3 روی نود «' . $name . '» خاموش شود؟ تا روشن شدن دوباره، نسخهٔ HTTP/3 مسیرهای XHTTP به مشتریان این گروه پیشنهاد نمی‌شود.'
                : 'HTTP/3 روی نود «' . $name . '» روشن شود؟ فایروال باید UDP پورت HTTPS را باز بگذارد.') . '"' : '') . '>' . View::csrf()
            . '<input type="hidden" name="a" value="edge_http3"><input type="hidden" name="id" value="' . $id . '">'
            . '<input type="hidden" name="http3" value="' . ($on ? '0' : '1') . '">'
            . '<button type="submit" class="pcdna-shield-btn pcdna-h3-btn' . ($on && $capable ? ' is-on' : '') . '" role="switch" aria-checked="' . ($on && $capable ? 'true' : 'false') . '"'
            . ($capable ? '' : ' disabled') . ' data-h3="' . ($capable ? ($on ? 'on' : 'off') : 'nocap') . '"'
            . ' aria-label="' . View::e('HTTP/3 نود ' . $name) . '" title="' . View::e($tip) . '">'
            . '<span class="pcdna-sw" aria-hidden="true"></span><span>HTTP/3</span></button></form>';
    }

    /** DNS weight of the node (SPEC §22.10, DNS_WEIGHTS=capacity): q 1..4 and the load level that lowered it. */
    private static function weightNote(array $e): string
    {
        $w = is_array($e['dns_weight'] ?? null) ? $e['dns_weight'] : null;
        if (!$w || !isset($w['q']) || !is_numeric($w['q'])) {
            return '';
        }
        $q = (int) $w['q'];
        $lv = (int) ($w['level'] ?? 0);
        return '<div class="pcdna-small pcdna-muted pcdna-weight" data-weight="' . $q . '" title="سهم این نود در پاسخ DNS نسبت به نودهای هم‌گروه، از ظرفیت و بار (۱ تا ۴)">وزن DNS '
            . View::n($q) . ' از ۴' . ($lv > 0 ? ' · <span class="pcdna-c-warn">کاهش‌یافته (بار ' . ($lv === 1 ? 'بالای ۷۰٪' : 'بالای ۸۵٪') . ')</span>' : '') . '</div>';
    }

    /** overview.tunnel_multi_origin_sites of this request (0 = none / older controller → no flag). */
    public static $multiSites = 0;

    /** «تخلیه برای به‌روزرسانی…» menu + «لغو تخلیه» button of a node row / detail page; nothing when the controller has no drain. */
    private static function drainControls(array $e, int $id, array $q): string
    {
        $d = self::drainOf($e);
        if ($d === null) {
            return '';
        }
        $st = (string) ($d['state'] ?? '');
        $name = (string) ($e['name'] ?? ('#' . $id));
        $form = '<form method="post" action="' . View::url($q) . '" class="pcdna-edge-form pcdna-drain-form" data-drain-form="' . $id . '">' . View::csrf()
            . '<input type="hidden" name="a" value="edge_drain"><input type="hidden" name="id" value="' . $id . '">'
            . '<p class="pcdna-small pcdna-muted">نود فوراً از DNS خارج می‌شود و پس از مهلت DNS اتصال تونلی <b>تازه</b> نمی‌پذیرد؛ نشست‌های برقرار تا پایان مدت ادامه دارند. '
            . 'پس از به‌روزرسانی «لغو تخلیه» را بزنید (تخلیهٔ مدیر خودکار لغو نمی‌شود؛ کنترلر پس از مهلت نگه‌داری حداکثر آن را برمی‌گرداند).</p>'
            . '<label><span>مدت (دقیقه، ۱ تا ۱۲۰)</span><input class="pcdna-input" name="minutes" type="number" min="1" max="120" dir="ltr" inputmode="numeric" value="15" required></label>'
            . '<label><span>دلیل (اختیاری)</span><input class="pcdna-input" name="reason" maxlength="64" dir="ltr" placeholder="upgrade"></label>'
            . '<button type="submit" class="pcdna-btn pcdna-btn-sm pcdna-btn-primary">' . View::icon('history') . '<span>' . ($st === 'draining' ? 'تغییر مدت تخلیه' : 'شروع تخلیه') . '</span></button></form>';
        return '<details class="pcdna-menu pcdna-edge-drain"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-icon" aria-label="' . View::e('تخلیهٔ نود ' . $name)
            . '" title="تخلیه برای به‌روزرسانی…">' . View::icon('history') . '</summary><div class="pcdna-menu-list">' . $form . '</div></details>'
            . ($st !== '' ? View::postButton($q, 'edge_undrain', ['id' => $id], 'لغو تخلیه', 'pcdna-btn pcdna-btn-sm pcdna-btn-icon pcdna-undrain',
                'تخلیهٔ نود «' . $name . '» لغو شود؟ نود دوباره در پاسخ DNS قرار می‌گیرد.', 'refresh') : '');
    }

    /** After 409 last_edge: «تخلیهٔ نود X» card — reason + the «با این حال تخلیه کن» checkbox, minutes / reason kept. */
    public static function drainForceCard(array $edges, array $q): string
    {
        $id = self::$drainForce;
        if ($id <= 0) {
            return '';
        }
        $name = '#' . $id;
        foreach ($edges as $e) {
            if (is_array($e) && (int) ($e['id'] ?? 0) === $id) {
                $name = (string) ($e['name'] ?? $name);
            }
        }
        $in = self::$drainForceIn;
        $min = (int) ($in['minutes'] ?? 15);
        $form = '<form method="post" action="' . View::url($q) . '" class="pcdna-form pcdna-drain-force" data-drain-force="' . $id . '">' . View::csrf()
            . '<input type="hidden" name="a" value="edge_drain"><input type="hidden" name="id" value="' . $id . '">'
            . '<input type="hidden" name="minutes" value="' . $min . '"><input type="hidden" name="reason" value="' . View::e((string) ($in['reason'] ?? '')) . '">'
            . View::alert('warn', '<strong>آخرین نود فعال این گروه/منطقه است.</strong> با تخلیهٔ ' . View::ltr($name) . ' هیچ نود فعال دیگری در گروه/منطقهٔ آن نمی‌ماند؛ '
                . 'کنترلر برای اینکه پاسخ DNS خالی نشود نود را در DNS نگه می‌دارد، ولی اتصال تونلی تازه پس از مهلت DNS رد می‌شود.')
            . '<p>' . self::check('force', false, 'با این حال تخلیه کن (' . View::n($min) . ' دقیقه)') . '</p>'
            . '<div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('history') . '<span>تخلیه</span></button>'
            . '<a class="pcdna-btn pcdna-btn-ghost" href="' . View::url($q) . '">انصراف</a></div></form>';
        return View::card('تخلیهٔ نود ' . $name, $form, '', 'pcdna-drain-force-card', 'history');
    }

    /** HTTP/3 summary per group: [group => [h3 nodes, enabled nodes]], or null on a controller without the switch. */
    public static function h3Summary(array $edges): ?array
    {
        $known = false;
        $out = [];
        foreach (array_keys(self::EDGE_GROUPS) as $g) {
            $out[$g] = [0, 0];
        }
        foreach ($edges as $e) {
            if (!is_array($e) || empty($e['enabled'])) {
                continue;
            }
            $known = $known || array_key_exists('http3_enabled', $e);
            $g = isset($out[$e['group'] ?? 'general']) ? ($e['group'] ?? 'general') : 'general';
            $out[$g][1]++;
            $caps = is_array($e['capabilities'] ?? null) ? $e['capabilities'] : [];
            if (($caps['http3'] ?? false) === true && ($e['http3_enabled'] ?? true) !== false) {
                $out[$g][0]++;
            }
        }
        return $known ? $out : null;
    }

    const RELOAD_LABELS = [
        'count_1h' => 'بارگذاری مجدد در ساعت گذشته', 'count_24h' => 'بارگذاری مجدد در ۲۴ ساعت', 'coalesced_1h' => 'تغییرات ادغام‌شده (ساعت گذشته)',
        'pending_s' => 'سن تنظیمات در انتظار', 'forced_shutdowns_24h' => 'خاموشی اجباری کارگرها (محافظ حافظه، ۲۴ ساعت)',
    ];

    /** Node detail «پایداری تونل» (SPEC §22.1–§22.3, §22.6, §22.9, §22.10): drain, probe, reloads, kernel tuning, HTTP/3, DNS weight. */
    public static function edgeDetail(int $id): string
    {
        $back = '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::url(['page' => 'edges']) . '">' . View::icon('server') . '<span>بازگشت به نودها</span></a>';
        if ($id <= 0) {
            return $back . View::alert('bad', 'شناسه نود نامعتبر است.');
        }
        $ping = self::ping();
        if (!$ping['ok']) {
            return $back . self::ctlError($ping);
        }
        $r = self::fetch(['/api/v1/edges']);
        if (!self::ok($r['/api/v1/edges'])) {
            return $back . View::alert('bad', 'فهرست نودها دریافت نشد: ' . View::e((string) $r['/api/v1/edges']['error']));
        }
        $edge = null;
        foreach ((array) $r['/api/v1/edges']['data'] as $e) {
            if (is_array($e) && (int) ($e['id'] ?? 0) === $id) {
                $edge = $e;
                break;
            }
        }
        if ($edge === null) {
            return $back . View::alert('bad', 'نودی با این شناسه پیدا نشد.');
        }
        $e = $edge;
        $name = (string) ($e['name'] ?? ('#' . $id));
        $q = ['page' => 'edges', 'view' => 'detail', 'id' => $id];
        $row = function (string $k, string $label, string $val) {
            return '<div data-d="' . View::e($k) . '"><dt>' . View::e($label) . '</dt><dd>' . $val . '</dd></div>';
        };
        $na = '<span class="pcdna-muted">—</span>';
        // SPEC §23.12.2: the public tag support uses to map a customer's X-Served-By header to this node, and the customer label
        $ident = '';
        if (self::wave14([$e])) {
            $ident = View::card('شناسهٔ عمومی و نام نمایشی', '<dl class="pcdna-dl pcdna-dl-cols" data-detail="identity">'
                . $row('tag', 'شناسهٔ عمومی (X-Served-By)', !empty($e['public_tag']) ? View::ltr((string) $e['public_tag'], 'pcdna-code') : $na)
                . $row('label', 'نام برای مشتری', !empty($e['display_label']) ? View::e((string) $e['display_label']) . (!empty($e['display_label_en']) ? ' · <span dir="ltr">' . View::e((string) $e['display_label_en']) . '</span>' : '') : $na)
                . $row('release', 'نسخه', self::releaseCell($e)) . '</dl>'
                . '<p class="pcdna-small pcdna-muted">مشتری فقط نام نمایشی را می‌بیند. برای پیدا کردن نود از روی هدر مشتری، از «جست‌وجو با شناسه» در صفحهٔ نودها استفاده کنید.</p>', '', '', 'tag');
        }
        if (!self::wave13([$e])) {
            return $ident . View::card('پایداری تونل نود ' . $name, View::alert('info', 'کنترلر فعلی جزئیات تخلیه، پروب تونل، بارگذاری مجدد و تنظیمات هسته را گزارش نمی‌کند؛ برای این بخش کنترلر را به موج ۱۳ به‌روزرسانی کنید.'), $back, '', 'activity');
        }
        $h = '';
        $force = self::drainForceCard([$e], $q);
        // drain
        $d = self::drainOf($e) ?? [];
        $st = (string) ($d['state'] ?? '');
        $body = '<dl class="pcdna-dl pcdna-dl-cols" data-detail="drain">'
            . $row('state', 'وضعیت', $st === 'draining' ? self::drainBadge($e) : ($st === 'drained' ? View::badge('تخلیه شد', 'muted') : View::badge('عادی (در DNS)', 'ok')))
            . $row('since', 'شروع', !empty($d['since']) ? View::e(View::date($d['since'], true)) : $na)
            . $row('until', 'پایان', !empty($d['until']) ? View::e(View::date($d['until'], true)) : $na)
            . $row('by', 'شروع‌کننده', ($d['by'] ?? '') === 'edge' ? 'خود نود (به‌روزرسانی با --drain)' : (($d['by'] ?? '') === 'admin' ? 'مدیر' : $na))
            . $row('reason', 'دلیل', !empty($d['reason']) ? View::ltr((string) $d['reason']) : $na)
            . $row('conns', 'اتصال‌های باز کاربران', isset($d['conns']) && $d['conns'] !== null ? View::n((int) $d['conns']) : $na)
            . '</dl><div class="pcdna-form-actions">' . self::drainControls($e, $id, $q) . '</div>'
            . '<p class="pcdna-small pcdna-muted">روی خود نود هم می‌توانید بنویسید: <code dir="ltr">bootstrap.sh --upgrade --drain=15</code> — به‌روزرسانی پس از تخلیه انجام و نود خودکار برگردانده می‌شود.</p>';
        $h .= View::card('تخلیه برای به‌روزرسانی', $body, '', '', 'history');
        // tunnel probe
        $p = is_array($e['tunnel_probe'] ?? null) ? $e['tunnel_probe'] : [];
        $last = is_array($p['last'] ?? null) ? $p['last'] : null;
        $body = '<dl class="pcdna-dl pcdna-dl-cols" data-detail="probe">' . $row('state', 'وضعیت', self::probeCell($e))
            . $row('at', 'آخرین پروب', $last && !empty($last['at']) ? View::e(View::ago($last['at'])) : $na)
            . $row('fails', 'شکست پیاپی', $last && isset($last['consecutive_fail']) ? View::n((int) $last['consecutive_fail']) : $na) . '</dl>';
        if ($last) {
            $body .= '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-probe-table"><thead><tr><th>پروب</th><th>نتیجه</th><th>زمان برقراری</th><th>اکو</th><th>دانلود</th><th>آپلود</th><th>آخرین خطا</th></tr></thead><tbody>';
            foreach (['ws' => 'WebSocket', 'grpc' => 'gRPC'] as $k => $lbl) {
                $x = $last[$k] ?? null;
                if (!is_array($x) || !empty($x['unsupported'])) {
                    $body .= '<tr data-probe-kind="' . $k . '"><td>' . $lbl . '</td><td colspan="6" class="pcdna-muted">پشتیبانی نمی‌شود</td></tr>';
                    continue;
                }
                $kb = function ($v) {
                    return is_numeric($v) ? View::e(self::mbps(((float) $v) / 1000)) : '—';
                };
                $body .= '<tr data-probe-kind="' . $k . '"><td>' . $lbl . '</td><td>' . (!empty($x['ok']) ? View::badge('سالم', 'ok') : View::badge('ناموفق', 'bad')) . '</td>'
                    . '<td dir="ltr">' . (is_numeric($x['setup_ms'] ?? null) ? View::n((int) $x['setup_ms']) . ' ms' : '—') . '</td>'
                    . '<td>' . (array_key_exists('echo_ok', $x) ? (!empty($x['echo_ok']) ? '✓' : '✗') : '—') . '</td>'
                    . '<td dir="ltr">' . $kb($x['down_kbps'] ?? null) . '</td><td dir="ltr">' . ($k === 'ws' ? $kb($x['up_kbps'] ?? null) : '—') . '</td>'
                    . '<td>' . (!empty($x['error']) ? '<code dir="ltr">' . View::e(View::clip((string) $x['error'], 120)) . '</code>' : '—') . '</td></tr>';
            }
            $body .= '</tbody></table></div>';
        }
        $body .= '<p class="pcdna-small pcdna-muted">پروب داخلی سلامت خود نود را می‌سنجد (nginx، TLS و مسیر تونل به یک مبدأ آزمایشی محلی) — نه دسترسی از شبکهٔ کاربران. نود خراب فقط برای سایت‌های تونل و با سقف بودجهٔ هر گروه از DNS خارج می‌شود.</p>';
        $h .= View::card('پروب تونل', $body, '', '', 'activity');
        // reloads
        $rl = is_array($e['reloads'] ?? null) ? $e['reloads'] : null;
        $m = is_array($e['metrics'] ?? null) ? $e['metrics'] : [];
        $body = '<dl class="pcdna-dl pcdna-dl-cols" data-detail="reloads">';
        foreach (['count_1h', 'count_24h', 'coalesced_1h'] as $k) {
            $body .= $row($k, self::RELOAD_LABELS[$k], $rl && is_numeric($rl[$k] ?? null) ? View::n((int) $rl[$k]) : $na);
        }
        $body .= $row('last_at', 'آخرین بارگذاری مجدد', $rl && !empty($rl['last_at']) ? View::e(View::ago($rl['last_at'])) : $na)
            . $row('pending_s', self::RELOAD_LABELS['pending_s'], $rl && is_numeric($rl['pending_s'] ?? null) ? ((int) $rl['pending_s'] > 0 ? View::n((int) $rl['pending_s']) . ' ثانیه'
                . (!empty($rl['deferred']) ? ' ' . View::badge('به تعویق افتاده', 'warn') : '') : 'ندارد') : $na)
            . $row('wst', 'مهلت خاموشی کارگرها (WST)', $rl && is_numeric($rl['wst_s'] ?? null) ? View::e(self::secs((int) $rl['wst_s'])) : $na)
            . $row('draining_workers', 'نسل‌های در حال تخلیه', is_numeric($m['draining_workers'] ?? null) ? View::n((int) $m['draining_workers']) : $na)
            . $row('forced', self::RELOAD_LABELS['forced_shutdowns_24h'], $rl && is_numeric($rl['forced_shutdowns_24h'] ?? null) ? View::n((int) $rl['forced_shutdowns_24h']) : $na)
            . $row('socks', 'سوکت‌های TCP / TIME-WAIT', is_numeric($m['sock_tcp'] ?? null) ? View::n((int) $m['sock_tcp']) . ' / ' . View::n((int) ($m['sock_tw'] ?? 0)) : $na)
            . '</dl><p class="pcdna-small pcdna-muted">تغییرات تنظیمات پشت‌سرهم ادغام و حداکثر با یک بارگذاری مجدد اعمال می‌شوند؛ اتصال‌های طولانی در نسل قبلی کارگرها تا پایان WST ادامه دارند.</p>';
        $h .= View::card('بارگذاری مجدد nginx', $body, '', '', 'refresh');
        // tuning
        $tu = is_array($e['tuning'] ?? null) ? $e['tuning'] : null;
        if ($tu === null) {
            $body = View::emptyState('گزارشی نیست', 'agent این نود هنوز پروفایل تنظیمات هسته را گزارش نکرده است.', 'info');
        } else {
            $mis = is_array($tu['mismatches'] ?? null) ? array_filter($tu['mismatches'], 'is_array') : [];
            $body = '<dl class="pcdna-dl pcdna-dl-cols" data-detail="tuning">'
                . $row('ok', 'وضعیت', !empty($tu['ok']) ? View::badge('✓ مطابق پروفایل', 'ok') : View::badge(View::n(count($mis)) . ' مورد ناهمخوان', 'warn'))
                . $row('profile', 'پروفایل', View::ltr((string) ($tu['profile'] ?? '—')) . (is_numeric($tu['ram_mb'] ?? null) ? ' · ' . View::n((int) $tu['ram_mb']) . ' MB RAM' : ''))
                . $row('cc', 'کنترل ازدحام', !empty($tu['cc']) ? View::ltr((string) $tu['cc']) : $na)
                . $row('qdisc', 'qdisc', !empty($tu['qdisc']) ? View::ltr((string) $tu['qdisc']) : $na)
                . $row('nofile', 'حداکثر فایل باز nginx', is_numeric($tu['nofile'] ?? null) ? View::n((int) $tu['nofile']) : $na) . '</dl>';
            if ($mis) {
                $body .= '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-tuning-table"><thead><tr><th>کلید</th><th>مقدار مورد انتظار</th><th>مقدار فعلی</th></tr></thead><tbody>';
                foreach (array_slice($mis, 0, 20) as $x) {
                    $body .= '<tr data-mismatch="' . View::e((string) ($x['key'] ?? '')) . '"><td>' . View::ltr(View::clip((string) ($x['key'] ?? ''), 64)) . '</td><td>'
                        . View::ltr(View::clip((string) ($x['want'] ?? ''), 64)) . '</td><td>' . View::ltr(View::clip((string) ($x['have'] ?? ''), 64)) . '</td></tr>';
                }
                $body .= '</tbody></table></div><p class="pcdna-small pcdna-muted">روی نود <code dir="ltr">pcdn-agent tune --write</code> را اجرا کنید.</p>';
            }
        }
        $h .= View::card('تنظیمات هسته', $body, '', '', 'sliders');
        // HTTP/3, capacity weight, capabilities
        $caps = is_array($e['capabilities'] ?? null) ? $e['capabilities'] : [];
        $w = is_array($e['dns_weight'] ?? null) ? $e['dns_weight'] : null;
        $flag = function ($k) use ($caps) {
            return ($caps[$k] ?? null) === true ? View::badge('دارد', 'ok') : View::badge('ندارد', 'muted');
        };
        $body = '<dl class="pcdna-dl pcdna-dl-cols" data-detail="network">'
            . $row('http3', 'HTTP/3 (QUIC)', array_key_exists('http3_enabled', $e) ? self::edgeHttp3Toggle($e, $id, $q) : $na)
            . $row('capacity', 'ظرفیت اعلام‌شده', (int) ($e['capacity_mbps'] ?? 0) > 0 ? View::e(self::mbps((int) $e['capacity_mbps'])) : 'نامشخص')
            . $row('weight', 'وزن DNS', $w && is_numeric($w['q'] ?? null) ? self::weightNote($e) : '<span class="pcdna-muted">وزن‌دهی DNS خاموش است (همه هم‌وزن)</span>')
            . $row('cap_drain', 'تخلیه روی نود', $flag('drain')) . $row('cap_probe', 'پروب تونل', $flag('tunnel_probe'))
            . $row('cap_multi', 'چند مبدأ برای مسیر تونل', $flag('tunnel_multi_origin')) . $row('cap_resolve', 'اتصال ماندگار به مبدأ دامنه‌ای', $flag('upstream_resolve'))
            . '</dl>';
        $h .= View::card('شبکه، HTTP/3 و وزن', $body, '', '', 'zap');
        return '<div class="pcdna-detail-head">' . $back . '<h2 class="pcdna-detail-title">پایداری تونل نود ' . View::ltr($name) . '</h2></div>' . $force . $ident
            . '<div class="pcdna-grid-2 pcdna-edge-detail">' . $h . '</div>';
    }

    private static function secs(int $s): string
    {
        if ($s >= 3600 && $s % 3600 === 0) {
            return View::n($s / 3600) . ' ساعت';
        }
        if ($s >= 60 && $s % 60 === 0) {
            return View::n($s / 60) . ' دقیقه';
        }
        return View::n($s) . ' ثانیه';
    }

    /**
     * @param array $edges edge objects
     * @param bool $actions render the per-row action menu
     * @param array|null $series map of edge id => daily uptime rows for the inline sparkline
     */
    private static function edgeTable(array $edges, bool $actions, ?array $series = null, ?string $bundle = null, string $ctlUrl = ''): string
    {
        if (!$edges) {
            return View::emptyState('هنوز نودی ثبت نشده است', 'برای شروع، از صفحه «نودها» اولین نود را اضافه کنید.', 'server');
        }
        $w13 = $actions && self::wave13($edges);
        $w14 = $actions && self::wave14($edges);
        $multiFleet = $w13 && self::$multiSites > 0;
        $h = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-edges"><thead><tr><th>نام / IP</th><th>منطقه / گروه</th>'
            . ($w14 ? '<th>نسخه</th><th>شهر نمایشی</th>' : '') . '<th>وضعیت</th>'
            . ($w13 ? '<th>پروب تونل</th>' : '') . '<th>بار لحظه‌ای</th><th>در دسترس‌بودن</th><th>آخرین ارتباط</th>' . ($actions ? '<th><span class="pcdna-sr">عملیات</span></th>' : '') . '</tr></thead><tbody>';
        foreach ($edges as $e) {
            $online = self::edgeOnline($e);
            $fresh = !empty($e['enabled']) && empty($e['last_seen_at']);
            $status = empty($e['enabled']) ? View::badge('غیرفعال', 'muted') : ($online ? View::badge('آنلاین', 'ok')
                : ($fresh ? View::badge('در انتظار نصب', 'warn', ' title="agent هنوز به کنترلر وصل نشده است"') : View::badge('آفلاین', 'bad')));
            $err = trim((string) ($e['last_error'] ?? ''));
            [$gl, $gt] = self::EDGE_GROUPS[$e['group'] ?? 'general'] ?? [(string) ($e['group'] ?? ''), 'muted'];
            $id = (int) ($e['id'] ?? 0);
            $shieldKnown = array_key_exists('shield', $e);
            $h .= '<tr data-edge="' . $id . '"' . (!empty($e['enabled']) && !$online && !$fresh ? ' class="is-bad"' : '') . ($err !== '' ? ' data-has-error="1"' : '')
                . (!empty($e['shed']) ? ' data-shed="1"' : '') . (!empty($e['shield']) ? ' data-shield="1"' : '') . '><td><strong>' . View::ltr($e['name'] ?? '') . '</strong>'
                . '<div class="pcdna-small pcdna-muted">' . View::ltr($e['ipv4'] ?? '') . (!empty($e['ipv6']) ? '<br>' . View::ltr($e['ipv6']) : '') . '</div>'
                . ($actions ? self::edgeCapBadges($e) : '') . '</td>'
                . '<td><span class="pcdna-badges">' . (($e['region'] ?? '') === 'home' ? View::badge('ایران', 'brand') : View::badge('خارج', 'violet'))
                . View::badge($gl, $gt === 'violet' ? 'violet' : 'muted', ' data-group="' . View::e($e['group'] ?? 'general') . '"') . '</span></td>'
                . ($w14 ? '<td class="pcdna-release-cell">' . self::releaseCell($e) . '</td><td class="pcdna-city-cell">' . self::cityCell($e, $id) . '</td>' : '')
                // «Shield» (SPEC §14.1) sits under the status badge: the status column has room, the group column does not.
                . '<td>' . $status . (!$actions && !empty($e['shield']) ? ' ' . View::badge('Shield', 'ok', ' title="لایهٔ کش میانی (Origin Shield)"') : '')
                . ($actions && $shieldKnown ? '<div class="pcdna-shield-cell">' . self::edgeShieldToggle($e, $id) . '</div>' : '')
                . ($actions && array_key_exists('http3_enabled', $e) ? '<div class="pcdna-shield-cell">' . self::edgeHttp3Toggle($e, $id, ['page' => 'edges']) . '</div>' : '')
                . ($actions ? self::drainBadge($e) : '')
                . ($multiFleet && ($e['group'] ?? '') === 'tunnel' && is_array($e['capabilities'] ?? null) && ($e['capabilities']['tunnel_multi_origin'] ?? false) !== true
                    ? View::badge('بدون چند مبدأ', 'warn', ' data-warn="multi_origin" title="' . View::e('agent این نود قدیمی است؛ ' . View::n(self::$multiSites) . ' سایت مسیر تونل با چند سرور مبدأ دارد و روی این نود فقط به سرور اصلی می‌رسد (بدون جایگزینی خودکار). نود را به‌روزرسانی کنید.') . '"') : '')
                . self::edgeWarnBadges($e) . '</td>' . ($w13 ? '<td class="pcdna-probe-cell">' . self::probeCell($e) . '</td>' : '')
                . '<td class="pcdna-load-cell">' . self::loadCell($e) . ($actions ? self::weightNote($e) : '') . '</td>'
                . '<td class="pcdna-uptime-cell">' . self::uptimeCell($e, $series[$id] ?? null) . '</td>'
                . '<td title="' . View::e($e['last_seen_at'] ?? '') . '">' . View::e(View::ago($e['last_seen_at'] ?? null))
                . (!empty($e['applied_version']) ? '<div class="pcdna-small pcdna-muted" title="نسخه تنظیمات اعمال‌شده">' . View::ltr(substr((string) $e['applied_version'], 0, 8), 'pcdna-code') . '</div>' : '')
                . (self::edgeOutdated($e, $bundle) ? '<div class="pcdna-small"><span class="pcdna-badge pcdna-t-warn" data-outdated="1" title="نسخهٔ در حال اجرا: ' . View::e(substr((string) $e['bundle_version'], 0, 12)) . ' — نسخهٔ فعلی بسته: ' . View::e(substr((string) $bundle, 0, 12)) . '">به‌روزرسانی موجود است</span></div>' : '')
                . '</td>';
            if ($actions) {
                $q = ['page' => 'edges'];
                $up = self::edgeOutdated($e, $bundle)
                    ? '<details class="pcdna-menu pcdna-edge-upgrade"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-icon" aria-label="ارتقای نود ' . View::e($e['name'] ?? '') . '" title="به‌روزرسانی نود">'
                        . View::icon('activity') . '</summary><div class="pcdna-menu-list"><p class="pcdna-small pcdna-muted">این دستور را روی سرور نود اجرا کنید تا بستهٔ edge به نسخهٔ فعلی به‌روزرسانی شود (بدون تغییر توکن یا تنظیمات):</p>'
                        . View::copyable(self::upgradeCmd($ctlUrl), 'کپی دستور ارتقا') . '</div></details>'
                    : '';
                $logsLink = '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-icon' . (!empty($e['has_logs']) ? ' pcdna-has-logs' : '') . '" data-logs="' . $id . '"'
                    . ' href="' . View::url(['page' => 'edges', 'view' => 'logs', 'id' => $id]) . '" title="لاگ‌ها'
                    . (!empty($e['logs_at']) ? ' (آخرین گزارش: ' . View::e(View::ago($e['logs_at'])) . ')' : '') . '" aria-label="لاگ‌های نود ' . View::e($e['name'] ?? '') . '">'
                    . View::icon('info') . (!empty($e['has_logs']) ? '<span class="pcdna-log-dot" aria-hidden="true"></span>' : '') . '<span class="pcdna-sr">لاگ‌ها</span></a>';
                // «آدرس‌ها» — on-demand panel: primary + additional addresses with per-address health (SPEC §12.5).
                $addrs = is_array($e['addresses'] ?? null) ? array_filter($e['addresses'], 'is_array') : [];
                $addrCount = count($addrs);
                $addrDown = false;
                foreach ($addrs as $a) {
                    if (($a['probe_ok'] ?? null) === false || (isset($a['advertised']) && !$a['advertised'] && !empty($a['enabled']))) {
                        $addrDown = true;
                        break;
                    }
                }
                $addrLink = '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-icon' . ($addrDown ? ' pcdna-has-addrs' : '') . '" data-addresses="' . $id . '"'
                    . ' href="' . View::url(['page' => 'edges', 'view' => 'addresses', 'id' => $id]) . '" title="آدرس‌ها'
                    . ($addrCount ? ' (' . View::n($addrCount) . ' آدرس اضافی)' : '') . '" aria-label="آدرس‌های نود ' . View::e($e['name'] ?? '') . '">'
                    . View::icon('globe') . ($addrDown ? '<span class="pcdna-addr-dot" aria-hidden="true"></span>' : '') . '<span class="pcdna-sr">آدرس‌ها</span></a>';
                $detailLink = $w13 ? '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-icon" data-detail-link="' . $id . '" href="' . View::url(['page' => 'edges', 'view' => 'detail', 'id' => $id])
                    . '" title="پایداری تونل (تخلیه، پروب، بارگذاری مجدد، تنظیمات هسته)" aria-label="' . View::e('پایداری تونل نود ' . ($e['name'] ?? '')) . '">' . View::icon('activity')
                    . '<span class="pcdna-sr">پایداری تونل</span></a>' : '';
                $h .= '<td class="pcdna-actions">' . $addrLink . $logsLink . $detailLink . $up . self::drainControls($e, $id, $q)
                    . '<details class="pcdna-menu pcdna-edge-edit"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-icon" aria-label="ویرایش نود ' . View::e($e['name'] ?? '') . '" title="گروه، ظرفیت و منطقه">'
                    . View::icon('sliders') . '</summary><div class="pcdna-menu-list"><form method="post" action="' . View::url($q) . '" class="pcdna-edge-form">' . View::csrf()
                    . '<input type="hidden" name="a" value="edge_edit"><input type="hidden" name="id" value="' . $id . '">'
                    . '<label><span>گروه</span>' . View::select('group', ['general' => 'عمومی (سایت‌ها)', 'tunnel' => 'تونل (VPN)'], $e['group'] ?? 'general') . '</label>'
                    . '<label><span>ظرفیت (Mbps، ۰ = نامشخص)</span><input class="pcdna-input" name="capacity_mbps" dir="ltr" inputmode="numeric" value="' . (int) ($e['capacity_mbps'] ?? 0) . '"></label>'
                    . '<label><span>منطقه</span>' . View::select('region', ['home' => 'ایران (home)', 'global' => 'خارج (global)'], $e['region'] ?? 'home') . '</label>'
                    . '<button type="submit" class="pcdna-btn pcdna-btn-sm pcdna-btn-primary">' . View::icon('check') . '<span>ذخیره</span></button></form></div></details>'
                    . View::postButton($q, 'edge_toggle', ['id' => $id, 'enabled' => empty($e['enabled']) ? '1' : '0'],
                        empty($e['enabled']) ? 'فعال‌سازی' : 'غیرفعال‌سازی', 'pcdna-btn pcdna-btn-sm pcdna-btn-icon',
                        empty($e['enabled']) ? '' : 'نود «' . ($e['name'] ?? '') . '» از DNS خارج شود؟ ترافیک به نودهای دیگر می‌رود.', 'power')
                    . View::postButton($q, 'edge_rotate', ['id' => $id], 'توکن جدید', 'pcdna-btn pcdna-btn-sm pcdna-btn-icon',
                        'توکن فعلی نود «' . ($e['name'] ?? '') . '» باطل می‌شود و agent تا نصب توکن جدید نمی‌تواند تنظیمات بگیرد. ادامه می‌دهید؟', 'key')
                    . View::postButton($q, 'edge_delete', ['id' => $id], 'حذف نود', 'pcdna-btn pcdna-btn-sm pcdna-btn-icon pcdna-btn-danger',
                        'نود «' . ($e['name'] ?? '') . '» برای همیشه حذف شود؟', 'trash')
                    . '</td>';
            }
            $h .= '</tr>';
            if ($err !== '') {
                $h .= '<tr class="pcdna-errrow"><td colspan="' . (($actions ? 7 : 6) + ($w13 ? 1 : 0) + ($w14 ? 2 : 0)) . '"><span class="pcdna-err-label">' . View::icon('warn') . 'آخرین خطا:</span> '
                    . '<code dir="ltr" title="' . View::e(View::clip($err, 600)) . '">' . View::e(View::clip($err, 300)) . '</code></td></tr>';
            }
        }
        return $h . '</tbody></table></div>';
    }

    /** «جست‌وجو با شناسه»: GET /api/v1/edges?tag=<8 hex> — maps a customer's X-Served-By / X-Pcdn-Node value to a node. */
    private static function tagSearch(string $tag): string
    {
        $res = '';
        if ($tag !== '') {
            $p = '/api/v1/edges?tag=' . $tag;
            $r = self::fetch([$p]);
            $list = self::ok($r[$p]) ? array_values(array_filter((array) $r[$p]['data'], 'is_array')) : [];
            $list = array_values(array_filter($list, function ($e) use ($tag) {
                return !isset($e['public_tag']) || strtolower((string) $e['public_tag']) === $tag;
            }));
            $res = $list ? '<p data-tag-result="' . View::e($tag) . '">' . View::icon('check') . ' شناسهٔ ' . View::ltr($tag, 'pcdna-code') . ' = نود '
                . implode('، ', array_map(function ($e) {
                    return '<a href="' . View::url(['page' => 'edges', 'view' => 'detail', 'id' => (int) ($e['id'] ?? 0)]) . '">' . View::ltr((string) ($e['name'] ?? '')) . '</a>'
                        . (!empty($e['display_label']) ? ' (' . View::e((string) $e['display_label']) . ')' : '');
                }, $list)) . '</p>'
                : '<p class="pcdna-err" data-tag-result="">نودی با شناسهٔ ' . View::ltr($tag, 'pcdna-code') . ' پیدا نشد.</p>';
        }
        return '<form method="get" action="addonmodules.php" class="pcdna-filters pcdna-tag-search"><input type="hidden" name="module" value="' . View::e(Env::MODULE) . '"><input type="hidden" name="page" value="edges">'
            . '<label><span>جست‌وجو با شناسه (هدر X-Served-By مشتری)</span><input class="pcdna-input" name="tag" dir="ltr" maxlength="8" pattern="[0-9a-fA-F]{8}" placeholder="3fa91c0d" value="' . View::e($tag) . '"></label>'
            . '<button type="submit" class="pcdna-btn">' . View::icon('search') . '<span>جست‌وجو</span></button></form>' . $res;
    }

    /** Per-group totals of online edges: [group => [online, edges, rx, tx, cap, conns]]. */
    public static function groupTotals(array $edges): array
    {
        $out = [];
        foreach (array_keys(self::EDGE_GROUPS) as $g) {
            $out[$g] = ['online' => 0, 'edges' => 0, 'rx' => 0.0, 'tx' => 0.0, 'cap' => 0, 'conns' => 0, 'shed' => 0];
        }
        foreach ($edges as $e) {
            if (!is_array($e) || empty($e['enabled'])) {
                continue;
            }
            $g = isset($out[$e['group'] ?? 'general']) ? ($e['group'] ?? 'general') : 'general';
            $out[$g]['edges']++;
            if (!self::edgeOnline($e)) {
                continue;
            }
            $out[$g]['online']++;
            $out[$g]['shed'] += !empty($e['shed']) ? 1 : 0;
            $l = self::edgeLoad($e);
            if ($l['fresh']) {
                $out[$g]['rx'] += (float) ($l['m']['rx_mbps'] ?? 0);
                $out[$g]['tx'] += (float) ($l['m']['tx_mbps'] ?? 0);
                $out[$g]['conns'] += (int) ($l['m']['connections'] ?? 0);
            }
            $out[$g]['cap'] += (int) ($e['capacity_mbps'] ?? 0);
        }
        return $out;
    }

    private static function groupCards(array $edges): string
    {
        $h = '<div class="pcdna-groups">';
        $h3 = self::h3Summary($edges);
        foreach (self::groupTotals($edges) as $g => $t) {
            [$label] = self::EDGE_GROUPS[$g];
            $peak = max($t['rx'], $t['tx']);
            $h .= '<div class="pcdna-group" data-group-card="' . $g . '"><div class="pcdna-group-head">' . View::badge('گروه ' . $label, $g === 'tunnel' ? 'violet' : 'muted')
                . '<span class="pcdna-small pcdna-muted">' . View::n($t['online']) . ' آنلاین از ' . View::n($t['edges']) . ' نود فعال'
                . ($t['shed'] ? ' · <span class="pcdna-c-bad">' . View::n($t['shed']) . ' خارج از DNS</span>' : '') . '</span></div>'
                . '<div class="pcdna-group-val"><span dir="ltr">↓' . View::e(self::mbps($t['rx'])) . ' ↑' . View::e(self::mbps($t['tx'])) . '</span>'
                . ($t['cap'] > 0 ? '<small>از ظرفیت ' . View::e(self::mbps($t['cap'])) . '</small>' : '') . '</div>'
                . ($t['cap'] > 0 ? View::meter(min(1, $peak / $t['cap']), $peak / $t['cap'] > .8 ? 'warn' : 'brand') : '')
                . '<div class="pcdna-small pcdna-muted">' . View::n($t['conns']) . ' اتصال همزمان</div>'
                // SPEC §22.9: the client app offers the HTTP/3 variant of an xhttp path only when every node of the group speaks it
                . ($h3 !== null ? '<div class="pcdna-small" data-h3-summary="' . $h3[$g][0] . '/' . $h3[$g][1] . '" title="نسخهٔ HTTP/3 مسیرهای XHTTP فقط وقتی به مشتری پیشنهاد می‌شود که همهٔ نودهای گروه HTTP/3 داشته باشند">'
                    . View::badge('HTTP/3: ' . View::n($h3[$g][0]) . ' از ' . View::n($h3[$g][1]) . ' نود', $h3[$g][1] > 0 && $h3[$g][0] === $h3[$g][1] ? 'ok' : 'muted') . '</div>' : '')
                . '</div>';
        }
        return $h . '</div>';
    }

    private static function eventTable(array $events, array $byDomain, bool $compact): string
    {
        $h = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-events"><thead><tr><th>زمان</th><th>' . ($compact ? 'دامنه / IP' : 'دامنه') . '</th><th>منبع</th><th>اقدام</th>'
            . ($compact ? '' : '<th>IP / کشور</th><th>درخواست / User-Agent</th>') . '</tr></thead><tbody>';
        foreach ($events as $e) {
            if (!is_array($e)) {
                continue;
            }
            $d = strtolower((string) ($e['domain'] ?? $e['host'] ?? ''));
            $svc = $byDomain[$d] ?? null;
            [$at, $atone] = self::ACTIONS[$e['action'] ?? ''] ?? [(string) ($e['action'] ?? ''), 'muted'];
            $h .= '<tr><td title="' . View::e($e['t'] ?? '') . '">' . View::e(View::ago($e['t'] ?? null)) . '</td>'
                . '<td>' . ($svc ? '<a href="' . self::manageUrl((int) $svc->id) . '#pcdn=events">' . View::ltr($d) . '</a>' : View::ltr($d))
                . ($compact ? '<div class="pcdna-small pcdna-muted">' . View::ltr($e['ip'] ?? '') . '</div>' : '') . '</td>'
                . '<td>' . View::badge(self::SOURCES[$e['source'] ?? ''] ?? (string) ($e['source'] ?? ''), 'violet') . '</td>'
                . '<td>' . View::badge($at, $atone) . '</td>';
            if (!$compact) {
                $path = (string) ($e['method'] ?? '') . ' ' . (string) ($e['path'] ?? '');
                $ua = (string) ($e['user_agent'] ?? '');
                $h .= '<td>' . View::ltr($e['ip'] ?? '') . '<div class="pcdna-small pcdna-muted">' . View::ltr($e['country'] ?? '—') . '</div></td>'
                    . '<td><div class="pcdna-clip" dir="ltr" title="' . View::e(View::clip($path, 800)) . '">' . View::e(View::clip($path, 300)) . '</div>'
                    . '<div class="pcdna-clip pcdna-small pcdna-muted" dir="ltr" title="' . View::e(View::clip($ua, 500)) . '">'
                    . (($e['rule'] ?? '') !== '' ? View::e('rule ' . $e['rule'] . ' · ') : '') . View::e($ua !== '' ? View::clip($ua, 200) : '—') . '</div></td>';
            }
            $h .= '</tr>';
        }
        return $h . '</tbody></table></div>';
    }

    // ------------------------------------------------------------------ 2. sites

    public static function sites(array $get): string
    {
        if (($get['view'] ?? '') === 'sync') {
            return self::sync();
        }
        if (($get['view'] ?? '') === 'diag') {
            // SPEC §23.8: the admin-audience diagnostics report of one site («گزارش عیب‌یابی»)
            require_once __DIR__ . '/Ops.php';
            return Ops::siteDiag((int) ($get['service'] ?? 0));
        }
        $f = [
            'q' => View::clip(Env::input($get['q'] ?? ''), 100),
            'status' => array_key_exists((string) ($get['status'] ?? ''), self::WHMCS_STATUS) ? (string) $get['status'] : '',
            'pid' => (int) ($get['pid'] ?? 0),
            'cdn' => in_array((string) ($get['cdn'] ?? ''), ['active', 'pending_ns', 'suspended', 'over_quota', 'missing'], true) ? (string) $get['cdn'] : '',
        ];
        $page = max(1, (int) ($get['p'] ?? 1));
        $per = 25;

        $ping = self::ping();
        $usage = null;
        if ($ping['ok']) {
            $up = '/api/v1/usage?month=' . gmdate('Y-m');
            $r = self::fetch([$up, Operator::LIST]);
            $usage = self::ok($r[$up]) ? (array) ($r[$up]['data']['sites'] ?? []) : null;
            // SPEC §19.1: operator sites belong to no service (the usage rows carry no owner_kind)
            if ($usage !== null) {
                $usage = Data::withoutOperator($usage, self::operatorSet($r[Operator::LIST]));
            }
        }
        $ix = Data::siteIndex($usage ?? []);

        if ($f['cdn'] !== '' && $usage !== null) {
            [$all] = Data::services($f, 1, 100000);
            $all = array_values(array_filter($all, function ($svc) use ($ix, $f) {
                $site = Data::siteFor($svc, $ix);
                return $f['cdn'] === 'missing' ? $site === null : ($site && ($site['status'] ?? '') === $f['cdn']);
            }));
            $total = count($all);
            $rows = array_slice($all, ($page - 1) * $per, $per);
        } else {
            [$rows, $total] = Data::services($f, $page, $per);
        }

        $co = Data::configOptions($rows);
        // §10.2 smart-usage: services the prepaid engine flagged for an upgrade suggestion this month.
        $flags = Data::suggestFlags(\function_exists('pasargadcdn_month') ? \pasargadcdn_month() : gmdate('Y-m'));
        // Per-site details (NS / SSL) for the visible rows only, in parallel.
        $details = [];
        if ($usage !== null) {
            $paths = [];
            foreach ($rows as $svc) {
                $site = Data::siteFor($svc, $ix);
                if ($site) {
                    $paths[(int) $svc->id] = ApiClient::site((string) $site['domain']);
                }
            }
            $res = $paths ? self::fetch(array_values($paths)) : [];
            foreach ($paths as $sid => $p) {
                if (isset($res[$p]) && self::ok($res[$p])) {
                    $details[$sid] = $res[$p]['data'];
                }
            }
        }

        $h = '';
        if (!$ping['ok']) {
            $h .= self::ctlError($ping);
        }
        if ($usage !== null) {
            $sync = Data::sync($usage);
            $n = count($sync['missing']) + count($sync['orphans']) + count($sync['conflicts']);
            if ($n > 0) {
                $h .= View::alert('warn', '<strong>' . View::n($n) . ' مورد ناهمگام</strong> بین WHMCS و کنترلر پیدا شد. '
                    . '<a href="' . View::url(['page' => 'sites', 'view' => 'sync']) . '">مشاهده گزارش همگام‌سازی</a>');
            }
        }

        // filters
        $products = ['' => 'همه محصولات'];
        foreach (Data::products() as $p) {
            $products[(int) $p->id] = $p->name;
        }
        $statuses = ['' => 'همه وضعیت‌های WHMCS'];
        foreach (self::WHMCS_STATUS as $k => [$t]) {
            $statuses[$k] = $t;
        }
        $cdn = ['' => 'همه وضعیت‌های CDN', 'active' => 'فعال', 'pending_ns' => 'در انتظار NS', 'suspended' => 'معلق',
            'over_quota' => 'اتمام ترافیک', 'missing' => 'روی CDN نیست'];
        $h .= '<form method="get" action="addonmodules.php" class="pcdna-filters" role="search">'
            . '<input type="hidden" name="module" value="' . View::e(Env::MODULE) . '"><input type="hidden" name="page" value="sites">'
            . '<label class="pcdna-search">' . View::icon('search') . '<input type="search" name="q" class="pcdna-input" value="' . View::e($f['q'])
            . '" placeholder="جستجوی دامنه، نام مشتری، ایمیل یا #شناسه" aria-label="جستجو"></label>'
            . View::select('status', $statuses, $f['status'], ' aria-label="وضعیت WHMCS"')
            . View::select('pid', $products, $f['pid'] ?: '', ' aria-label="محصول"')
            . View::select('cdn', $cdn, $f['cdn'], ' aria-label="وضعیت CDN"')
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('search') . '<span>اعمال</span></button>'
            . ($f['q'] !== '' || $f['status'] !== '' || $f['pid'] || $f['cdn'] !== '' ? '<a class="pcdna-btn pcdna-btn-ghost" href="' . View::url(['page' => 'sites']) . '">حذف فیلترها</a>' : '')
            . '</form>';

        if (!$rows) {
            $h .= View::card('', $total === 0 && $f === ['q' => '', 'status' => '', 'pid' => 0, 'cdn' => '']
                ? View::emptyState('هنوز سرویس CDN در WHMCS ثبت نشده است', 'پس از اولین سفارش، سرویس‌ها اینجا نمایش داده می‌شوند. برای ساخت محصولات به «پلن‌ها و قیمت‌گذاری» بروید.', 'globe')
                : View::emptyState('نتیجه‌ای پیدا نشد', 'فیلترها را تغییر دهید.', 'search'));
            return $h;
        }

        $t = '<div class="pcdna-table-wrap pcdna-sites-wrap"><table class="pcdna-table pcdna-sites"><thead><tr><th>دامنه / سرویس</th><th>مشتری</th>'
            . '<th>WHMCS / سررسید</th><th>وضعیت CDN</th><th>NS</th><th>SSL</th><th>ترافیک این ماه</th><th><span class="pcdna-sr">عملیات</span></th></tr></thead><tbody>';
        // SPEC §21: «امکانات اختصاصی (n)» badges — one query for the page
        $foCounts = class_exists('\\PasargadCdn\\FeatureOverrides') ? \PasargadCdn\FeatureOverrides::counts(array_map(function ($r) {
            return \PasargadCdn\FeatureOverrides::serviceKey((int) $r->id);
        }, $rows)) : [];
        foreach ($rows as $svc) {
            $sid = (int) $svc->id;
            $site = $usage === null ? false : Data::siteFor($svc, $ix);
            $det = $details[$sid] ?? null;
            $domain = Env::domain((string) $svc->domain);
            // CDN status
            $liveSvc = in_array((string) $svc->domainstatus, Data::LIVE, true);
            if ($site === false) {
                $cdnCell = '<span class="pcdna-muted">—</span>';
            } elseif ($site) {
                $cdnCell = ($site['status'] ?? '') === 'over_quota' && Data::prepaid($svc, $co[(int) $svc->id] ?? []) !== null
                    ? View::badge('قطع به‌دلیل اعتبار ناکافی', 'bad', ' title="ترافیک این ماه تمام شده و اعتبار کیف پول مشتری برای بسته بعدی کافی نیست (یا سقف خرید ماهانه پر شده)"')
                    : self::cdnBadge((string) ($site['status'] ?? ''));
            } elseif ($liveSvc) {
                $cdnCell = self::cdnBadge(null);
            } else {
                $cdnCell = View::badge((string) $svc->domainstatus === 'Pending' ? 'پس از پرداخت ساخته می‌شود' : 'ندارد', 'muted');
            }
            $ns = $det ? (!empty($det['ns_verified']) ? '<span class="pcdna-yes" title="تأیید شده">' . View::icon('check') . '</span>'
                : '<span class="pcdna-no" title="' . View::e('فعلی: ' . implode(', ', (array) ($det['ns_found'] ?? []))) . '">' . View::icon('x') . '</span>')
                : '<span class="pcdna-muted">—</span>';
            $ssl = '<span class="pcdna-muted">—</span>';
            if ($det) {
                $st = (string) ($det['ssl']['status'] ?? 'none');
                $ssl = $st === 'active' ? View::badge('فعال', 'ok', ' title="' . View::e('تا ' . View::date($det['ssl']['expires_at'] ?? null)) . '"')
                    : ($st === 'pending' ? View::badge('در حال صدور', 'warn') : ($st === 'failed' ? View::badge('ناموفق', 'bad', ' title="'
                        . View::e(View::clip((string) ($det['ssl']['error'] ?? ''), 300)) . '"') : View::badge('ندارد', 'muted')));
            }
            $traffic = '<span class="pcdna-muted">—</span>';
            if ($site) {
                $used = (float) ($site['bytes'] ?? 0) / 1073741824;
                $limit = self::includedGb($svc, $site);
                $traffic = '<span class="pcdna-num">' . View::n($used, $used < 10 ? 2 : 1) . ($limit > 0 ? ' از ' . View::n($limit) : '') . ' GB</span>'
                    . ($limit > 0 ? View::meter($used / $limit) : '<span class="pcdna-small pcdna-muted">نامحدود</span>');
            }
            $live = in_array((string) $svc->domainstatus, Data::LIVE, true);
            $q = array_filter(['page' => 'sites', 'q' => $f['q'], 'status' => $f['status'], 'pid' => $f['pid'] ?: null, 'cdn' => $f['cdn'], 'p' => $page > 1 ? $page : null]);
            $menu = '';
            if ($site) {
                $menu .= View::postButton($q, 'purge', ['service' => $sid], 'پاکسازی کل کش', 'pcdna-menu-item', 'کل کش ' . $domain . ' پاکسازی شود؟', 'refresh')
                    . View::postButton($q, 'nscheck', ['service' => $sid], 'بررسی مجدد NS', 'pcdna-menu-item', '', 'sync')
                    . View::postButton($q, 'dnssync', ['service' => $sid], 'همگام‌سازی DNS', 'pcdna-menu-item', '', 'sync')
                    . View::postButton($q, 'ssl', ['service' => $sid], 'درخواست صدور SSL', 'pcdna-menu-item', '', 'key');
            }
            if ((string) $svc->domainstatus === 'Active') {
                $menu .= View::postButton($q, 'suspend', ['service' => $sid], 'تعلیق سرویس', 'pcdna-menu-item is-danger',
                    'سرویس #' . $sid . ' (' . $domain . ') در WHMCS و CDN معلق شود؟', 'power');
            } elseif ((string) $svc->domainstatus === 'Suspended') {
                $menu .= View::postButton($q, 'unsuspend', ['service' => $sid], 'رفع تعلیق سرویس', 'pcdna-menu-item', 'تعلیق سرویس #' . $sid . ' برداشته شود؟', 'power');
            }
            if ($live && $site === null) {
                $menu .= View::postButton($q, 'create', ['service' => $sid], 'ساخت روی CDN (ModuleCreate)', 'pcdna-menu-item', 'سایت ' . $domain . ' روی کنترلر ساخته شود؟', 'plus');
            }
            $menu .= '<a class="pcdna-menu-item" href="' . View::e(Data::serviceUrl((int) $svc->userid, $sid)) . '">' . View::icon('external') . '<span>صفحه سرویس در WHMCS</span></a>';
            // SPEC §23.8: admin-audience diagnostics report (serving nodes, ids) with copy / JSON download
            $menu .= '<a class="pcdna-menu-item" data-diag-link="' . $sid . '" href="' . View::url(['page' => 'sites', 'view' => 'diag', 'service' => $sid]) . '">' . View::icon('info') . '<span>گزارش عیب‌یابی</span></a>';
            if ($live) {
                // SPEC §19.2: «انتقال دامنه» to another client or to the operator
                $menu .= '<a class="pcdna-menu-item" href="' . View::url(['page' => 'transfer', 'service' => $sid]) . '">' . View::icon('users') . '<span>انتقال دامنه</span></a>'
                    // SPEC §21: per-domain feature overrides
                    . '<a class="pcdna-menu-item" href="' . View::url(['page' => 'features', 'service' => $sid]) . '">' . View::icon('sliders') . '<span>امکانات اختصاصی</span></a>';
            }
            $foN = (int) ($foCounts['service:' . $sid] ?? 0);
            $foBadge = $foN > 0 ? '<a class="pcdna-fo-badge" href="' . View::url(['page' => 'features', 'service' => $sid]) . '" data-overrides="' . $foN . '" title="این دامنه امکانات اختصاصی دارد (جدا از پلن محصول)">'
                . View::badge('امکانات اختصاصی (' . View::n($foN) . ')', 'violet') . '</a>' : '';
            $tunnel = '';
            if ($det && !empty($det['plan']['features']['tunnel'])) {
                $tc = (array) ($det['config']['tunnel'] ?? []);
                $np = count((array) ($tc['paths'] ?? []));
                $tunnel = View::badge(!empty($tc['enabled']) ? 'تونل · ' . View::n($np) . ' مسیر' : 'تونل خاموش', !empty($tc['enabled']) ? 'violet' : 'muted',
                    ' data-tunnel="' . (!empty($tc['enabled']) ? 'on' : 'off') . '" title="' . View::e('حالت تونل (VPN) — گروه نود: ' . ($det['plan']['features']['edge_group'] ?? 'general')) . '"');
            }
            $fl = $flags[$sid] ?? null;
            $suggest = '';
            if ($fl && !empty($fl['upgrade'])) {
                $suggest = View::badge('پیشنهاد ارتقا', 'violet', ' data-suggest="upgrade" title="مصرف این سرویس به‌طور مداوم از ترافیک پلن فراتر رفته — پیشنهاد ارتقای پلن به مشتری نمایش داده می‌شود"');
            } elseif ($fl && !empty($fl['forecast'])) {
                $suggest = View::badge('پیش‌بینی اتمام', 'warn', ' data-suggest="forecast" title="طبق روند مصرف، ترافیک این ماه زودتر از پایان ماه تمام می‌شود"');
            }
            $t .= '<tr data-service="' . $sid . '"><td class="pcdna-domain-cell"><a class="pcdna-domain" href="' . self::manageUrl($sid) . '">' . View::ltr($domain !== '' ? $domain : '—') . '</a>'
                . '<div class="pcdna-small pcdna-muted"><a href="' . View::e(Data::serviceUrl((int) $svc->userid, $sid)) . '" title="صفحه سرویس در WHMCS">#' . View::n($sid) . '</a> · '
                . View::e($svc->product) . '</div>' . ($tunnel !== '' ? '<div class="pcdna-tn-line">' . $tunnel . '</div>' : '')
                . ($suggest !== '' ? '<div class="pcdna-tn-line">' . $suggest . '</div>' : '')
                . ($foBadge !== '' ? '<div class="pcdna-tn-line">' . $foBadge . '</div>' : '') . '</td>'
                . '<td class="pcdna-client" data-label="مشتری"><a href="' . View::e(Data::clientUrl((int) $svc->userid)) . '">' . View::e(Data::clientName($svc)) . '</a></td>'
                . '<td data-label="WHMCS / سررسید">' . self::whmcsBadge((string) $svc->domainstatus) . '<div class="pcdna-small pcdna-muted pcdna-nowrap" title="سررسید بعدی">' . View::e(View::date($svc->nextduedate)) . '</div></td>'
                . '<td data-label="وضعیت CDN">' . $cdnCell . '</td><td data-label="NS">' . $ns . '</td><td data-label="SSL">' . $ssl . '</td><td class="pcdna-traffic" data-label="ترافیک این ماه">' . $traffic . '</td>'
                . '<td class="pcdna-actions"><a class="pcdna-btn pcdna-btn-sm pcdna-btn-primary" href="' . self::manageUrl($sid) . '" title="باز کردن پنل کامل CDN این سرویس">' . View::icon('sliders') . '<span>مدیریت کامل</span></a>'
                . '<details class="pcdna-menu"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-icon" aria-label="عملیات بیشتر" title="عملیات بیشتر">' . View::icon('more') . '</summary>'
                . '<div class="pcdna-menu-list">' . $menu . '</div></details></td></tr>';
        }
        $t .= '</tbody></table></div>';
        $h .= View::card('سرویس‌های CDN (' . View::n($total) . ')', $t . self::pager($total, $page, $per, array_filter([
                'page' => 'sites', 'q' => $f['q'], 'status' => $f['status'], 'pid' => $f['pid'] ?: null, 'cdn' => $f['cdn']])),
            '<a class="pcdna-btn pcdna-btn-sm" href="' . View::url(['page' => 'sites', 'view' => 'sync']) . '">' . View::icon('sync') . '<span>همگام‌سازی</span></a>', 'pcdna-flush');
        return $h;
    }

    private static function pager(int $total, int $page, int $per, array $q): string
    {
        $pages = (int) ceil($total / $per);
        if ($pages <= 1) {
            return '';
        }
        $h = '<nav class="pcdna-pager" aria-label="صفحه‌ها">';
        for ($i = 1; $i <= $pages; $i++) {
            if ($pages > 9 && $i > 2 && $i < $pages - 1 && abs($i - $page) > 2) {
                if ($i === 3 || $i === $pages - 2) {
                    $h .= '<span>…</span>';
                }
                continue;
            }
            $h .= $i === $page ? '<span class="is-current" aria-current="page">' . View::n($i) . '</span>'
                : '<a href="' . View::url($q + ['p' => $i]) . '">' . View::n($i) . '</a>';
        }
        return $h . '</nav>';
    }

    public static function sync(): string
    {
        $ping = self::ping();
        $h = '<p class="pcdna-back"><a href="' . View::url(['page' => 'sites']) . '">→ بازگشت به فهرست سایت‌ها</a></p>';
        if (!$ping['ok']) {
            return $h . self::ctlError($ping);
        }
        $r = self::fetch(['/api/v1/sites']);
        if (!self::ok($r['/api/v1/sites'])) {
            return $h . View::alert('bad', 'فهرست سایت‌های کنترلر دریافت نشد: ' . View::e((string) $r['/api/v1/sites']['error']));
        }
        $sync = Data::sync((array) $r['/api/v1/sites']['data']);
        $q = ['page' => 'sites', 'view' => 'sync'];
        $h .= View::alert('info', 'این گزارش سرویس‌های <strong>فعال یا معلق</strong> WHMCS را با سایت‌های کنترلر (بر اساس شناسه سرویس و دامنه) مقایسه می‌کند.');

        $m = '';
        if ($sync['missing']) {
            $m .= '<div class="pcdna-table-wrap"><table class="pcdna-table"><thead><tr><th>سرویس</th><th>دامنه</th><th>مشتری</th><th>محصول</th><th>وضعیت</th><th></th></tr></thead><tbody>';
            foreach ($sync['missing'] as $svc) {
                $m .= '<tr><td><a href="' . View::e(Data::serviceUrl((int) $svc->userid, (int) $svc->id)) . '">#' . View::n($svc->id) . '</a></td>'
                    . '<td>' . View::ltr(Env::domain((string) $svc->domain) ?: '—') . '</td><td>' . View::e(Data::clientName($svc)) . '</td>'
                    . '<td>' . View::e($svc->product) . '</td><td>' . self::whmcsBadge((string) $svc->domainstatus) . '</td><td class="pcdna-actions">'
                    . View::postButton($q, 'create', ['service' => (int) $svc->id], 'ساخت روی CDN', 'pcdna-btn pcdna-btn-sm pcdna-btn-primary',
                        'ماژول برای سرویس #' . (int) $svc->id . ' اجرا شود (ModuleCreate)؟', 'plus') . '</td></tr>';
            }
            $m .= '</tbody></table></div>';
        } else {
            $m = '<p class="pcdna-okline">' . View::icon('check') . '<span>همه سرویس‌های فعال و معلق روی کنترلر سایت دارند.</span></p>';
        }
        $h .= View::card('سرویس‌های WHMCS بدون سایت روی کنترلر', $m, '', '', 'globe');

        if ($sync['conflicts']) {
            $c = '<div class="pcdna-table-wrap"><table class="pcdna-table"><thead><tr><th>سرویس</th><th>دامنه</th><th>external_id روی کنترلر</th></tr></thead><tbody>';
            foreach ($sync['conflicts'] as $x) {
                $c .= '<tr><td><a href="' . View::e(Data::serviceUrl((int) $x['service']->userid, (int) $x['service']->id)) . '">#' . View::n($x['service']->id) . '</a></td>'
                    . '<td>' . View::ltr($x['site']['domain']) . '</td><td>' . View::ltr($x['site']['external_id'] ?? '—') . '</td></tr>';
            }
            $c .= '</tbody></table></div><p class="pcdna-muted">این دامنه‌ها روی کنترلر به سرویس دیگری تعلق دارند. ابتدا مالک درست را مشخص کنید؛ '
                . 'اگر سرویس قبلی حذف‌شده است، سایت آن را در جدول پایین حذف و سپس «ساخت روی CDN» را اجرا کنید.</p>';
            $h .= View::card('تداخل دامنه', $c, '', 'pcdna-card-bad', 'warn');
        }

        $o = '';
        if ($sync['orphans']) {
            $o .= '<div class="pcdna-table-wrap"><table class="pcdna-table"><thead><tr><th>دامنه</th><th>وضعیت CDN</th><th>external_id</th><th>سرویس WHMCS</th><th></th></tr></thead><tbody>';
            foreach ($sync['orphans'] as $x) {
                $s = $x['site'];
                $svc = $x['service'];
                $o .= '<tr><td>' . View::ltr($s['domain']) . '</td><td>' . self::cdnBadge((string) ($s['status'] ?? '')) . '</td>'
                    . '<td>' . View::ltr(($s['external_id'] ?? '') !== '' ? $s['external_id'] : '—') . '</td>'
                    . '<td>' . ($svc ? '<a href="' . View::e(Data::serviceUrl((int) $svc->userid, (int) $svc->id)) . '">#' . View::n($svc->id) . '</a> '
                        . self::whmcsBadge((string) $svc->domainstatus) : '<span class="pcdna-muted">وجود ندارد</span>') . '</td>'
                    . '<td class="pcdna-actions"><form method="post" action="' . View::url($q) . '" class="pcdna-inline" data-confirm-type="' . View::e($s['domain']) . '">'
                    . View::csrf() . '<input type="hidden" name="a" value="orphan_delete"><input type="hidden" name="domain" value="' . View::e($s['domain']) . '">'
                    . '<input type="hidden" name="confirm" value="">'
                    . '<button type="submit" class="pcdna-btn pcdna-btn-sm pcdna-btn-danger">' . View::icon('trash') . '<span>حذف از کنترلر</span></button></form></td></tr>';
            }
            $o .= '</tbody></table></div><p class="pcdna-muted">حذف، زون DNS و همه تنظیمات سایت را روی کنترلر پاک می‌کند و برگشت‌پذیر نیست. برای تأیید باید نام دامنه را تایپ کنید.</p>';
        } else {
            $o = '<p class="pcdna-okline">' . View::icon('check') . '<span>سایت بدون سرویس روی کنترلر وجود ندارد.</span></p>';
        }
        $h .= View::card('سایت‌های کنترلر بدون سرویس فعال در WHMCS', $o, '', '', 'server');

        // Security review C1: owners of the sites (client_id) — sites made by an older module have none
        require_once __DIR__ . '/OwnerSync.php';
        $unowned = OwnerSync::unowned((array) $r['/api/v1/sites']['data']);
        $btn = View::postButton($q, 'owner_sync', [], 'همگام‌سازی مالکیت دامنه‌ها', 'pcdna-btn pcdna-btn-sm pcdna-btn-primary', '', 'sync');
        if ($unowned === null) {
            $w = '<p class="pcdna-muted">کنترلر هنوز مالک سایت‌ها را نمی‌شناسد (نسخهٔ پیش از بازبینی امنیتی).</p>';
            $btn = '';
        } elseif ($unowned > 0) {
            $w = View::alert('warn', View::n($unowned) . ' سرویس فعال یا معلق سایتی بدون مالک روی کنترلر دارد؛ تا مالک ثبت نشود، محافظت در برابر '
                . 'ثبت زیردامنهٔ مشتری دیگر برای این دامنه‌ها کامل نیست و مشتری نمی‌تواند زیردامنهٔ دامنهٔ خودش را سفارش دهد. '
                . '«همگام‌سازی مالکیت دامنه‌ها» شناسهٔ مشتری WHMCS هر سرویس را روی سایتش ثبت می‌کند (کران هم هر بار حداکثر '
                . View::n(OwnerSync::MAX_PER_RUN) . ' سایت را انجام می‌دهد).');
        } else {
            $w = '<p class="pcdna-okline">' . View::icon('check') . '<span>همه سایت‌های سرویس‌های فعال و معلق مالک دارند.</span></p>';
        }
        $h .= View::card('مالکیت دامنه‌ها', $w, $btn, '', 'shield');
        return $h;
    }

    // ------------------------------------------------------------------ 3. edges

    public static function edges(?array $newToken = null, array $old = [], array $get = [], array $batch = []): string
    {
        if (($get['view'] ?? '') === 'availability') {
            return self::availability();
        }
        if (($get['view'] ?? '') === 'logs') {
            return self::edgeLogs((int) ($get['id'] ?? 0));
        }
        if (($get['view'] ?? '') === 'addresses') {
            return self::edgeAddresses((int) ($get['id'] ?? 0));
        }
        if (($get['view'] ?? '') === 'detail') {
            return self::edgeDetail((int) ($get['id'] ?? 0));
        }
        $ping = self::ping();
        $h = '';
        $ctlUrl = Env::controllerUrl();
        if ($newToken) {
            // the controller's own one-liner when it sent one (POST /api/v1/edges), else built the same way (rotate-token)
            $cmd = is_string($newToken['install'] ?? null) && $newToken['install'] !== '' ? (string) $newToken['install']
                : self::installCmd($ctlUrl, (string) $newToken['token'], (string) ($newToken['region'] ?? 'home'), (string) ($newToken['role'] ?? 'general'));
            $h .= '<section class="pcdna-card pcdna-token" data-token-panel="1"><header class="pcdna-card-head"><h3>' . View::icon('key') . '<span>'
                . View::e($newToken['title']) . '</span></h3></header><div class="pcdna-card-body">'
                . View::alert('warn', '<strong>این توکن فقط همین یک بار نمایش داده می‌شود</strong> و جایی ذخیره یا ثبت نمی‌شود. همین حالا آن را کپی کنید.')
                . '<p class="pcdna-label">توکن نود ' . View::ltr($newToken['name']) . '</p>' . View::copyable($newToken['token'], 'کپی توکن')
                . '<p class="pcdna-label">دستور نصب تک‌خطی روی سرور نود (فقط این را اجرا کنید — بوت‌استرپ بستهٔ edge را از کنترلر می‌گیرد و نصب می‌کند):</p>' . View::copyable($cmd, 'کپی دستور')
                . '<p class="pcdna-muted">پس از اجرای دستور، حداکثر یک دقیقه بعد نود «آنلاین» می‌شود و در پاسخ DNS سایت‌ها قرار می‌گیرد.</p></div></section>';
        }
        if ($batch) {
            $h .= self::batchResult($batch, $ctlUrl);
        }
        if (!$ping['ok']) {
            return $h . self::ctlError($ping);
        }
        $tag = strtolower(Env::input($get['tag'] ?? ''));
        $tag = preg_match('/^[0-9a-f]{8}$/D', $tag) ? $tag : '';
        $r = self::fetch(['/api/v1/edges', '/edge/version', '/api/v1/overview']);
        // SPEC §22.4: how many sites use several origins per tunnel path (overview.tunnel_multi_origin_sites, wave 13)
        self::$multiSites = self::ok($r['/api/v1/overview']) && is_numeric($r['/api/v1/overview']['data']['tunnel_multi_origin_sites'] ?? null)
            ? (int) $r['/api/v1/overview']['data']['tunnel_multi_origin_sites'] : 0;
        $bundle = self::ok($r['/edge/version']) && is_string($r['/edge/version']['data']['version'] ?? null)
            ? (string) $r['/edge/version']['data']['version'] : null;
        $edges = self::ok($r['/api/v1/edges']) ? (array) $r['/api/v1/edges']['data'] : null;
        $online = 0;
        foreach ((array) $edges as $e) {
            $online += self::edgeOnline($e) ? 1 : 0;
        }
        $series = $edges !== null ? self::uptimeSeries($edges) : null;
        if ($edges !== null && self::wave14($edges)) {
            // SPEC §23.1 / §23.12: pinned releases + controller version, the customer-label city list and the tag lookup
            require_once __DIR__ . '/Ops.php';
            $rr = self::fetch(['/api/v1/releases', '/healthz']);
            $h .= Ops::pinnedLine(self::ok($rr['/api/v1/releases']) ? $rr['/api/v1/releases']['data'] : null,
                self::ok($rr['/healthz']) && is_string($rr['/healthz']['data']['version'] ?? null) ? $rr['/healthz']['data']['version'] : null);
            $h .= self::cityList() . self::tagSearch($tag);
        }
        if ($edges !== null) {
            $h .= self::drainForceCard($edges, ['page' => 'edges']);
            foreach (self::saturated($edges) as $e) {
                $h .= View::alert(!empty($e['shed']) ? 'bad' : 'warn', 'نود ' . View::ltr($e['name'] ?? '') . (!empty($e['shed'])
                    ? ' اشباع شده و موقتاً از پاسخ DNS خارج است؛ ترافیک به نودهای دیگر همان گروه می‌رود. ظرفیت اضافه کنید یا نود جدید به این گروه بیاورید.'
                    : ' بیش از ۸۰٪ ظرفیت خود بار دارد.'));
            }
            $h .= View::card('گروه‌های نود', self::groupCards($edges), '', '', 'activity');
        }
        $h .= View::card('نودهای CDN' . ($edges !== null ? ' (' . View::n($online) . ' آنلاین از ' . View::n(count($edges)) . ')' : ''),
            $edges === null ? View::alert('bad', 'فهرست نودها دریافت نشد: ' . View::e((string) $r['/api/v1/edges']['error']))
                : self::edgeTable($edges, true, $series, $bundle, $ctlUrl) . self::edgePerfNote($edges),
            '<a class="pcdna-btn pcdna-btn-sm" href="' . View::url(['page' => 'edges', 'view' => 'availability']) . '">' . View::icon('activity') . '<span>گزارش در دسترس‌بودن</span></a>',
            'pcdna-flush', 'server');

        $form = '<form method="post" action="' . View::url(['page' => 'edges']) . '" class="pcdna-form" autocomplete="off">' . View::csrf()
            . '<input type="hidden" name="a" value="edge_add"><div class="pcdna-form-grid">'
            . '<label><span>نام نود</span><input class="pcdna-input" name="name" dir="ltr" required maxlength="64" pattern="[A-Za-z0-9_.\-]{1,64}" placeholder="ir-thr-1" value="' . View::e($old['name'] ?? '') . '">'
            . '<small>حروف انگلیسی، عدد، نقطه، خط تیره</small></label>'
            . '<label><span>IPv4 عمومی</span><input class="pcdna-input" name="ipv4" dir="ltr" required maxlength="15" placeholder="5.160.10.20" value="' . View::e($old['ipv4'] ?? '') . '"></label>'
            . '<label><span>IPv6 (اختیاری)</span><input class="pcdna-input" name="ipv6" dir="ltr" maxlength="45" placeholder="2a01:…" value="' . View::e($old['ipv6'] ?? '') . '"></label>'
            . '<label><span>منطقه</span>' . View::select('region', ['home' => 'ایران (home)', 'global' => 'خارج از ایران (global)'], $old['region'] ?? 'home') . '</label>'
            . '<label><span>گروه</span>' . View::select('group', ['general' => 'عمومی (سایت‌ها)', 'tunnel' => 'تونل (VPN)'], $old['group'] ?? 'general') . '</label>'
            . '<label><span>ظرفیت پهنای باند (Mbps)</span><input class="pcdna-input" name="capacity_mbps" dir="ltr" inputmode="numeric" maxlength="8" placeholder="1000" value="' . View::e($old['capacity_mbps'] ?? '') . '">'
            . '<small>۰ یا خالی = نامشخص (بدون خروج خودکار از DNS)</small></label>'
            . '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('plus') . '<span>افزودن نود و ساخت توکن</span></button></div></form>';
        $regions = '<ul class="pcdna-bullets"><li><strong>ایران (home):</strong> نودهای داخل ایران. با GeoDNS، کاربران ایرانی ابتدا به این نودها هدایت می‌شوند؛ '
            . 'ترافیک داخلی ارزان‌تر است و در قطعی اینترنت بین‌الملل، سایت برای کاربران داخل در دسترس می‌ماند.</li>'
            . '<li><strong>خارج (global):</strong> نودهای خارج از ایران برای بازدیدکنندگان خارجی و به‌عنوان پشتیبان وقتی همه نودهای ایران از دسترس خارج شوند.</li>'
            . '<li>بدون GeoDNS همه نودهای سالم به‌صورت تصادفی در پاسخ DNS قرار می‌گیرند. نود «آنلاین» یعنی در ۳ دقیقه اخیر با کنترلر ارتباط داشته است.</li>'
            . '<li>غیرفعال کردن نود آن را برای نگهداری از DNS خارج می‌کند؛ «توکن جدید» توکن فعلی را باطل می‌کند.</li>'
            . '<li><strong>گروه:</strong> سایت‌های پلن‌های تونل (VPN) فقط به نودهای گروه «تونل» و بقیه سایت‌ها فقط به نودهای «عمومی» هدایت می‌شوند؛ '
            . 'اگر گروهی نود آنلاین نداشته باشد، همه نودها پاسخ می‌دهند. ترافیک سنگین تونل‌ها این‌طور روی سایت‌های معمولی اثر نمی‌گذارد.</li>'
            . '<li><strong>ظرفیت و بار:</strong> نودها هر دقیقه ترافیک ورودی/خروجی، تعداد اتصال و بار CPU را گزارش می‌کنند. نودی که به ۹۰٪ ظرفیت برسد موقتاً از DNS خارج می‌شود '
            . '(به شرط ماندن نود دیگری در همان گروه و منطقه) و زیر ۷۵٪ برمی‌گردد.</li></ul>';
        $h .= '<div class="pcdna-grid-2">' . View::card('افزودن نود جدید', $form, '', '', 'plus') . View::card('منطقه‌ها، گروه‌ها و وضعیت نودها', $regions, '', '', 'info') . '</div>';
        $bold = $batch['old'] ?? [];
        $batchForm = '<form method="post" action="' . View::url(['page' => 'edges']) . '" class="pcdna-form" autocomplete="off">' . View::csrf()
            . '<input type="hidden" name="a" value="edge_batch"><div class="pcdna-form-grid">'
            . '<label><span>تعداد نود</span><input class="pcdna-input" name="count" dir="ltr" inputmode="numeric" required min="1" max="50" type="number" placeholder="5" value="' . View::e($bold['count'] ?? '') . '">'
            . '<small>۱ تا ۵۰ نود در یک درخواست</small></label>'
            . '<label><span>منطقه</span>' . View::select('region', ['home' => 'ایران (home)', 'global' => 'خارج از ایران (global)'], $bold['region'] ?? 'home') . '</label>'
            . '<label><span>نقش (گروه)</span>' . View::select('group', ['general' => 'عمومی (سایت‌ها)', 'tunnel' => 'تونل (VPN)'], $bold['group'] ?? 'general') . '</label>'
            . '<label><span>پیشوند نام (اختیاری)</span><input class="pcdna-input" name="name_prefix" dir="ltr" maxlength="48" pattern="[A-Za-z0-9_.\-]{1,48}" placeholder="ir-thr" value="' . View::e($bold['name_prefix'] ?? '') . '">'
            . '<small>نام‌ها به‌صورت <code dir="ltr">پیشوند-۱</code>، <code dir="ltr">پیشوند-۲</code> … ساخته می‌شوند</small></label>'
            . '<label><span>ظرفیت پهنای باند (Mbps)</span><input class="pcdna-input" name="capacity_mbps" dir="ltr" inputmode="numeric" maxlength="8" placeholder="1000" value="' . View::e($bold['capacity_mbps'] ?? '') . '">'
            . '<small>روی همهٔ نودهای این دسته اعمال می‌شود</small></label>'
            . '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('plus') . '<span>افزودن گروهی و ساخت توکن‌ها</span></button></div></form>'
            . '<p class="pcdna-muted pcdna-small">پس از ثبت، برای هر نود یک دستور نصب تک‌خطی آماده نمایش داده می‌شود که فقط همان یک بار قابل مشاهده است. IP هر نود پس از اولین ارتباط با کنترلر ثبت می‌شود.</p>';
        $h .= View::card('افزودن گروهی نودها', $batchForm, '', '', 'server');
        return $h;
    }

    /**
     * Bootstrap one-command install for a node (SPEC §11.1): downloads the bundle from the controller and runs it.
     * Same shape as the controller's bundle.install_command: the one-time token travels in the environment
     * (PCDN_EDGE_TOKEN, read by edge/bootstrap.sh), not on bash's argv, so other local users cannot see it in
     * ps / /proc/<pid>/cmdline while the node installs. Used when the controller did not send its own `install`.
     */
    public static function installCmd(string $ctlUrl, string $token, string $region = 'home', string $role = 'general'): string
    {
        $ctl = $ctlUrl !== '' ? $ctlUrl : 'https://<controller>';
        $region = $region === 'global' ? 'global' : 'home';
        $role = $role === 'tunnel' ? 'tunnel' : 'general';
        return 'curl -fsSL ' . $ctl . '/edge/bootstrap.sh | sudo PCDN_EDGE_TOKEN=' . self::shellQuote($token) . ' bash -s -- --controller ' . $ctl
            . ' --region ' . $region . ' --role ' . $role;
    }

    /**
     * Python's shlex.quote (the controller's quoting, byte for byte): safe words as they are, anything else in
     * single quotes with ' as '"'"'. Unlike escapeshellarg() it never drops non-ASCII bytes under a C locale.
     */
    public static function shellQuote(string $v): string
    {
        if ($v !== '' && preg_match('#^[A-Za-z0-9@%+=:,./_-]+$#D', $v)) {
            return $v;
        }
        return "'" . str_replace("'", "'\"'\"'", $v) . "'";
    }

    /** Re-run bootstrap with --upgrade on an existing node to pull the current bundle (SPEC §11.1). */
    public static function upgradeCmd(string $ctlUrl): string
    {
        $ctl = $ctlUrl !== '' ? $ctlUrl : 'https://<controller>';
        return 'curl -fsSL ' . $ctl . '/edge/bootstrap.sh | sudo bash -s -- --controller ' . $ctl . ' --upgrade';
    }

    /** Rendered result of a batch add: one copyable one-liner per new node (shown once). */
    private static function batchResult(array $batch, string $ctlUrl): string
    {
        $rows = $batch['rows'] ?? null;
        if (!is_array($rows) || !$rows) {
            return '';
        }
        $body = View::alert('warn', '<strong>این توکن‌ها فقط همین یک بار نمایش داده می‌شوند</strong> و جایی ذخیره نمی‌شوند. دستورها را همین حالا کپی و روی هر سرور اجرا کنید.');
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }
            $name = (string) ($row['name'] ?? ($row['edge']['name'] ?? ''));
            $cmd = is_string($row['install'] ?? null) && $row['install'] !== ''
                ? (string) $row['install']
                : self::installCmd($ctlUrl, (string) ($row['token'] ?? ''),
                    (string) ($row['region'] ?? ($row['edge']['region'] ?? 'home')),
                    (($row['group'] ?? ($row['edge']['group'] ?? 'general')) === 'tunnel') ? 'tunnel' : 'general');
            $body .= '<p class="pcdna-label">نود ' . View::ltr($name) . '</p>' . View::copyable($cmd, 'کپی دستور');
        }
        return '<section class="pcdna-card pcdna-token" data-batch-panel="1"><header class="pcdna-card-head"><h3>' . View::icon('server')
            . '<span>دستورهای نصب نودهای جدید</span></h3></header><div class="pcdna-card-body">' . $body . '</div></section>';
    }

    /** Per-node centralized logs view (SPEC §11.2): GET /api/v1/edges/{id}/logs, newest-first, level-coloured. */
    public static function edgeLogs(int $id): string
    {
        $back = '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::url(['page' => 'edges']) . '">' . View::icon('server') . '<span>بازگشت به نودها</span></a>';
        if ($id <= 0) {
            return $back . View::alert('bad', 'شناسه نود نامعتبر است.');
        }
        $ping = self::ping();
        if (!$ping['ok']) {
            return $back . self::ctlError($ping);
        }
        $path = '/api/v1/edges/' . $id . '/logs';
        $r = self::fetch([$path]);
        if (!self::ok($r[$path])) {
            $code = (int) ($r[$path]['code'] ?? 0);
            return $back . View::alert('bad', $code === 404 ? 'نودی با این شناسه پیدا نشد.'
                : 'دریافت لاگ‌های نود ناموفق بود: ' . View::e((string) ($r[$path]['error'] ?? 'خطای نامشخص')));
        }
        $data = (array) $r[$path]['data'];
        $name = (string) ($data['name'] ?? ('#' . $id));
        $lines = is_array($data['lines'] ?? null) ? $data['lines'] : [];
        $at = $data['logs_at'] ?? null;
        $title = 'لاگ‌های نود ' . $name;
        if (!$lines) {
            return View::card($title, View::emptyState('لاگی گزارش نشده', 'این نود تاکنون خط خطا یا هشداری به کنترلر نفرستاده است. agent فقط خطوط WARN/ERROR/crit را می‌فرستد.', 'info'), $back, '', 'server');
        }
        $intro = View::alert('info', 'تازه‌ترین خطوط خطا و هشدار گزارش‌شده توسط این نود (فقط عملیاتی؛ بدون IP بازدیدکننده، توکن یا کلید). '
            . ($at ? 'آخرین گزارش: <span title="' . View::e((string) $at) . '">' . View::e(View::ago($at)) . '</span>.' : ''));
        $body = '<ul class="pcdna-logs">';
        foreach (array_reverse($lines) as $ln) {
            if (!is_array($ln)) {
                continue;
            }
            $level = strtolower((string) ($ln['level'] ?? 'info'));
            [$tone, $lbl] = self::LOG_LEVELS[$level] ?? ['muted', $level];
            $t = $ln['t'] ?? null;
            $body .= '<li class="pcdna-log-line pcdna-log-' . View::e($level) . '" data-level="' . View::e($level) . '">'
                . View::badge($lbl, $tone, ' data-lvl="' . View::e($level) . '"')
                . '<code class="pcdna-log-msg" dir="ltr">' . View::e((string) ($ln['msg'] ?? '')) . '</code>'
                . '<span class="pcdna-log-t pcdna-muted pcdna-small" title="' . View::e((string) $t) . '">' . View::e(View::ago($t)) . '</span></li>';
        }
        $body .= '</ul>';
        return View::card($title, $intro . $body, $back, 'pcdna-flush', 'server');
    }

    const LOG_LEVELS = ['crit' => ['bad', 'بحرانی'], 'critical' => ['bad', 'بحرانی'], 'error' => ['bad', 'خطا'],
        'err' => ['bad', 'خطا'], 'warn' => ['warn', 'هشدار'], 'warning' => ['warn', 'هشدار'],
        'notice' => ['muted', 'اطلاع'], 'info' => ['muted', 'اطلاع']];

    // ------------------------------------------------------------------ §12 multi-address edges & health-based failover

    /**
     * Per-node «آدرس‌ها» panel (SPEC §12.5): the PRIMARY address(es) and any ADDITIONAL addresses,
     * each with per-address health (سالم / در حال بررسی / قطع) and whether it is currently advertised
     * in DNS. Failover is AUTOMATIC and health-based — this panel only manages addresses; there is no
     * "force/switch to this IP now" control. Fetched on demand, like the logs view; degrades gracefully
     * when the controller does not yet expose the addresses endpoint.
     */
    public static function edgeAddresses(int $id): string
    {
        $back = '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::url(['page' => 'edges']) . '">' . View::icon('server') . '<span>بازگشت به نودها</span></a>';
        if ($id <= 0) {
            return $back . View::alert('bad', 'شناسه نود نامعتبر است.');
        }
        $ping = self::ping();
        if (!$ping['ok']) {
            return $back . self::ctlError($ping);
        }
        $addrPath = '/api/v1/edges/' . $id . '/addresses';
        $r = self::fetch([$addrPath, '/api/v1/edges']);
        $edges = self::ok($r['/api/v1/edges']) ? (array) $r['/api/v1/edges']['data'] : [];
        $edge = null;
        foreach ($edges as $e) {
            if (is_array($e) && (int) ($e['id'] ?? 0) === $id) {
                $edge = $e;
                break;
            }
        }
        if ($edge === null) {
            return $back . View::alert('bad', 'نودی با این شناسه پیدا نشد.');
        }
        $name = (string) ($edge['name'] ?? ('#' . $id));
        $title = 'آدرس‌های نود ' . $name;
        $addrOk = self::ok($r[$addrPath]);
        $addrData = $addrOk ? (array) $r[$addrPath]['data'] : null;
        $code = (int) ($r[$addrPath]['code'] ?? 0);
        // Feature-detect: the node exists but the addresses endpoint is absent (older controller) → 404.
        $featureMissing = !$addrOk && $code === 404;
        $rows = self::addressRows($addrData, $edge);

        $note = View::alert('info', '<strong>جابه‌جایی خودکار است.</strong> آدرس فعال به‌صورت خودکار بر اساس سلامت انتخاب می‌شود '
            . '(کنترلر دسترس‌پذیری هر آدرس را دوره‌ای بررسی می‌کند)؛ آدرس سالم در DNS اعلام و آدرس قطع‌شده به‌صورت خودکار کنار گذاشته می‌شود. '
            . 'در این صفحه فقط آدرس‌ها را مدیریت می‌کنید (افزودن، ویرایش/تغییر برچسب، فعال/غیرفعال برای نگهداری، حذف)؛ '
            . 'هیچ گزینه‌ای برای «انتخاب دستی آدرس فعال» وجود ندارد.');
        if (!$addrOk) {
            $note .= View::alert('warn', $featureMissing
                ? 'مدیریت آدرس‌های اضافی روی نسخهٔ فعلی کنترلر در دسترس نیست؛ فقط آدرس اصلی نمایش داده می‌شود. برای فعال‌سازی چند-آدرسی، کنترلر را به‌روزرسانی کنید.'
                : 'دریافت کامل فهرست آدرس‌ها ناموفق بود: ' . View::e((string) ($r[$addrPath]['error'] ?? 'خطای نامشخص')) . ' — فقط آدرس اصلی نمایش داده می‌شود.');
        }
        $manage = $addrOk;
        $body = $note . self::addressTable($rows, $id, $manage);
        if ($manage) {
            $body .= self::addressAddForm($id);
        }
        return View::card($title, $body, $back, '', 'globe');
    }

    /** Health of an address from its probe result: [label, tone]. null = never probed yet. */
    public static function addrHealth($probeOk): array
    {
        if ($probeOk === true) {
            return ['سالم', 'ok'];
        }
        if ($probeOk === false) {
            return ['قطع', 'bad'];
        }
        return ['در حال بررسی', 'warn'];
    }

    /** Normalise one address (from the controller, or synthesised) into a stable render shape. */
    private static function normAddr(array $a, bool $primary): array
    {
        $ip = (string) ($a['ip'] ?? '');
        $fam = (int) ($a['family'] ?? 0);
        if ($fam !== 4 && $fam !== 6) {
            $fam = strpos($ip, ':') !== false ? 6 : 4;
        }
        $enabled = array_key_exists('enabled', $a) ? (bool) $a['enabled'] : true;
        $probeOk = array_key_exists('probe_ok', $a) ? $a['probe_ok'] : null;
        if ($probeOk !== true && $probeOk !== false) {
            $probeOk = null;
        }
        $adv = array_key_exists('advertised', $a) ? (bool) $a['advertised'] : ($enabled && $probeOk !== false);
        return ['id' => isset($a['id']) && is_numeric($a['id']) ? (int) $a['id'] : null, 'family' => $fam, 'ip' => $ip,
            'label' => (string) ($a['label'] ?? ''), 'enabled' => $enabled, 'probe_ok' => $probeOk,
            'probe_at' => $a['probe_at'] ?? null, 'probe_error' => (string) ($a['probe_error'] ?? ''),
            'advertised' => $adv, 'primary' => $primary];
    }

    /**
     * Unified, defensively-parsed address list: primary row(s) first, then additional addresses.
     * Reads `primary` as a single dict, a list, or an {ipv4,ipv6} pair; falls back to the edge object's
     * own ipv4/ipv6 + probe when the controller returns no usable `primary` (e.g. feature not present).
     */
    private static function addressRows(?array $addrData, array $edge): array
    {
        $rows = [];
        $primList = [];
        $primary = is_array($addrData['primary'] ?? null) ? $addrData['primary'] : null;
        if ($primary !== null) {
            if (isset($primary['ip']) || isset($primary['family'])) {
                $primList[] = $primary;
            } elseif (array_is_list($primary)) {
                foreach ($primary as $p) {
                    if (is_array($p)) {
                        $primList[] = $p;
                    }
                }
            } else {
                if (!empty($primary['ipv4'])) {
                    $primList[] = ['family' => 4, 'ip' => $primary['ipv4']] + $primary;
                }
                if (!empty($primary['ipv6'])) {
                    $primList[] = ['family' => 6, 'ip' => $primary['ipv6']] + $primary;
                }
            }
        }
        if (!$primList) {
            $probe = is_array($edge['probe'] ?? null) ? $edge['probe'] : [];
            $pk = array_key_exists('ok', $probe) ? $probe['ok'] : ($edge['probe_ok'] ?? null);
            $pat = $probe['at'] ?? ($edge['probe_at'] ?? null);
            $en = !empty($edge['enabled']);
            if (!empty($edge['ipv4'])) {
                $primList[] = ['family' => 4, 'ip' => $edge['ipv4'], 'probe_ok' => $pk, 'probe_at' => $pat, 'enabled' => $en];
            }
            if (!empty($edge['ipv6'])) {
                $primList[] = ['family' => 6, 'ip' => $edge['ipv6'], 'probe_ok' => $pk, 'probe_at' => $pat, 'enabled' => $en];
            }
        }
        foreach ($primList as $p) {
            if (is_array($p)) {
                $rows[] = self::normAddr($p, true);
            }
        }
        $add = is_array($addrData['addresses'] ?? null) ? $addrData['addresses'] : [];
        foreach ($add as $a) {
            if (is_array($a) && empty($a['primary'])) {
                $rows[] = self::normAddr($a, false);
            }
        }
        return $rows;
    }

    /** Renders the address table: IP, family, label, per-address health, DNS/advertise state, actions. */
    private static function addressTable(array $rows, int $id, bool $manage): string
    {
        if (!$rows) {
            return View::emptyState('آدرسی برای نمایش نیست', 'این نود آدرس قابل نمایشی ندارد.', 'globe');
        }
        $h = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-addrs"><thead><tr>'
            . '<th>آدرس</th><th>نسخه</th><th>برچسب</th><th>سلامت</th><th>وضعیت در DNS</th>'
            . ($manage ? '<th><span class="pcdna-sr">عملیات</span></th>' : '') . '</tr></thead><tbody>';
        foreach ($rows as $a) {
            $primary = !empty($a['primary']);
            [$hl, $ht] = self::addrHealth($a['probe_ok']);
            $fam = (int) $a['family'];
            if (!$a['enabled']) {
                $dns = View::badge('غیرفعال (نگهداری)', 'muted', ' title="برای نگهداری غیرفعال شده و در DNS اعلام نمی‌شود"');
            } elseif (!empty($a['advertised'])) {
                $dns = View::badge('در DNS', 'ok', ' title="هم‌اکنون در پاسخ DNS اعلام می‌شود"');
            } else {
                $dns = View::badge('خارج از DNS', 'bad', ' title="به‌دلیل قطعی، به‌صورت خودکار از DNS کنار گذاشته شده است"');
            }
            $h .= '<tr data-addr="' . ($a['id'] ?? '') . '"' . ($primary ? ' data-primary="1"' : '') . '>'
                . '<td><strong>' . View::ltr($a['ip']) . '</strong>'
                . ($primary ? ' ' . View::badge('اصلی', 'brand', ' title="آدرس اصلی و هویتی نود"') : '') . '</td>'
                . '<td>' . View::badge('IPv' . ($fam === 6 ? '6' : '4'), 'violet') . '</td>'
                . '<td>' . ($a['label'] !== '' ? View::e($a['label']) : '<span class="pcdna-muted">—</span>') . '</td>'
                . '<td><span title="' . View::e($a['probe_at'] ? 'آخرین بررسی: ' . View::ago($a['probe_at']) : 'هنوز بررسی نشده است') . '">' . View::badge($hl, $ht) . '</span>'
                . ($a['probe_error'] !== '' ? '<div class="pcdna-small pcdna-muted pcdna-clip" dir="ltr" title="' . View::e(View::clip($a['probe_error'], 300)) . '">' . View::e(View::clip($a['probe_error'], 80)) . '</div>' : '') . '</td>'
                . '<td>' . $dns . '</td>';
            if ($manage) {
                $h .= '<td class="pcdna-actions">' . ($primary ? self::primaryHint() : self::addrActions($id, $a)) . '</td>';
            }
            $h .= '</tr>';
        }
        return $h . '</tbody></table></div>';
    }

    /** The primary is the node's identity address: point at the existing edit-node form (don't duplicate it). */
    private static function primaryHint(): string
    {
        return '<span class="pcdna-small pcdna-muted">برای اصلاح، نود را از «ویرایش نود» در فهرست نودها تغییر دهید.</span>';
    }

    /** Per-address actions for an ADDITIONAL address: edit/rename, enable/disable for maintenance, remove. */
    private static function addrActions(int $id, array $a): string
    {
        $aid = (int) $a['id'];
        $q = ['page' => 'edges', 'view' => 'addresses', 'id' => $id];
        $fam = (int) $a['family'];
        $edit = '<details class="pcdna-menu pcdna-addr-edit"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-icon" aria-label="ویرایش آدرس ' . View::e($a['ip']) . '" title="ویرایش آدرس و برچسب">'
            . View::icon('sliders') . '</summary><div class="pcdna-menu-list"><form method="post" action="' . View::url($q) . '" class="pcdna-edge-form">' . View::csrf()
            . '<input type="hidden" name="a" value="edge_addr_edit"><input type="hidden" name="id" value="' . $id . '"><input type="hidden" name="aid" value="' . $aid . '"><input type="hidden" name="family" value="' . $fam . '">'
            . '<label><span>آدرس IPv' . ($fam === 6 ? '6' : '4') . '</span><input class="pcdna-input" name="ip" dir="ltr" maxlength="45" value="' . View::e($a['ip']) . '"></label>'
            . '<label><span>برچسب (اختیاری)</span><input class="pcdna-input" name="label" maxlength="64" value="' . View::e($a['label']) . '" placeholder="مثلاً لینک دوم"></label>'
            . '<button type="submit" class="pcdna-btn pcdna-btn-sm pcdna-btn-primary">' . View::icon('check') . '<span>ذخیره</span></button></form></div></details>';
        $toggle = View::postButton($q, 'edge_addr_toggle', ['id' => $id, 'aid' => $aid, 'enabled' => $a['enabled'] ? '0' : '1'],
            $a['enabled'] ? 'غیرفعال‌سازی برای نگهداری' : 'فعال‌سازی', 'pcdna-btn pcdna-btn-sm pcdna-btn-icon',
            $a['enabled'] ? 'آدرس «' . $a['ip'] . '» برای نگهداری غیرفعال شود؟ بی‌درنگ از DNS خارج می‌شود.' : '', 'power');
        $del = View::postButton($q, 'edge_addr_delete', ['id' => $id, 'aid' => $aid],
            'حذف آدرس', 'pcdna-btn pcdna-btn-sm pcdna-btn-icon pcdna-btn-danger',
            'آدرس «' . $a['ip'] . '» برای همیشه حذف شود؟', 'trash');
        return $edit . $toggle . $del;
    }

    /** Add-an-additional-address form (family + IP + optional label). */
    private static function addressAddForm(int $id): string
    {
        $form = '<form method="post" action="' . View::url(['page' => 'edges', 'view' => 'addresses', 'id' => $id]) . '" class="pcdna-form" autocomplete="off">' . View::csrf()
            . '<input type="hidden" name="a" value="edge_addr_add"><input type="hidden" name="id" value="' . $id . '"><div class="pcdna-form-grid">'
            . '<label><span>نسخهٔ IP</span>' . View::select('family', ['4' => 'IPv4', '6' => 'IPv6'], '4') . '</label>'
            . '<label><span>آدرس IP عمومی</span><input class="pcdna-input" name="ip" dir="ltr" required maxlength="45" placeholder="5.160.1.12" value="">'
            . '<small>یک آدرس عمومی معتبر متناسب با نسخهٔ انتخاب‌شده</small></label>'
            . '<label><span>برچسب (اختیاری)</span><input class="pcdna-input" name="label" maxlength="64" placeholder="مثلاً لینک دوم" value=""></label>'
            . '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('plus') . '<span>افزودن آدرس</span></button></div></form>'
            . '<p class="pcdna-muted pcdna-small">آدرس جدید بلافاصله فعال می‌شود و پس از اولین بررسی سلامت به‌صورت خودکار در DNS اعلام می‌شود. آدرس اصلی نود در این فهرست فقط برای مشاهده است؛ برای اصلاح آن، نود را از فهرست نودها ویرایش کنید.</p>';
        return View::card('افزودن آدرس اضافی', $form, '', '', 'plus');
    }

    /**
     * Daily uptime series per edge (last 30 days) — one parallel controller call per edge
     * (GET /api/v1/edges/{id}/uptime?days=30). Returns [id => [{day, uptime}...]].
     */
    public static function uptimeSeries(array $edges): array
    {
        $paths = [];
        $byPath = [];
        foreach ($edges as $e) {
            $id = (int) ($e['id'] ?? 0);
            if ($id > 0) {
                $p = '/api/v1/edges/' . $id . '/uptime?days=30';
                $paths[] = $p;
                $byPath[$p] = $id;
            }
        }
        if (!$paths) {
            return [];
        }
        $out = [];
        foreach (self::fetch($paths) as $p => $r) {
            if (self::ok($r) && is_array($r['data']['days'] ?? null)) {
                $out[$byPath[$p]] = $r['data']['days'];
            }
        }
        return $out;
    }

    /** Node-health summary block for the dashboard «سلامت نودها» card. */
    public static function healthSummary(array $edges, ?array $alerts): string
    {
        $total = count($edges);
        $enabled = 0;
        $online = 0;
        $problem = [];
        foreach ($edges as $e) {
            if (!is_array($e)) {
                continue;
            }
            $enabled += !empty($e['enabled']) ? 1 : 0;
            $online += self::edgeOnline($e) ? 1 : 0;
        }
        $sat = self::saturated($edges);
        $shed = array_filter($edges, function ($e) {
            return is_array($e) && !empty($e['shed']);
        });
        $offline = $enabled - $online;
        $worst = self::worstUptime($edges);

        $tiles = '<div class="pcdna-health-tiles">';
        $onlineTone = $online === 0 && $enabled > 0 ? 'bad' : ($online < $enabled ? 'warn' : 'ok');
        $tiles .= '<div class="pcdna-health-tile pcdna-t-' . $onlineTone . '" data-health="online"><span class="pcdna-health-n">' . View::n($online)
            . '<small> / ' . View::n($enabled) . '</small></span><span class="pcdna-health-l">نود آنلاین از فعال</span></div>';
        $degraded = count($sat);
        $tiles .= '<div class="pcdna-health-tile ' . ($degraded ? 'pcdna-t-warn' : 'pcdna-t-ok') . '" data-health="degraded"><span class="pcdna-health-n">'
            . View::n($degraded) . '</span><span class="pcdna-health-l">نود پرِبار / اشباع</span></div>';
        if ($worst !== null) {
            $tiles .= '<div class="pcdna-health-tile pcdna-t-' . self::uptimeTone($worst['d30']) . '" data-health="worst"><span class="pcdna-health-n">'
                . View::n($worst['d30'], 2) . '٪</span><span class="pcdna-health-l">کمترین در دسترس‌بودن ۳۰ روز'
                . ($worst['name'] !== '' ? ' · ' . View::ltr($worst['name']) : '') . '</span></div>';
        }
        if ($alerts !== null) {
            $open = (int) ($alerts['open'] ?? 0);
            $crit = (int) ($alerts['critical'] ?? 0);
            $tiles .= '<div class="pcdna-health-tile ' . ($crit ? 'pcdna-t-bad' : ($open ? 'pcdna-t-warn' : 'pcdna-t-ok')) . '" data-health="alerts" data-alerts-open="' . $open . '">'
                . '<span class="pcdna-health-n">' . View::n($open) . ($crit ? ' <small>(' . View::n($crit) . ' بحرانی)</small>' : '')
                . '</span><span class="pcdna-health-l">هشدار باز کنترلر</span></div>';
        }
        $tiles .= '</div>';

        $notes = [];
        if ($offline > 0) {
            $notes[] = View::n($offline) . ' نود فعال آفلاین است';
        }
        if (count($shed)) {
            $notes[] = View::n(count($shed)) . ' نود به‌دلیل اشباع از DNS خارج شده';
        }
        return $tiles . ($notes ? '<p class="pcdna-small pcdna-muted pcdna-health-notes">' . implode(' · ', $notes) . '</p>' : '');
    }

    /** Worst enabled edge by 30-day availability: ['name' => .., 'd30' => float] or null. */
    public static function worstUptime(array $edges): ?array
    {
        $worst = null;
        foreach ($edges as $e) {
            if (!is_array($e) || empty($e['enabled']) || !is_array($e['uptime'] ?? null)) {
                continue;
            }
            $d30 = (float) ($e['uptime']['d30'] ?? 100);
            if ($worst === null || $d30 < $worst['d30']) {
                $worst = ['name' => (string) ($e['name'] ?? ''), 'd30' => $d30];
            }
        }
        return $worst;
    }

    /** Availability report: sortable table of nodes with 24h/30d uptime, last-seen and a 30-day sparkline. */
    public static function availability(): string
    {
        $ping = self::ping();
        $back = '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::url(['page' => 'edges']) . '">' . View::icon('server') . '<span>بازگشت به نودها</span></a>';
        if (!$ping['ok']) {
            return $back . self::ctlError($ping);
        }
        $r = self::fetch(['/api/v1/edges']);
        $edges = self::ok($r['/api/v1/edges']) ? (array) $r['/api/v1/edges']['data'] : null;
        if ($edges === null) {
            return $back . View::alert('bad', 'فهرست نودها دریافت نشد: ' . View::e((string) $r['/api/v1/edges']['error']));
        }
        if (!$edges) {
            return $back . View::card('در دسترس‌بودن نودها', View::emptyState('هنوز نودی ثبت نشده است', 'برای شروع، از صفحه «نودها» اولین نود را اضافه کنید.', 'server'), '', '', 'activity');
        }
        $series = self::uptimeSeries($edges);
        $h = View::alert('info', 'در دسترس‌بودن هر نود بر اساس ضربان‌های ثبت‌شده در کنترلر است. ستون‌ها با کلیک روی سرتیتر مرتب می‌شوند؛ نوار پایین، ۳۰ روز اخیر را روز‌به‌روز نشان می‌دهد.');
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-sortable pcdna-avail" data-sortable="1"><thead><tr>'
            . '<th data-sort="text" aria-sort="none">نام / IP</th>'
            . '<th data-sort="text">وضعیت</th>'
            . '<th data-sort="num" class="pcdna-num">۲۴ ساعت</th>'
            . '<th data-sort="num" class="pcdna-num" data-sort-default="asc" aria-sort="ascending">۳۰ روز</th>'
            . '<th data-sort="num" class="pcdna-num">آخرین ارتباط</th>'
            . '<th>۳۰ روز اخیر</th></tr></thead><tbody>';
        // default sort: worst 30-day uptime first
        usort($edges, function ($a, $b) {
            return ((float) ($a['uptime']['d30'] ?? 100)) <=> ((float) ($b['uptime']['d30'] ?? 100));
        });
        foreach ($edges as $e) {
            $id = (int) ($e['id'] ?? 0);
            $online = self::edgeOnline($e);
            $fresh = !empty($e['enabled']) && empty($e['last_seen_at']);
            $status = empty($e['enabled']) ? View::badge('غیرفعال', 'muted') : ($online ? View::badge('آنلاین', 'ok')
                : ($fresh ? View::badge('در انتظار نصب', 'warn') : View::badge('آفلاین', 'bad')));
            $up = is_array($e['uptime'] ?? null) ? $e['uptime'] : ['h24' => 0, 'd30' => 0];
            $h24 = (float) ($up['h24'] ?? 0);
            $d30 = (float) ($up['d30'] ?? 0);
            $seen = $e['last_seen_at'] ?? null;
            $seenTs = $seen ? strtotime((string) $seen) : 0;
            $t .= '<tr data-edge="' . $id . '">'
                . '<td data-sort-value="' . View::e((string) ($e['name'] ?? '')) . '"><strong>' . View::ltr($e['name'] ?? '') . '</strong>'
                . '<div class="pcdna-small pcdna-muted">' . View::ltr($e['ipv4'] ?? '') . '</div></td>'
                . '<td data-sort-value="' . ($online ? 2 : (empty($e['enabled']) ? 0 : 1)) . '">' . $status . self::edgeWarnBadges($e) . '</td>'
                . '<td class="pcdna-num" data-sort-value="' . View::n($h24, 2) . '">' . View::badge(View::n($h24, 2) . '٪', self::uptimeTone($h24)) . '</td>'
                . '<td class="pcdna-num" data-sort-value="' . View::n($d30, 2) . '">' . View::badge(View::n($d30, 2) . '٪', self::uptimeTone($d30)) . '</td>'
                . '<td class="pcdna-num" data-sort-value="' . (int) $seenTs . '" title="' . View::e((string) $seen) . '">' . View::e(View::ago($seen)) . '</td>'
                . '<td class="pcdna-spark-cell">' . (isset($series[$id]) ? self::uptimeSpark($series[$id]) : '<span class="pcdna-muted pcdna-small">—</span>') . '</td></tr>';
        }
        $t .= '</tbody></table></div>';
        return View::card('در دسترس‌بودن نودها', $h . $t, $back, 'pcdna-flush', 'activity');
    }

    // ------------------------------------------------------------------ 4. plans

    const AUTOSETUP = ['payment' => 'پس از دریافت اولین پرداخت', 'order' => 'بلافاصله پس از ثبت سفارش', 'on' => 'پس از تأیید دستی سفارش', '' => 'دستی (بدون راه‌اندازی خودکار)'];

    public static function plans(array $state = []): string
    {
        $currencies = Data::currencies();
        $h = '';
        if (!empty($state['summary'])) {
            $h .= self::wizardSummary($state['summary']);
        }
        if (!empty($state['preview'])) {
            return $h . self::wizardPreview($state['input'], $state['post'], $currencies);
        }

        $products = Data::products();
        $pricing = Data::pricing(array_map(function ($p) {
            return (int) $p->id;
        }, $products));
        if ($products) {
            $h .= self::tunnelBulkCard();
            $h .= self::productCards($products, $pricing, $currencies);
        } else {
            $h .= View::alert('info', 'هنوز محصولی با ماژول Pasargad CDN وجود ندارد. با فرم زیر چهار پلن CDN (پایه، حرفه‌ای، تجاری، سازمانی) — که تونل / VPN در همه‌شان گنجانده شده — را با قیمت، ایمیل خوش‌آمد، فیلد Origin IP و مسیر ارتقا بسازید.');
        }
        $h .= self::wizardForm($state['input'] ?? Wizard::defaults($currencies), $currencies, (array) ($state['errors'] ?? []), !$products || !empty($state['errors']));
        return $h;
    }

    /**
     * «فعال‌سازی تونل روی سرویس‌های فعلی»: after the products are unified (tunnel included in every CDN plan),
     * already-provisioned services still show tunnel disabled on the controller until their plan is re-pushed.
     * This card offers a one-click, idempotent, CSRF-protected bulk push (Admin::action → 'tunnel_enable').
     */
    private static function tunnelBulkCard(): string
    {
        $n = Data::tunnelServices();
        if ($n < 1) {
            return '';
        }
        $body = '<p class="pcdna-muted pcdna-small">تونل / VPN اکنون در همه پلن‌های CDN گنجانده شده است. '
            . 'برای <strong>' . View::n($n) . '</strong> سرویس فعال روی محصولات تونل‌دار، با این دکمه پلن دوباره به کنترلر ارسال می‌شود تا تونل بلافاصله فعال شود. '
            . 'این کار بی‌خطر و قابل تکرار است، صورتحساب و ترافیک را تغییر نمی‌دهد و در صورت وجود، گزینه‌های سفارشی تونل هر سرویس را هم روشن می‌کند.</p>'
            . '<form method="post" action="' . View::url(['page' => 'plans']) . '" class="pcdna-form-actions">' . View::csrf()
            . '<input type="hidden" name="a" value="tunnel_enable">'
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('shield') . '<span>فعال‌سازی تونل روی سرویس‌های فعلی</span></button></form>';
        return View::card('فعال‌سازی تونل روی سرویس‌های موجود', $body, View::badge(View::n($n) . ' سرویس', 'brand'), 'pcdna-tunnel-bulk', 'shield');
    }

    private static function productCards(array $products, array $pricing, array $currencies): string
    {
        $upg = [];
        if (Env::hasTable('tblproduct_upgrade_products')) {
            foreach (Capsule::table('tblproduct_upgrade_products')->whereIn('product_id', array_map(function ($p) {
                return (int) $p->id;
            }, $products))->get() as $r) {
                $upg[(int) $r->product_id][] = (int) $r->upgrade_product_id;
            }
        }
        $emails = Capsule::table('tblemailtemplates')->whereIn('id', array_filter(array_map(function ($p) {
            return (int) ($p->welcomeemail ?? 0);
        }, $products)) ?: [0])->pluck('name', 'id')->all();
        $h = '<div class="pcdna-products">';
        foreach ($products as $p) {
            $pid = (int) $p->id;
            $plan = function_exists('pasargadcdn_plan') ? \pasargadcdn_plan((array) $p) : null;
            $o = function_exists('pasargadcdn_overage') ? \pasargadcdn_overage((array) $p) : null;
            $pp = function_exists('pasargadcdn_prepaid') ? \pasargadcdn_prepaid((array) $p) : null;
            $f = $plan['features'] ?? [];
            $feat = function ($on, $label) {
                return '<span class="pcdna-feat' . ($on ? ' is-on' : '') . '">' . View::icon($on ? 'check' : 'x') . '<span>' . View::e($label) . '</span></span>';
            };
            $field = Wizard::originField($pid);
            $body = '<dl class="pcdna-dl pcdna-dl-3">'
                . '<div><dt>ترافیک پلن</dt><dd>' . ($o ? View::n($o['included_gb']) . ' GB' : (($plan['bandwidth_limit_gb'] ?? 0) ? View::n($plan['bandwidth_limit_gb']) . ' GB' : 'نامحدود')) . '</dd></div>'
                . '<div><dt>سقف قطع روی CDN</dt><dd>' . (($plan['bandwidth_limit_gb'] ?? 0) ? View::n($plan['bandwidth_limit_gb']) . ' GB' : 'نامحدود') . '</dd></div>'
                . '<div><dt>ترافیک اضافه</dt><dd>' . ($o ? View::n($o['price_per_gb'], $o['price_per_gb'] >= 100 ? 0 : 2) . ' برای هر گیگابایت<div class="pcdna-small pcdna-muted">فاکتور پایان ماه — ذخیره در WHMCS: ' . View::n($p->overagesbwprice, 4) . ' برای هر مگابایت</div>'
                    : ($pp !== null ? ($pp['price_per_gb'] !== null ? View::n($pp['price_per_gb'], $pp['price_per_gb'] >= 100 ? 0 : 2) . ' برای هر گیگابایت' : View::badge('قیمت ثبت نشده', 'bad'))
                        . '<div class="pcdna-small pcdna-muted">پیش‌پرداخت از کیف پول — بسته‌های ' . View::n($pp['block_gb']) . ' گیگابایتی</div>'
                    : ((int) $p->configoption1 > 0 ? 'قطع در پایان ترافیک' : '—'))) . '</dd></div>'
                . '<div><dt>رکورد DNS</dt><dd>' . View::n($plan['max_records'] ?? 0) . '</dd></div>'
                . '<div><dt>قوانین فایروال / صفحه / نرخ</dt><dd>' . View::n($f['max_firewall_rules'] ?? 0) . ' / ' . View::n($f['max_page_rules'] ?? 0) . ' / ' . View::n($f['max_ratelimit_rules'] ?? 0) . '</dd></div>'
                . '<div><dt>استخر توزیع بار</dt><dd>' . View::n($f['max_pools'] ?? 0) . '</dd></div>'
                . (!empty($f['tunnel']) ? '<div data-tunnel="1"><dt>تونل / VPN</dt><dd>' . View::n($f['max_tunnel_paths'] ?? 0) . ' مسیر · '
                    . (!empty($f['max_tunnel_connections']) ? View::n($f['max_tunnel_connections']) . ' اتصال هر نود' : 'اتصال نامحدود') . ' · '
                    . (!empty($f['tunnel_max_mbps']) ? View::n($f['tunnel_max_mbps']) . ' Mbps' : 'بدون سقف سرعت') . '</dd></div>' : '')
                . '<div><dt>گروه نودها</dt><dd>' . (($f['edge_group'] ?? 'general') === 'tunnel' ? View::badge('تونل', 'violet') : View::badge('عمومی', 'muted')) . '</dd></div>'
                . '<div><dt>گروه سرور</dt><dd>' . ((int) $p->servergroup > 0 ? View::e($p->servergroup_name ?: '#' . (int) $p->servergroup) : View::badge('تنظیم نشده', 'bad')) . '</dd></div>'
                . '<div><dt>راه‌اندازی</dt><dd>' . View::e(self::AUTOSETUP[(string) $p->autosetup] ?? (string) $p->autosetup) . '</dd></div>'
                . '<div><dt>ایمیل خوش‌آمد</dt><dd>' . (!empty($p->welcomeemail) ? View::e($emails[(int) $p->welcomeemail] ?? '#' . (int) $p->welcomeemail) : View::badge('ندارد', 'warn')) . '</dd></div>'
                . '<div><dt>فیلد Origin IP</dt><dd>' . ($field ? View::badge('دارد', 'ok') : View::badge('ندارد', 'muted')) . '</dd></div>'
                . '<div><dt>مسیر ارتقا</dt><dd>' . (isset($upg[$pid]) ? View::n(count($upg[$pid])) . ' محصول' : View::badge('ندارد', 'warn')) . '</dd></div>'
                . '<div><dt>نیاز به دامنه</dt><dd>' . (!empty($p->showdomainoptions) ? View::badge('بله', 'ok') : View::badge('خیر', 'bad')) . '</dd></div>'
                . '</dl><div class="pcdna-feats">' . $feat($plan['ssl_allowed'] ?? false, 'SSL رایگان') . $feat($f['waf'] ?? false, 'WAF')
                . $feat($f['ddos'] ?? false, 'DDoS') . $feat(($f['load_balancer'] ?? false) && ($f['max_pools'] ?? 0) > 0, 'توزیع بار')
                . $feat($f['image_optimization'] ?? false, 'بهینه‌سازی تصویر') . $feat($f['custom_ssl'] ?? false, 'گواهی اختصاصی')
                . $feat($f['dnssec'] ?? false, 'DNSSEC') . $feat($f['tunnel'] ?? false, 'تونل / VPN') . '</div>';
            $body .= '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-prices"><thead><tr><th>ارز</th><th>ماهانه</th><th>سه‌ماهه</th><th>شش‌ماهه</th><th>سالانه</th></tr></thead><tbody>';
            foreach ($currencies as $c) {
                $row = $pricing[$pid][(int) $c->id] ?? null;
                $body .= '<tr><th>' . View::ltr($c->code) . '</th>';
                foreach (array_keys(Wizard::CYCLES) as $cycle) {
                    $v = $row ? (float) $row->{$cycle} : -1;
                    $body .= '<td class="pcdna-num">' . ($v < 0 ? '<span class="pcdna-muted">غیرفعال</span>' : View::n($v, 2)) . '</td>';
                }
                $body .= '</tr>';
            }
            $body .= '</tbody></table></div>';
            $h .= View::card($p->name, $body, (!empty($p->hidden) ? View::badge('مخفی', 'muted') : '') . (!empty($p->retired) ? View::badge('بازنشسته', 'muted') : '')
                . '<span class="pcdna-muted pcdna-small">' . View::e($p->group_name ?: '—') . ' · #' . View::n($pid) . '</span>'
                . '<a class="pcdna-btn pcdna-btn-sm" href="configproducts.php?action=edit&amp;id=' . $pid . '">' . View::icon('external') . '<span>ویرایش در WHMCS</span></a>',
                'pcdna-product', 'tag');
        }
        return $h . '</div>';
    }

    private static function wizardForm(array $in, array $currencies, array $errors, bool $open): string
    {
        $h = '<details class="pcdna-card pcdna-wizard" id="wizard"' . ($open ? ' open' : '') . '><summary class="pcdna-card-head"><h3>' . View::icon('wand')
            . '<span>راه‌اندازی خودکار محصولات</span></h3><span class="pcdna-muted pcdna-small">گروه، ۴ پلن CDN (با تونل گنجانده‌شده)، قیمت‌ها، ایمیل خوش‌آمد، فیلد Origin IP و مسیر ارتقا — قابل اجرای مجدد</span></summary><div class="pcdna-card-body">';
        foreach ($errors as $e) {
            $h .= View::alert('bad', View::e($e));
        }
        if (!$currencies) {
            return $h . View::alert('bad', 'هیچ ارزی در WHMCS تعریف نشده است (System Settings → Currencies).') . '</div></details>';
        }
        $h .= '<form method="post" action="' . View::url(['page' => 'plans']) . '#wizard" class="pcdna-form" data-wizard="1">' . View::csrf()
            . '<input type="hidden" name="a" value="wizard_preview">';

        // general
        $sg = ['new' => 'ساخت/استفاده از گروه «' . Wizard::SERVER_GROUP_NAME . '»'];
        foreach (Wizard::serverGroups() as $g) {
            $sg[(int) $g->id] = $g->name . ' (#' . (int) $g->id . ')';
        }
        $servers = [];
        foreach (Env::servers() as $s) {
            $servers[(int) $s->id] = ($s->name ?: 'Pasargad CDN') . ' — ' . preg_replace('#^https?://#', '', Env::controllerUrl($s)) . (!empty($s->disabled) ? ' (غیرفعال)' : '');
        }
        $def = Wizard::defaultCurrency($currencies);
        $h .= '<fieldset class="pcdna-fieldset"><legend>تنظیمات عمومی</legend><div class="pcdna-form-grid">'
            . '<label><span>نام گروه محصولات</span><input class="pcdna-input" name="group_name" maxlength="100" value="' . View::e($in['group_name']) . '"></label>'
            . '<label><span>گروه سرور</span>' . View::select('servergroup', $sg, $in['servergroup']) . '</label>'
            . '<label><span>سرور CDN (برای گروه جدید)</span>' . ($servers ? View::select('server_id', $servers, $in['server_id']) : '<span class="pcdna-badge pcdna-t-bad">سروری تعریف نشده</span>') . '</label>'
            . '<label><span>راه‌اندازی خودکار</span>' . View::select('autosetup', self::AUTOSETUP, $in['autosetup']) . '</label>'
            . '</div><div class="pcdna-checks-row">'
            . self::check('hidden', $in['hidden'], 'محصولات مخفی ساخته شوند (برای بررسی پیش از انتشار)')
            . self::check('update', $in['update'], 'به‌روزرسانی محصولات و قیمت‌های موجود (در غیر این صورت فقط موارد جاافتاده ساخته می‌شوند)')
            . '</div></fieldset>';

        $h .= '<fieldset class="pcdna-fieldset" data-billing-fs="1"><legend>صورتحساب ترافیک بیش از پلن</legend><div class="pcdna-billing">';
        $hints = [
            'prepaid' => 'پس از اتمام ترافیک پلن، بسته‌های ترافیک خودکار از اعتبار کیف پول مشتری خریده و فاکتورشان با اعتبار پرداخت می‌شود. اگر اعتبار کافی نباشد سرویس قطع و پس از شارژ کیف پول ظرف چند ثانیه دوباره وصل می‌شود.',
            'overage' => 'سرویس تا سقف تعیین‌شده ادامه می‌دهد و WHMCS در پایان ماه مازاد را فاکتور می‌کند (Overage Billing).',
            'cut' => 'سرویس در پایان ترافیک پلن تا ماه بعد قطع می‌شود؛ هیچ هزینه اضافه‌ای گرفته نمی‌شود.',
        ];
        foreach (Wizard::BILLING as $k => $label) {
            $h .= '<label class="pcdna-radio-card' . ($in['billing'] === $k ? ' is-on' : '') . '"><input type="radio" name="billing" value="' . $k . '"'
                . ($in['billing'] === $k ? ' checked' : '') . '><span><strong>' . View::e($label) . '</strong><small>' . View::e($hints[$k]) . '</small></span></label>';
        }
        $h .= '</div><div class="pcdna-form-grid">'
            . '<label data-billing-show="prepaid overage"><span>قیمت هر گیگابایت ترافیک اضافه (' . View::e($def ? $def->code : '') . ')</span><input class="pcdna-input" name="overage_price" dir="ltr" inputmode="decimal" value="'
            . View::e(Wizard::fmt((float) $in['overage_price'])) . '" data-per-mb="1"><small data-billing-show="overage" data-per-mb-out="1">WHMCS قیمت را به ازای هر مگابایت ذخیره می‌کند: '
            . View::n(Wizard::perMb((float) $in['overage_price']), 4) . ' هر MB</small>'
            . '<small data-billing-show="prepaid">اندازه بسته (' . View::n((int) Env::setting('block_gb', '10') ?: 10) . ' GB) و سقف خرید ماهانه در تنظیمات ماژول هستند.</small></label>'
            . '<label data-billing-show="overage"><span>سقف ترافیک اضافه (درصد از ترافیک پلن)</span><input class="pcdna-input" name="overage_allow" dir="ltr" inputmode="numeric" value="' . (int) $in['overage_allow'] . '">'
            . '<small>مثلاً ۱۰۰ یعنی سرویس ۱۰۰ گیگابایتی حداکثر تا ۲۰۰ گیگابایت ادامه می‌دهد و سپس روی CDN متوقف می‌شود.</small></label>'
            . '</div></fieldset>';

        $h .= '<fieldset class="pcdna-fieldset"><legend>قالب‌های ایمیل</legend><div class="pcdna-checks-row">'
            . self::check('email', $in['email'], 'قالب‌های «' . Wizard::EMAIL_NAME . '» (به محصولات وصل می‌شود)، «' . Wizard::EMAIL_EXHAUSTED . '» و «' . Wizard::EMAIL_WARNING . '» ساخته شوند')
            . self::check('email_update', $in['email_update'], 'به‌روزرسانی: اگر قالبی با این نام‌ها وجود دارد متن آن بازنویسی شود')
            . '</div><small class="pcdna-muted">قالب‌های «' . Wizard::EMAIL_TUNNEL_DOWN . '» (قطعی سرور پشت تونل) و «' . Wizard::EMAIL_TUNNEL_UP
            . '» (اتصال دوباره برقرار شد) هم ساخته می‌شوند؛ کران WHMCS آن‌ها را از رویدادهای تونل کنترلر برای صاحب سرویس می‌فرستد.</small></fieldset>';

        // Wave 7 (SPEC §15.7): «بسته‌ی ترافیک افزوده» product add-ons
        $h .= '<fieldset class="pcdna-fieldset" data-addon-fs="1"><legend>' . View::e(Wizard::ADDON_NAME) . '</legend><div class="pcdna-checks-row">'
            . self::check('addon', !empty($in['addon']), 'افزونه‌های «' . Wizard::ADDON_NAME . '» ساخته شوند (یک افزونه‌ی یک‌بار پرداخت برای هر اندازه، متصل به همه‌ی محصولات CDN)')
            . '</div><div class="pcdna-form-grid"><label><span>اندازه‌ها (گیگابایت، با کاما جدا)</span><input class="pcdna-input" name="addon_sizes" dir="ltr" inputmode="numeric" value="'
            . View::e(implode(', ', array_map('intval', (array) ($in['addon_sizes'] ?? Wizard::ADDON_SIZES)))) . '">'
            . '<small>افزونه‌ها پنهان ساخته می‌شوند و قیمتی برایشان ثبت نمی‌شود: در Setup ← Products/Services ← Product Addons قیمت را تعیین و «Show on Order» را روشن کنید. '
            . 'پس از پرداخت فاکتور، سقف ترافیک همان ماه سرویس به اندازه‌ی بسته بالا می‌رود (یک بار برای هر قلم فاکتور).</small></label></div></fieldset>';

        // SPEC §16.8: optional «Storage GB» configurable option (object storage quota of the service)
        $h .= '<fieldset class="pcdna-fieldset" data-storage-fs="1"><legend>فضای ذخیره‌سازی ابری (اختیاری)</legend><div class="pcdna-checks-row">'
            . self::check('storage_opt', !empty($in['storage_opt']), 'گزینه‌ی قابل‌تنظیم «Storage GB» ساخته شود (فهرست کشویی اندازه‌ها، متصل به همه‌ی محصولات CDN)')
            . '</div><div class="pcdna-form-grid"><label><span>اندازه‌ها (گیگابایت، با کاما جدا؛ ۰ = بدون فضا)</span><input class="pcdna-input" name="storage_sizes" dir="ltr" inputmode="numeric" value="'
            . View::e(implode(', ', array_map('intval', (array) ($in['storage_sizes'] ?? Wizard::STORAGE_SIZES)))) . '">'
            . '<small>مقدار انتخاب‌شده در سفارش، سهمیه‌ی فضای ذخیره‌سازی سرویس (storage_gb) می‌شود؛ محصولی که این گزینه را ندارد فضای ذخیره‌سازی ندارد. '
            . 'قیمت‌ها صفر ساخته می‌شوند: یا در Setup ← Configurable Options برای هر اندازه قیمت ماهانه بگذارید، یا در تنظیمات ماژول «قیمت هر گیگابایت-ماه ذخیره‌سازی» را تعیین کنید تا مصرف واقعی هر ماه فاکتور شود. اجرای دوباره چیزی را تکرار نمی‌کند.</small></label></div></fieldset>';

        // Security review H1: optional «Secondary DNS» configurable option (plan feature dns_secondary)
        $h .= '<fieldset class="pcdna-fieldset" data-dns2-fs="1"><legend>DNS ثانویه (اختیاری)</legend><div class="pcdna-checks-row">'
            . self::check('dns2_opt', !empty($in['dns2_opt']), 'گزینه‌ی قابل‌تنظیم «Secondary DNS» ساخته شود (بله/خیر، متصل به همه‌ی محصولات CDN)')
            . '</div><p class="pcdna-muted">DNS ثانویه (انتقال زون از سرور DNS خود مشتری) قابلیت پلن است و روی کنترلر به‌طور پیش‌فرض خاموش است؛ '
            . 'فقط سرویس‌هایی که این گزینه را «بله» دارند صفحه‌ی «DNS ثانویه» را باز می‌بینند. قیمت صفر ساخته می‌شود؛ در Setup ← Configurable Options قیمت بگذارید.</p></fieldset>';

        // Growth: free trial product + its e-mails; the scheduled usage-report e-mail template
        $h .= '<fieldset class="pcdna-fieldset" data-trial-fs="1"><legend>پلن آزمایشی رایگان و گزارش ایمیلی</legend><div class="pcdna-checks-row">'
            . self::check('trial', !empty($in['trial']), 'محصول «' . Wizard::TRIAL_NAME . '» ساخته شود (رایگان، بدون تونل، یک بار برای هر مشتری / ایمیل / دامنه، با قالب‌های «'
                . Wizard::EMAIL_TRIAL_ENDING . '» و «' . Wizard::EMAIL_TRIAL_ENDED . '» به فارسی و انگلیسی)')
            . '</div><div class="pcdna-form-grid">'
            . '<label><span>نام محصول آزمایشی</span><input class="pcdna-input" name="trial_name" maxlength="100" value="' . View::e((string) ($in['trial_name'] ?? Wizard::TRIAL_NAME)) . '"></label>'
            . '<label><span>مدت دوره (روز)</span><input class="pcdna-input" name="trial_days" dir="ltr" inputmode="numeric" value="' . (int) ($in['trial_days'] ?? 7) . '"></label>'
            . '<label><span>سقف ترافیک دوره (گیگابایت)</span><input class="pcdna-input" name="trial_gb" dir="ltr" inputmode="numeric" value="' . (int) ($in['trial_gb'] ?? 5) . '"></label>'
            . '<label><span>ایمیل یادآوری (روز پیش از پایان؛ ۰ = بدون یادآوری)</span><input class="pcdna-input" name="trial_remind" dir="ltr" inputmode="numeric" value="' . (int) ($in['trial_remind'] ?? 2) . '"></label>'
            . '<label><span>در پایان دوره</span>' . View::select('trial_end', Wizard::TRIAL_ENDS, (string) ($in['trial_end'] ?? 'pause')) . '</label>'
            . '<label><span>حذف خودکار پس از پایان (روز؛ ۰ = هرگز)</span><input class="pcdna-input" name="trial_terminate_after" dir="ltr" inputmode="numeric" value="' . (int) ($in['trial_terminate_after'] ?? 14) . '"></label>'
            . '</div><small class="pcdna-muted">هنگام پرداخت سبد خرید، هر مشتری، هر ایمیل و هر دامنه فقط یک بار دوره آزمایشی می‌گیرد. کران WHMCS یادآوری را می‌فرستد و در پایان دوره، سرویس را متوقف / معلق / حذف می‌کند؛ '
            . 'در حالت «توقف روی CDN» مشتری با ارتقای درجا (مسیر ارتقا به همه پلن‌ها ساخته می‌شود) بلافاصله و با همه تنظیمات برمی‌گردد.</small>'
            . '<div class="pcdna-checks-row">' . self::check('report_tpl', !empty($in['report_tpl']), 'قالب «' . Wizard::EMAIL_REPORT . '» (گزارش هفتگی/ماهانه‌ای که مشتری در ناحیه کاربری فعال می‌کند) به فارسی و انگلیسی ساخته شود')
            . '</div></fieldset>';

        // feature matrix, one table per plan family (a single «CDN» family now — tunnel is included in every plan)
        $h .= '<fieldset class="pcdna-fieldset"><legend>امکانات پلن‌ها</legend>';
        foreach (Wizard::FAMILIES as $fam => $famLabel) {
            $keys = array_keys(array_filter(Wizard::PLANS, function ($d) use ($fam) {
                return $d['family'] === $fam;
            }));
            $h .= '<h4 class="pcdna-subhead">' . View::e($famLabel) . '</h4>'
                . '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-matrix" data-family="' . $fam . '"><thead><tr><th></th>';
            foreach ($keys as $key) {
                $p = $in['plans'][$key];
                $h .= '<th><label class="pcdna-check"><input type="checkbox" name="plan[' . $key . '][enabled]" value="1"' . ($p['enabled'] ? ' checked' : '') . '><span>'
                    . View::e(Wizard::PLANS[$key]['title']) . '</span></label></th>';
            }
            $h .= '</tr></thead><tbody><tr><th>نام محصول</th>';
            foreach ($keys as $key) {
                $h .= '<td><input class="pcdna-input" name="plan[' . $key . '][name]" maxlength="100" value="' . View::e($in['plans'][$key]['name']) . '" aria-label="نام محصول ' . View::e(Wizard::PLANS[$key]['title']) . '"></td>';
            }
            $h .= '</tr>';
            $fields = ['bw', 'records', 'ssl', 'rate', 'waf', 'ddos', 'lb', 'image', 'customssl', 'dnssec', 'page', 'fw', 'rl', 'pools', 'tunnel', 'tpaths', 'tconn', 'tmbps', 'group',
                'wroom', 'access'];
            foreach ($fields as $f) {
                $h .= '<tr data-field="' . $f . '"><th>' . View::e(Wizard::FIELD_LABELS[$f]) . '</th>';
                foreach ($keys as $key) {
                    $v = $in['plans'][$key][$f] ?? 0;
                    $nm = 'plan[' . $key . '][' . $f . ']';
                    $aria = ' aria-label="' . View::e(Wizard::FIELD_LABELS[$f] . ' — ' . Wizard::PLANS[$key]['title']) . '"';
                    if ($f === 'group') {
                        $h .= '<td>' . View::select($nm, Wizard::EDGE_GROUPS, (string) $v, $aria) . '</td>';
                        continue;
                    }
                    $h .= '<td>' . (isset(Wizard::FLAGS[$f]) || isset(Wizard::W10[$f])
                            ? '<label class="pcdna-switch"><input type="checkbox" name="' . $nm . '" value="1"' . ($v ? ' checked' : '') . $aria . '><span></span></label>'
                            : '<input class="pcdna-input pcdna-input-num" name="' . $nm . '" dir="ltr" inputmode="numeric" value="' . (int) $v . '"' . $aria . '>') . '</td>';
                }
                $h .= '</tr>';
            }
            $h .= '</tbody></table></div>';
        }
        $h .= '<p class="pcdna-muted pcdna-small">ترافیک ۰ یعنی نامحدود. استخر توزیع بار فقط وقتی «توزیع بار» روشن باشد اعمال می‌شود. '
            . 'حالت تونل (VPN برای Xray / V2Ray پشت CDN) در همه پلن‌های CDN گنجانده شده است؛ هزینه جداگانه‌ای ندارد و ترافیک آپلود و دانلود آن از همان ترافیک/کیف پول پلن حساب می‌شود. '
            . 'با «گروه نودها = عمومی» تونل از همه نودها سرو می‌شود (پیشنهادی)؛ اگر «تونل» را انتخاب کنید فقط به نودهای گروه تونل هدایت می‌شود و در نبود نود آنلاین همه نودها پاسخ می‌دهند. '
            . '«اتصال همزمان هر نود» ۰ یعنی نامحدود (هر جریان WebSocket/gRPC یک اتصال است). '
            . '«سقف سرعت اتصال» ۰ یعنی بدون سقف و فعلاً روی جریان‌های تونل اعمال نمی‌شود. '
            . '«اتاق انتظار» و «دسترسی محافظت‌شده» (موج ۱۰) در configoption20 / 21 با on / off ذخیره می‌شوند؛ اجرای دوبارهٔ ویزارد برای محصولات قدیمی فقط مقدار خالی را پر می‌کند. '
            . 'این مقادیر در Module Settings محصول (configoption1..21) ذخیره می‌شوند؛ برای سرویس‌های موجود با دکمه «فعال‌سازی تونل روی سرویس‌های فعلی» (بالای همین صفحه) یا ChangePackage اعمال می‌شوند.</p></fieldset>';

        // prices
        $h .= '<fieldset class="pcdna-fieldset"><legend>قیمت‌ها</legend><p class="pcdna-muted pcdna-small">خانه خالی یعنی آن دوره پرداخت غیرفعال است (در WHMCS با ‎-1 ذخیره می‌شود). '
            . 'هزینه راه‌اندازی صفر است. پیش‌فرض‌ها: سه‌ماهه ۵٪، شش‌ماهه ۱۰٪ و سالانه معادل ۱۰ ماه.</p>';
        foreach ($currencies as $c) {
            $cid = (int) $c->id;
            $h .= '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-matrix pcdna-price-matrix" data-currency="' . $cid . '"><thead><tr><th>' . View::ltr($c->code)
                . (!empty($c->default) ? ' <small class="pcdna-muted">(پیش‌فرض)</small>' : '') . '</th>';
            foreach (Wizard::CYCLES as $cycle => $label) {
                $h .= '<th>' . View::e($label) . '</th>';
            }
            $h .= '</tr></thead><tbody>';
            foreach (Wizard::PLANS as $key => $d) {
                $h .= '<tr data-plan="' . $key . '"><th>' . View::e($d['title']) . '</th>';
                foreach (Wizard::CYCLES as $cycle => $label) {
                    $h .= '<td><input class="pcdna-input pcdna-input-num" name="price[' . $key . '][' . $cid . '][' . $cycle . ']" dir="ltr" inputmode="decimal" data-cycle="' . $cycle . '" value="'
                        . View::e($in['plans'][$key]['prices'][$cid][$cycle] ?? '') . '" aria-label="' . View::e('قیمت ' . $label . ' ' . $d['title'] . ' ' . $c->code) . '"></td>';
                }
                $h .= '</tr>';
            }
            $h .= '</tbody></table></div>';
        }
        $h .= '</fieldset>';

        // descriptions
        $h .= '<fieldset class="pcdna-fieldset"><legend>توضیحات محصول (فرم سفارش)</legend><div class="pcdna-desc-grid">';
        foreach (Wizard::PLANS as $key => $d) {
            $h .= '<label><span>' . View::e($d['title']) . '</span><textarea class="pcdna-input" name="plan[' . $key . '][desc]" rows="7" dir="rtl">' . View::e($in['plans'][$key]['desc']) . '</textarea></label>';
        }
        $h .= '</div><p class="pcdna-muted pcdna-small">HTML مجاز است؛ فهرست امکانات در فرم سفارش WHMCS نمایش داده می‌شود.</p></fieldset>';
        $h .= '<div class="pcdna-form-actions pcdna-sticky"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('search')
            . '<span>پیش‌نمایش تغییرات</span></button><span class="pcdna-muted pcdna-small">در این مرحله چیزی ذخیره نمی‌شود.</span></div></form></div></details>';
        return $h;
    }

    public static function check(string $name, bool $on, string $label): string
    {
        return '<label class="pcdna-check"><input type="checkbox" name="' . View::e($name) . '" value="1"' . ($on ? ' checked' : '') . '><span>' . View::e($label) . '</span></label>';
    }

    const OPS = ['create' => ['ساخت', 'ok'], 'update' => ['به‌روزرسانی', 'warn'], 'reuse' => ['استفاده از موجود', 'brand'], 'skip' => ['بدون تغییر', 'muted']];

    private static function wizardPreview(array $in, array $post, array $currencies): string
    {
        $steps = Wizard::plan($in, $currencies);
        $counts = ['create' => 0, 'update' => 0, 'reuse' => 0, 'skip' => 0];
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-preview"><thead><tr><th>عملیات</th><th>نوع</th><th>مورد</th><th>جزئیات</th></tr></thead><tbody>';
        foreach ($steps as $s) {
            $counts[$s['op']]++;
            [$label, $tone] = self::OPS[$s['op']];
            $t .= '<tr class="is-' . View::e($s['op']) . '"><td>' . View::badge($label, $tone) . '</td><td>' . View::e($s['kind']) . '</td><td><strong>' . View::e($s['label'])
                . '</strong></td><td class="pcdna-small">' . View::e($s['detail']) . '</td></tr>';
        }
        $t .= '</tbody></table></div>';
        $sum = '<p class="pcdna-summary">' . View::badge(View::n($counts['create']) . ' ساخت', 'ok') . ' ' . View::badge(View::n($counts['update']) . ' به‌روزرسانی', 'warn')
            . ' ' . View::badge(View::n($counts['reuse']) . ' استفاده مجدد', 'brand') . ' ' . View::badge(View::n($counts['skip']) . ' بدون تغییر', 'muted') . '</p>';
        $form = '<form method="post" action="' . View::url(['page' => 'plans']) . '" class="pcdna-form-actions">' . View::csrf()
            . '<input type="hidden" name="a" value="wizard_apply">' . self::hidden($post, ['a', 'pcdn_csrf', 'token'])
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('check') . '<span>تأیید و اعمال</span></button>'
            . '<button type="submit" name="a" value="wizard_edit" class="pcdna-btn">' . View::icon('sliders') . '<span>بازگشت و ویرایش</span></button></form>';
        return View::card('پیش‌نمایش راه‌اندازی خودکار', View::alert('info', 'هنوز چیزی ذخیره نشده است. موارد زیر را بررسی و سپس «تأیید و اعمال» را بزنید. همه تغییرات در یک تراکنش پایگاه داده انجام می‌شوند.')
            . $sum . $t . $form, '', 'pcdna-wizard', 'wand');
    }

    private static function wizardSummary(array $summary): string
    {
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table"><thead><tr><th>نتیجه</th><th>نوع</th><th>مورد</th><th></th></tr></thead><tbody>';
        foreach ($summary as $s) {
            [$label, $tone] = self::OPS[$s['op']] ?? [$s['op'], 'muted'];
            $t .= '<tr><td>' . View::badge($label, $tone) . '</td><td>' . View::e($s['kind']) . '</td><td>' . View::e($s['label']) . '</td><td>'
                . ($s['link'] !== '' ? '<a href="' . View::e($s['link']) . '">' . View::icon('external') . ' مشاهده</a>' : '') . '</td></tr>';
        }
        $t .= '</tbody></table></div>';
        return View::card('نتیجه راه‌اندازی خودکار', $t, '', '', 'check');
    }

    /** Re-emits posted fields as hidden inputs (nested arrays flattened as name[a][b]). */
    private static function hidden(array $data, array $skip, string $prefix = ''): string
    {
        $h = '';
        foreach ($data as $k => $v) {
            if ($prefix === '' && in_array((string) $k, $skip, true)) {
                continue;
            }
            $name = $prefix === '' ? (string) $k : $prefix . '[' . $k . ']';
            if (is_array($v)) {
                $h .= self::hidden($v, $skip, $name);
            } elseif (is_scalar($v)) {
                $h .= '<input type="hidden" name="' . View::e($name) . '" value="' . View::e(Env::input((string) $v)) . '">';
            }
        }
        return $h;
    }

    // ------------------------------------------------------------------ 5. usage

    /** @return array [rows, totals, month, error] */
    public static function usageData(string $month): array
    {
        $ping = self::ping();
        if (!$ping['ok']) {
            return [[], [], $month, $ping];
        }
        $path = '/api/v1/usage?month=' . rawurlencode($month);
        $all = self::fetch([$path, Operator::LIST]);
        $r = $all[$path];
        // SPEC §19.1: operator sites are no client's usage (not in the per-client report / CSV)
        if (self::ok($r)) {
            $r['data']['sites'] = Data::withoutOperator((array) ($r['data']['sites'] ?? []), self::operatorSet($all[Operator::LIST]));
        }
        if (!self::ok($r)) {
            return [[], [], $month, ['ok' => false, 'code' => $r['code'], 'error' => (string) $r['error'], 'ms' => 0, 'data' => []]];
        }
        $services = [];
        foreach (Data::serviceQuery()->get(Data::SERVICE_COLS)->all() as $svc) {
            $services[(int) $svc->id] = $svc;
        }
        $co = Data::configOptions(array_values($services));
        $currencies = [];
        foreach (Data::currencies() as $c) {
            $currencies[(int) $c->id] = $c;
        }
        $def = Wizard::defaultCurrency(array_values($currencies));
        $ix = [];
        foreach ($services as $svc) {
            $d = Env::domain((string) $svc->domain);
            if (!isset($ix[$d]) || in_array((string) $svc->domainstatus, Data::LIVE, true)) {
                $ix[$d] = $svc;
            }
        }
        $rows = [];
        $tot = ['used' => 0.0, 'over' => 0.0, 'amount' => [], 'bought_gb' => 0, 'bought' => []];
        $tops = Data::topupSums($month);
        foreach ((array) ($r['data']['sites'] ?? []) as $s) {
            $ext = (string) ($s['external_id'] ?? '');
            $svc = ($ext !== '' && ctype_digit($ext) && isset($services[(int) $ext])) ? $services[(int) $ext] : ($ix[strtolower((string) ($s['domain'] ?? ''))] ?? null);
            $used = round((float) ($s['bytes'] ?? 0) / 1073741824, 3);
            $o = $svc && function_exists('pasargadcdn_overage') ? \pasargadcdn_overage((array) $svc) : null;
            $limit = $o ? (float) $o['included_gb'] : (float) ($s['bandwidth_limit_gb'] ?? 0);
            $pp = $svc ? Data::prepaid($svc, $co[(int) $svc->id] ?? []) : null;
            $top = $svc ? ($tops[(int) $svc->id] ?? null) : null;
            $plan = $limit;
            if ($pp !== null) {
                $plan = (float) $pp['plan_gb'];
                $limit = $plan + ($top ? $top['gb'] : 0);
            }
            $over = $limit > 0 ? max(0.0, round($used - $limit, 3)) : 0.0;
            $amount = null;
            $cur = $def;
            if ($o && $svc) {
                $cur = $currencies[(int) ($svc->currency ?? 0)] ?? $def;
                $rate = $cur && (float) $cur->rate > 0 ? (float) $cur->rate : 1.0;
                $amount = round($over * $o['price_per_gb'] * $rate, 2);
            }
            $code = $cur ? (string) $cur->code : '';
            $rows[] = [
                'service' => $svc ? (int) $svc->id : 0, 'userid' => $svc ? (int) $svc->userid : 0,
                'client' => $svc ? Data::clientName($svc) : '', 'domain' => (string) ($s['domain'] ?? ''),
                'product' => $svc ? (string) $svc->product : '', 'status' => $svc ? (string) $svc->domainstatus : '',
                'used' => $used, 'limit' => $limit, 'over' => $over, 'amount' => $amount, 'currency' => $amount !== null ? $code : '',
                'requests' => (int) ($s['requests'] ?? 0), 'prepaid' => $pp !== null, 'plan' => $plan,
                'bought_gb' => $top ? $top['gb'] : 0, 'bought' => $top ? round($top['amount'], 2) : 0.0,
                'bought_code' => $top ? $top['code'] : '', 'invoices' => $top ? $top['invoices'] : [],
            ];
            if ($top) {
                $tot['bought_gb'] += $top['gb'];
                $tot['bought'][$top['code']] = ($tot['bought'][$top['code']] ?? 0) + $top['amount'];
            }
            $tot['used'] += $used;
            $tot['over'] += $over;
            if ($amount !== null && $amount > 0) {
                $tot['amount'][$code] = ($tot['amount'][$code] ?? 0) + $amount;
            }
        }
        usort($rows, function ($a, $b) {
            return $b['used'] <=> $a['used'];
        });
        return [$rows, $tot, (string) ($r['data']['month'] ?? $month), null];
    }

    public static function months(): array
    {
        $out = [];
        $t = strtotime(date('Y-m-01'));
        for ($i = 0; $i < 12; $i++) {
            $m = date('Y-m', strtotime('-' . $i . ' month', $t));
            $label = View::digits($m);
            if (class_exists('\\IntlDateFormatter')) {
                $f = new \IntlDateFormatter('fa_IR@calendar=persian', \IntlDateFormatter::NONE, \IntlDateFormatter::NONE,
                    date_default_timezone_get(), \IntlDateFormatter::TRADITIONAL, 'MMMM yyyy');
                $j = $f->format(strtotime($m . '-15'));
                if (is_string($j) && $j !== '') {
                    $label .= ' (حدود ' . $j . ')';
                }
            }
            $out[$m] = $label;
        }
        return $out;
    }

    public static function validMonth($m): string
    {
        return is_string($m) && preg_match('/^(20\d\d)-(0[1-9]|1[0-2])$/D', $m) ? $m : date('Y-m');
    }

    public static function usage(array $get): string
    {
        $month = self::validMonth($get['month'] ?? '');
        [$rows, $tot, $month, $err] = self::usageData($month);
        $h = '<form method="get" action="addonmodules.php" class="pcdna-filters"><input type="hidden" name="module" value="' . View::e(Env::MODULE) . '">'
            . '<input type="hidden" name="page" value="usage"><label class="pcdna-inline-label"><span>ماه</span>' . View::select('month', self::months(), $month) . '</label>'
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">نمایش</button>'
            . '<a class="pcdna-btn" href="' . View::url(['page' => 'usage', 'month' => $month, 'export' => 'csv']) . '">' . View::icon('download') . '<span>خروجی CSV (Excel)</span></a></form>';
        if ($err) {
            return $h . self::ctlError($err);
        }
        $money = function ($a) {
            return View::n($a, abs($a) >= 100 ? 0 : 2);
        };
        $sumList = function (array $by) use ($money) {
            $out = [];
            foreach ($by as $code => $a) {
                if ($a > 0) {
                    $out[] = $money($a) . ' <small>' . View::e($code) . '</small>';
                }
            }
            return $out;
        };
        $amounts = $sumList($tot['amount']);
        $bought = $sumList($tot['bought']);
        $h .= '<div class="pcdna-kpis">' . View::kpi('activity', 'brand', 'کل ترافیک ماه', View::gb($tot['used']), View::n(count($rows)) . ' سایت')
            . View::kpi('wallet', 'ok', 'ترافیک خریداری‌شده (کیف پول)', View::gb($tot['bought_gb']), $bought ? implode(' · ', $bought) : 'خریدی ثبت نشده')
            . View::kpi('warn', 'warn', 'ترافیک مازاد', View::gb($tot['over']), 'بیش از سقف (پلن + خرید)')
            . View::kpi('tag', 'violet', 'مبلغ تخمینی مازاد', $amounts ? implode('<br>', $amounts) : '<span class="pcdna-muted">۰</span>', 'حالت فاکتور پایان ماه') . '</div>';
        if (!$rows) {
            return $h . View::card('', View::emptyState('برای این ماه مصرفی ثبت نشده است', '', 'chart')) . self::purchases($month);
        }
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-usage"><thead><tr><th>دامنه / محصول</th><th>سرویس / مشتری</th>'
            . '<th>مصرف (GB)</th><th>پلن + خرید (GB)</th><th>مازاد (GB)</th><th>مبلغ</th><th class="pcdna-num" title="جمع فاکتورهای خرید ترافیک این سرویس در این ماه">درآمد</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            if ($r['prepaid']) {
                $inv = implode(' ', array_map(function ($id) {
                    return '<a href="invoices.php?action=edit&amp;id=' . (int) $id . '">#' . View::n($id) . '</a>';
                }, $r['invoices']));
                $amountCell = $r['bought'] > 0 ? '<strong>' . $money($r['bought']) . '</strong> <small>' . View::e($r['bought_code']) . '</small>'
                    . '<div class="pcdna-small pcdna-muted">از کیف پول ' . $inv . '</div>' : '<span class="pcdna-muted" title="پیش‌پرداخت: خریدی در این ماه ثبت نشده">۰</span>';
                $limitCell = View::n($r['plan']) . ($r['bought_gb'] > 0 ? ' <span class="pcdna-bought">+ ' . View::n($r['bought_gb']) . '</span>' : '');
            } else {
                $amountCell = $r['amount'] === null ? '<span class="pcdna-muted" title="صورتحساب ترافیک اضافه برای این محصول فعال نیست">—</span>'
                    : ($r['amount'] > 0 ? '<strong>' . $money($r['amount']) . '</strong> <small>' . View::e($r['currency']) . '</small><div class="pcdna-small pcdna-muted">تخمین فاکتور پایان ماه</div>' : '<span class="pcdna-muted">۰</span>');
                $limitCell = $r['limit'] > 0 ? View::n($r['limit']) : 'نامحدود';
            }
            $t .= '<tr' . ($r['over'] > 0 ? ' class="is-warn"' : '') . '><td class="pcdna-nowrap">' . View::ltr($r['domain'])
                . '<div class="pcdna-small pcdna-muted">' . View::e($r['product'] ?: '—') . ($r['prepaid'] ? ' · پیش‌پرداخت' : '') . '</div></td>'
                . '<td>' . ($r['service'] ? '<a href="' . View::e(Data::serviceUrl($r['userid'], $r['service'])) . '">#' . View::n($r['service']) . '</a>'
                    . '<div class="pcdna-small"><a href="' . View::e(Data::clientUrl($r['userid'])) . '">' . View::e($r['client']) . '</a></div>'
                    : View::badge('بدون سرویس', 'muted')) . '</td>'
                . '<td class="pcdna-num">' . View::n($r['used'], 2) . ($r['limit'] > 0 ? View::meter($r['used'] / $r['limit']) : '') . '</td>'
                . '<td class="pcdna-num">' . $limitCell . '</td>'
                . '<td class="pcdna-num">' . ($r['over'] > 0 ? '<strong>' . View::n($r['over'], 2) . '</strong>' : '<span class="pcdna-muted">۰</span>') . '</td>'
                . '<td class="pcdna-num">' . $amountCell . '</td>'
                . '<td class="pcdna-num">' . ($r['bought'] > 0 ? '<strong>' . $money($r['bought']) . '</strong> <small>' . View::e($r['bought_code']) . '</small>' : '<span class="pcdna-muted">۰</span>') . '</td></tr>';
        }
        $t .= '</tbody><tfoot><tr><th colspan="2">جمع</th><th class="pcdna-num">' . View::n($tot['used'], 2) . '</th><th class="pcdna-num">'
            . ($tot['bought_gb'] > 0 ? '<span class="pcdna-bought">+ ' . View::n($tot['bought_gb']) . '</span>' : '') . '</th><th class="pcdna-num">'
            . View::n($tot['over'], 2) . '</th><th class="pcdna-num">' . (($bought || $amounts) ? implode('<br>', array_merge($bought, $amounts)) : '—') . '</th>'
            . '<th class="pcdna-num">' . ($bought ? implode('<br>', $bought) : '—') . '</th></tr></tfoot></table></div>';
        $h .= View::card('مصرف ' . View::digits($month), $t . '<p class="pcdna-muted pcdna-small pcdna-pad">پیش‌پرداخت: بسته‌های خریداری‌شده از کیف پول با فاکتور پرداخت‌شده ثبت می‌شوند. '
                . 'حالت فاکتور پایان ماه: مبلغ تخمینی = مازاد × قیمت هر گیگابایت محصول × نرخ ارز مشتری؛ WHMCS مازاد را بر اساس مصرفی که کران روزانه (UsageUpdate) ثبت کرده در پایان ماه فاکتور می‌کند.</p>', '', 'pcdna-flush', 'chart');
        return $h . self::purchases($month);
    }

    const TOPUP_STATUS = ['paid' => ['پرداخت‌شده', 'ok'], 'pending' => ['در حال پرداخت', 'warn'], 'failed' => ['ناموفق/لغو', 'bad']];

    /** «خریدهای ترافیک» of a month. */
    public static function purchases(string $month): string
    {
        $list = Data::topups($month, 300);
        if (!$list) {
            return View::card('خریدهای ترافیک', View::emptyState('در این ماه ترافیکی از کیف پول خریده نشده است',
                'در حالت پیش‌پرداخت، وقتی مصرف سرویسی به سقفش نزدیک شود و اعتبار مشتری کافی باشد، بسته‌ها خودکار خریده می‌شوند.', 'wallet'), '', '', 'wallet');
        }
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table"><thead><tr><th>زمان</th><th>دامنه / سرویس</th><th>مشتری</th><th>حجم</th><th>مبلغ</th><th>فاکتور</th><th>وضعیت</th></tr></thead><tbody>';
        foreach ($list as $x) {
            [$st, $tone] = self::TOPUP_STATUS[$x->status] ?? [$x->status, 'muted'];
            $t .= '<tr><td class="pcdna-nowrap">' . View::e(View::date($x->created_at, true)) . '</td>'
                . '<td>' . View::ltr(Env::domain((string) $x->domain)) . '<div class="pcdna-small"><a href="' . View::e(Data::serviceUrl((int) $x->userid, (int) $x->service_id)) . '">#' . View::n($x->service_id) . '</a></div></td>'
                . '<td><a href="' . View::e(Data::clientUrl((int) $x->userid)) . '">' . View::e(Data::clientName($x)) . '</a></td>'
                . '<td class="pcdna-num">' . View::n($x->gb) . ' GB' . ((int) $x->blocks > 1 ? '<div class="pcdna-small pcdna-muted">' . View::n($x->blocks) . ' بسته</div>' : '') . '</td>'
                . '<td class="pcdna-num">' . View::n($x->amount, (float) $x->amount >= 100 ? 0 : 2) . ' <small>' . View::e($x->currency_code) . '</small></td>'
                . '<td>' . ($x->invoice_id ? '<a href="invoices.php?action=edit&amp;id=' . (int) $x->invoice_id . '">#' . View::n($x->invoice_id) . '</a>' : '—') . '</td>'
                . '<td>' . View::badge($st, $tone) . '</td></tr>';
        }
        $t .= '</tbody></table></div>';
        return View::card('خریدهای ترافیک (' . View::n(count($list)) . ')', $t, '', 'pcdna-flush', 'wallet');
    }

    /** CSV (UTF-8 with BOM so Excel shows Persian correctly). */
    public static function usageCsv(string $month): array
    {
        [$rows, , $month, $err] = self::usageData(self::validMonth($month));
        if ($err) {
            return [502, 'text/plain; charset=utf-8', 'controller error: ' . (string) $err['error'], ''];
        }
        $fh = fopen('php://temp', 'w+');
        fwrite($fh, "\xEF\xBB\xBF");
        fputcsv($fh, ['شناسه سرویس', 'مشتری', 'دامنه', 'محصول', 'وضعیت', 'مصرف (GB)', 'سقف ترافیک (GB)', 'مازاد (GB)', 'مبلغ تخمینی', 'ارز', 'درخواست‌ها',
            'خرید پیش‌پرداخت (GB)', 'مبلغ خرید پیش‌پرداخت', 'فاکتورهای خرید', 'درآمد خرید ترافیک', 'ارز درآمد'], ',', '"', '\\');
        foreach ($rows as $r) {
            fputcsv($fh, [$r['service'] ?: '', self::csvSafe($r['client']), $r['domain'], self::csvSafe($r['product']), $r['status'],
                number_format($r['used'], 3, '.', ''), $r['limit'] > 0 ? number_format($r['limit'], 3, '.', '') : '',
                number_format($r['over'], 3, '.', ''), $r['amount'] === null ? '' : number_format($r['amount'], 2, '.', ''),
                $r['currency'], $r['requests'], $r['bought_gb'] ?: '', $r['bought'] > 0 ? number_format($r['bought'], 2, '.', '') : '',
                implode(' ', $r['invoices']),
                $r['bought'] > 0 ? number_format($r['bought'], 2, '.', '') : '0', $r['bought'] > 0 ? $r['bought_code'] : ''], ',', '"', '\\');
        }
        rewind($fh);
        $csv = (string) stream_get_contents($fh);
        fclose($fh);
        return [200, 'text/csv; charset=utf-8', $csv, 'pasargad-cdn-usage-' . $month . '.csv'];
    }

    /** Neutralise spreadsheet formulas in free text (CSV injection). */
    private static function csvSafe(string $s): string
    {
        return preg_match('/^[=+\-@\t\r]/', $s) ? "'" . $s : $s;
    }

    // ------------------------------------------------------------------ 6. events

    public static function events(array $get): string
    {
        $source = array_key_exists((string) ($get['source'] ?? ''), self::SOURCES) ? (string) $get['source'] : '';
        $limit = (int) ($get['limit'] ?? 100);
        $limit = in_array($limit, [50, 100, 200, 500], true) ? $limit : 100;
        $dq = strtolower(View::clip(Env::input($get['domain'] ?? ''), 100));
        $h = '<form method="get" action="addonmodules.php" class="pcdna-filters"><input type="hidden" name="module" value="' . View::e(Env::MODULE) . '">'
            . '<input type="hidden" name="page" value="events">'
            . View::select('source', ['' => 'همه منابع'] + self::SOURCES, $source, ' aria-label="منبع"')
            . '<label class="pcdna-search">' . View::icon('search') . '<input type="search" name="domain" class="pcdna-input" dir="ltr" value="' . View::e($dq) . '" placeholder="example.com" aria-label="دامنه"></label>'
            . View::select('limit', [50 => '۵۰ رویداد', 100 => '۱۰۰ رویداد', 200 => '۲۰۰ رویداد', 500 => '۵۰۰ رویداد'], $limit, ' aria-label="تعداد"')
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('search') . '<span>اعمال</span></button></form>';
        $ping = self::ping();
        if (!$ping['ok']) {
            return $h . self::ctlError($ping);
        }
        $path = '/api/v1/events?' . http_build_query(array_filter(['limit' => $limit, 'source' => $source]));
        $r = self::fetch([$path])[$path];
        if (!self::ok($r)) {
            return $h . View::alert('bad', 'رویدادها دریافت نشد: ' . View::e((string) $r['error']));
        }
        $events = array_values(array_filter((array) $r['data'], function ($e) use ($dq) {
            return is_array($e) && ($dq === '' || strpos(strtolower((string) ($e['domain'] ?? '')), $dq) !== false);
        }));
        $counts = [];
        foreach ($events as $e) {
            $s = (string) ($e['source'] ?? '');
            $counts[$s] = ($counts[$s] ?? 0) + 1;
        }
        $chips = '';
        foreach (self::SOURCES as $k => $label) {
            if (!empty($counts[$k])) {
                $chips .= View::badge($label . ': ' . View::n($counts[$k]), 'violet') . ' ';
            }
        }
        $h .= View::card('رویدادهای امنیتی (' . View::n(count($events)) . ')', ($events ? ($chips !== '' ? '<p class="pcdna-pad">' . $chips . '</p>' : '')
            . self::eventTable($events, Data::servicesByDomain(), false) : View::emptyState('رویدادی با این فیلتر پیدا نشد', '', 'shield')), '', 'pcdna-flush', 'shield');
        return $h;
    }

    // ------------------------------------------------------------------ 7. platform analytics (SPEC §9.1)

    const PERIODS = ['24h' => '۲۴ ساعت', '7d' => '۷ روز', '30d' => '۳۰ روز'];
    const SEC_SRC = ['waf' => 'WAF', 'firewall' => 'فایروال', 'ratelimit' => 'محدودیت نرخ', 'challenge' => 'چالش', 'ddos' => 'DDoS', 'hotlink' => 'هات‌لینک'];
    const STATUS_CLASSES = ['2xx' => ['موفق (2xx)', 'c-2xx'], '3xx' => ['ریدایرکت (3xx)', 'c-3xx'], '4xx' => ['خطای کاربر (4xx)', 'c-4xx'], '5xx' => ['خطای سرور (5xx)', 'c-5xx']];

    /**
     * «آنالیتیکس»: platform-wide traffic, cache performance, status codes, security
     * events over time, top countries and top sites. GET /api/v1/analytics?period=.
     */
    public static function analytics(array $get): string
    {
        $period = in_array($get['period'] ?? '', ['24h', '7d', '30d'], true) ? (string) $get['period'] : '24h';
        $h = self::analyticsBar($period);
        $ping = self::ping();
        if (!$ping['ok']) {
            return $h . self::ctlError($ping);
        }
        $path = '/api/v1/analytics?period=' . $period;
        $r = self::fetch([$path])[$path];
        if (!self::ok($r)) {
            return $h . View::alert('bad', 'دریافت آمار پلتفرم ممکن نشد: ' . View::e((string) $r['error']));
        }
        $a = (array) $r['data'];
        $tot = (array) ($a['totals'] ?? []);
        $series = array_values(array_filter((array) ($a['series'] ?? []), 'is_array'));
        $st = (array) ($tot['status'] ?? []);
        $sec = (array) ($tot['security'] ?? []);
        $reqs = (int) ($tot['requests'] ?? 0);
        $hits = (int) ($tot['cache_hits'] ?? 0);
        $secTotal = 0;
        foreach ($sec as $v) {
            $secTotal += (int) $v;
        }

        // KPI tiles
        $na = '<span class="pcdna-muted">—</span>';
        $h .= '<div class="pcdna-kpis" data-analytics-kpis="1">';
        $h .= View::kpi('chart', 'brand', 'کل درخواست‌ها', self::short($reqs), View::n($reqs) . ' درخواست در این بازه');
        $h .= View::kpi('activity', 'violet', 'پهنای باند', View::bytes($tot['bytes'] ?? 0), 'حجم ارسال‌شده از همه سایت‌ها');
        $h .= View::kpi('zap', 'ok', 'نرخ کش', $reqs > 0 ? View::n($hits * 100 / $reqs, 1) . '٪' : $na, self::short($hits) . ' پاسخ از کش');
        $h .= View::kpi('shield', 'bad', 'رویدادهای امنیتی', View::n($secTotal), 'مسدود یا ثبت‌شده در همه سایت‌ها');
        $h .= '</div>';

        // traffic over time: requests + cache hits (area) and bytes (bars)
        $labels = self::seriesLabels($series, $period);
        if (!$series) {
            $h .= View::card('ترافیک در طول زمان', View::emptyState('هنوز داده‌ای برای این بازه ثبت نشده است',
                'پس از تغییر نیم‌سرورهای مشتری‌ها و عبور ترافیک از نودها، آمار اینجا نمایش داده می‌شود.', 'chart'), '', '', 'chart');
        } else {
            $reqVals = array_map(function ($p) { return (int) ($p['requests'] ?? 0); }, $series);
            $hitVals = array_map(function ($p) { return (int) ($p['cache_hits'] ?? 0); }, $series);
            $byteVals = array_map(function ($p) { return (float) ($p['bytes'] ?? 0); }, $series);
            $reqChart = self::chart($labels, [
                ['color' => 'var(--a-c-req)', 'name' => 'کل درخواست‌ها', 'total' => self::short($reqs), 'values' => $reqVals],
                ['color' => 'var(--a-c-hit)', 'name' => 'پاسخ از کش', 'total' => self::short($hits), 'values' => $hitVals],
            ], 'area', 'num', 'نمودار درخواست‌ها و پاسخ‌های کش‌شده');
            $byteChart = self::chart($labels, [
                ['color' => 'var(--a-c-bytes)', 'name' => 'ترافیک', 'total' => View::bytes($tot['bytes'] ?? 0), 'values' => $byteVals],
            ], 'bar', 'bytes', 'نمودار ترافیک');
            $h .= '<div class="pcdna-grid-2">'
                . View::card('درخواست‌ها و کش', $reqChart, '', '', 'chart')
                . View::card('ترافیک', $byteChart, '', '', 'activity') . '</div>';
        }

        // status codes + security over time
        $statusCard = self::statusBreakdown($st, $reqs);
        $secSeries = array_values(array_filter((array) ($a['security_series'] ?? []), 'is_array'));
        if ($secSeries) {
            $secLabels = self::seriesLabels($secSeries, $period);
            $secVals = array_map(function ($p) { return (int) ($p['events'] ?? 0); }, $secSeries);
            $secBody = self::chart($secLabels, [['color' => 'var(--a-c-5xx)', 'name' => 'رویدادهای امنیتی', 'total' => View::n($secTotal), 'values' => $secVals]], 'line', 'num', 'نمودار رویدادهای امنیتی در طول زمان')
                . self::secSources($sec, $secTotal);
        } else {
            $secBody = $secTotal > 0 ? self::secSources($sec, $secTotal)
                : View::emptyState('رویداد امنیتی ثبت نشده است', 'در این بازه درخواستی مسدود یا ثبت نشده است.', 'shield');
        }
        $h .= '<div class="pcdna-grid-2">'
            . View::card('کدهای وضعیت', $statusCard, '', '', 'activity')
            . View::card('رویدادهای امنیتی', $secBody, '<a class="pcdna-btn pcdna-btn-sm" href="' . View::url(['page' => 'events']) . '">مشاهده رویدادها</a>', '', 'shield')
            . '</div>';

        // top countries + top sites
        $countries = array_values(array_filter((array) ($a['countries'] ?? []), 'is_array'));
        $h .= '<div class="pcdna-grid-2">'
            . View::card('کشورهای برتر', self::countryBars($countries, $reqs), '', '', 'globe')
            . View::card('پرترافیک‌ترین سایت‌ها', self::topSites((array) ($a['sites'] ?? [])), '', 'pcdna-flush', 'chart')
            . '</div>';
        return $h;
    }

    /** Period switcher (24h / 7d / 30d) as a segmented control of links. */
    private static function analyticsBar(string $cur): string
    {
        $h = '<div class="pcdna-filters pcdna-analytics-bar" data-analytics-period="' . View::e($cur) . '">'
            . '<span class="pcdna-inline-label"><span>بازه زمانی</span></span>'
            . '<div class="pcdna-seg" role="group" aria-label="بازه زمانی">';
        foreach (self::PERIODS as $k => $lbl) {
            $on = $k === $cur;
            $h .= '<a class="pcdna-seg-item' . ($on ? ' is-active' : '') . '" href="' . View::url(['page' => 'analytics', 'period' => $k]) . '"'
                . ($on ? ' aria-current="true"' : '') . ' data-period="' . View::e($k) . '">' . View::e($lbl) . '</a>';
        }
        return $h . '</div></div>';
    }

    /** Compact number: ۱٫۲ هزار / ۳٫۴ میلیون … using Latin K/M/B suffixes to stay short. */
    public static function short($v): string
    {
        $v = (float) $v;
        if ($v >= 1e9) {
            return View::n($v / 1e9, 1) . 'B';
        }
        if ($v >= 1e6) {
            return View::n($v / 1e6, 1) . 'M';
        }
        if ($v >= 1e3) {
            return View::n($v / 1e3, 1) . 'K';
        }
        return View::n($v);
    }

    private static function niceMax($v): float
    {
        $v = (float) $v;
        if ($v <= 0) {
            return 1.0;
        }
        $p = pow(10, floor(log10($v)));
        $n = $v / $p;
        $m = $n <= 1 ? 1 : ($n <= 2 ? 2 : ($n <= 2.5 ? 2.5 : ($n <= 5 ? 5 : 10)));
        return $m * $p;
    }

    /** X-axis labels: hour of day for 24h, month/day otherwise (Persian digits). */
    private static function seriesLabels(array $series, string $period): array
    {
        $hourly = $period === '24h';
        $out = [];
        foreach ($series as $p) {
            $t = strtotime((string) ($p['t'] ?? ''));
            $out[] = $t === false ? '' : View::digits($hourly ? gmdate('H:i', $t) : gmdate('m/d', $t));
        }
        return $out;
    }

    private static function axisLabel(string $fmt, float $v): string
    {
        return $fmt === 'bytes' ? View::bytes($v) : self::short($v);
    }

    /**
     * Static inline-SVG chart (area / bar / line), token colours only, responsive
     * (viewBox + width:100%). No JS: consistent with the admin's server-rendered style.
     * @param array $series list of ['color', 'name', 'total', 'values']
     */
    private static function chart(array $labels, array $series, string $type, string $axisFmt, string $aria): string
    {
        $n = count($labels);
        $W = 640;
        $H = 240;
        $L = 58;
        $R = 14;
        $T = 14;
        $B = 30;
        $pw = $W - $L - $R;
        $ph = $H - $T - $B;
        $vals = [];
        foreach ($series as $s) {
            foreach ($s['values'] as $v) {
                $vals[] = (float) $v;
            }
        }
        $max = self::niceMax($vals ? max($vals) : 0);
        $y = function ($v) use ($T, $ph, $max) {
            return round($T + $ph - ($max > 0 ? ((float) $v / $max) * $ph : 0), 1);
        };
        $xAt = function ($i) use ($L, $pw, $n) {
            return round($n > 1 ? $L + $i * $pw / ($n - 1) : $L + $pw / 2, 1);
        };
        $svg = '<svg viewBox="0 0 ' . $W . ' ' . $H . '" class="pcdna-chart-svg" preserveAspectRatio="none" role="img" aria-label="' . View::e($aria) . '">';
        for ($i = 0; $i <= 4; $i++) {
            $yy = $y($max * $i / 4);
            $svg .= '<line x1="' . $L . '" x2="' . ($W - $R) . '" y1="' . $yy . '" y2="' . $yy . '" class="pcdna-chart-grid' . ($i === 0 ? ' is-base' : '') . '"/>'
                . '<text x="' . ($L - 8) . '" y="' . ($yy + 4) . '" text-anchor="end" class="pcdna-chart-axis">' . View::e(self::axisLabel($axisFmt, $max * $i / 4)) . '</text>';
        }
        $step = max(1, (int) ceil($n / 7));
        for ($i = 0; $i < $n; $i++) {
            if ($i % $step === 0 && $labels[$i] !== '') {
                $svg .= '<text x="' . $xAt($i) . '" y="' . ($H - 10) . '" text-anchor="middle" class="pcdna-chart-axis">' . View::e($labels[$i]) . '</text>';
            }
        }
        foreach ($series as $s) {
            $color = $s['color'];
            if ($type === 'bar') {
                $slot = $pw / max(1, $n);
                $bw = max(2.0, min(26.0, $slot * 0.6));
                for ($i = 0; $i < $n; $i++) {
                    $yy = $y($s['values'][$i]);
                    $bh = round($T + $ph - $yy, 1);
                    if ($bh <= 0) {
                        continue;
                    }
                    $x = round($L + $i * $slot + ($slot - $bw) / 2, 1);
                    $svg .= '<rect x="' . $x . '" y="' . $yy . '" width="' . round($bw, 1) . '" height="' . $bh . '" rx="2" fill="' . View::e($color) . '"/>';
                }
            } else {
                $d = '';
                for ($i = 0; $i < $n; $i++) {
                    $d .= ($i ? 'L' : 'M') . $xAt($i) . ' ' . $y($s['values'][$i]) . ' ';
                }
                $d = trim($d);
                if ($type === 'area') {
                    $svg .= '<path d="' . $d . ' L' . $xAt($n - 1) . ' ' . ($T + $ph) . ' L' . $xAt(0) . ' ' . ($T + $ph) . ' Z" fill="' . View::e($color) . '" fill-opacity="0.13" stroke="none"/>';
                }
                $svg .= '<path d="' . $d . '" fill="none" stroke="' . View::e($color) . '" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>';
            }
        }
        $svg .= '</svg>';
        $leg = '<div class="pcdna-chart-legend">';
        foreach ($series as $s) {
            $leg .= '<span class="pcdna-chart-lg"><span class="pcdna-chart-key" style="background:' . View::e($s['color']) . '"></span>'
                . '<span>' . View::e((string) ($s['name'] ?? '')) . '</span>'
                . (isset($s['total']) && $s['total'] !== '' ? '<strong class="pcdna-num">' . $s['total'] . '</strong>' : '') . '</span>';
        }
        $leg .= '</div>';
        return '<div class="pcdna-chart" dir="ltr">' . $svg . '</div>' . $leg;
    }

    /** Status-code breakdown as coloured proportional bars (2xx/3xx/4xx/5xx). */
    private static function statusBreakdown(array $st, int $reqs): string
    {
        $sum = 0;
        foreach (self::STATUS_CLASSES as $k => $_) {
            $sum += (int) ($st[$k] ?? 0);
        }
        if ($sum <= 0) {
            return View::emptyState('کد وضعیتی ثبت نشده است', '', 'activity');
        }
        $h = '<ul class="pcdna-barlist" data-status-bars="1">';
        foreach (self::STATUS_CLASSES as $k => [$label, $cls]) {
            $v = (int) ($st[$k] ?? 0);
            $ratio = $sum > 0 ? $v / $sum : 0;
            $h .= '<li><div class="pcdna-barlist-row"><span class="pcdna-barlist-label">' . View::e($label) . '</span>'
                . '<span class="pcdna-barlist-val"><strong class="pcdna-num">' . self::short($v) . '</strong><span class="pcdna-muted">'
                . View::n($ratio * 100, 1) . '٪</span></span></div>'
                . '<span class="pcdna-barlist-track"><span class="pcdna-barlist-bar pcdna-' . $cls . '" style="width:' . round(max($v > 0 ? 1 : 0, $ratio * 100), 1) . '%"></span></span></li>';
        }
        return $h . '</ul>';
    }

    /** Security events broken down by source (WAF, firewall, …) as bars. */
    private static function secSources(array $sec, int $total): string
    {
        $rows = [];
        foreach (self::SEC_SRC as $k => $label) {
            $v = (int) ($sec[$k] ?? 0);
            if ($v > 0) {
                $rows[] = [$label, $v];
            }
        }
        if (!$rows) {
            return '<p class="pcdna-muted pcdna-small pcdna-pad">در این بازه رویداد امنیتی‌ای ثبت نشده است.</p>';
        }
        usort($rows, function ($a, $b) {
            return $b[1] - $a[1];
        });
        $max = $rows[0][1] ?: 1;
        $h = '<ul class="pcdna-barlist" data-sec-sources="1">';
        foreach ($rows as [$label, $v]) {
            $h .= '<li><div class="pcdna-barlist-row"><span class="pcdna-barlist-label">' . View::e($label) . '</span>'
                . '<span class="pcdna-barlist-val"><strong class="pcdna-num">' . View::n($v) . '</strong>'
                . '<span class="pcdna-muted">' . View::n($total > 0 ? $v * 100 / $total : 0, 1) . '٪</span></span></div>'
                . '<span class="pcdna-barlist-track"><span class="pcdna-barlist-bar pcdna-c-5xx" style="width:' . round(max(1, $v * 100 / $max), 1) . '%"></span></span></li>';
        }
        return $h . '</ul>';
    }

    /** Top countries by requests (code + proportional bar). */
    private static function countryBars(array $countries, int $reqs): string
    {
        $countries = array_slice(array_values(array_filter($countries, function ($c) {
            return is_array($c) && (int) ($c['requests'] ?? 0) > 0;
        })), 0, 10);
        if (!$countries) {
            return View::emptyState('هنوز داده‌ای برای کشورها ثبت نشده است', '', 'globe');
        }
        $max = max(array_map(function ($c) {
            return (int) $c['requests'];
        }, $countries)) ?: 1;
        $h = '<ul class="pcdna-barlist" data-countries="1">';
        foreach ($countries as $c) {
            $code = strtoupper((string) ($c['code'] ?? '?'));
            $v = (int) $c['requests'];
            $h .= '<li><div class="pcdna-barlist-row"><span class="pcdna-barlist-label">' . View::ltr($code) . '</span>'
                . '<span class="pcdna-barlist-val"><strong class="pcdna-num">' . View::n($v) . '</strong>'
                . '<span class="pcdna-muted">' . View::n($reqs > 0 ? $v * 100 / $reqs : 0, 1) . '٪</span></span></div>'
                . '<span class="pcdna-barlist-track"><span class="pcdna-barlist-bar pcdna-c-req" style="width:' . round(max(1, $v * 100 / $max), 1) . '%"></span></span></li>';
        }
        return $h . '</ul>';
    }

    /** Top-sites table (domain, requests, bytes) linking to the service in the admin. */
    private static function topSites(array $sites): string
    {
        $sites = array_values(array_filter($sites, 'is_array'));
        if (!$sites) {
            return View::emptyState('هنوز ترافیکی ثبت نشده است', 'پس از عبور ترافیک از نودها، پرترافیک‌ترین سایت‌ها اینجا فهرست می‌شوند.', 'chart');
        }
        $byDomain = Data::servicesByDomain();
        $maxB = max(1, (float) ($sites[0]['bytes'] ?? 1));
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-topsites"><thead><tr><th>دامنه</th><th>درخواست</th><th>ترافیک</th><th></th></tr></thead><tbody>';
        foreach (array_slice($sites, 0, 20) as $s) {
            $domain = (string) ($s['domain'] ?? '?');
            $svc = $byDomain[strtolower($domain)] ?? null;
            $t .= '<tr><td>' . View::ltr($domain) . '</td>'
                . '<td class="pcdna-num">' . View::n($s['requests'] ?? 0) . '</td>'
                . '<td class="pcdna-num">' . View::bytes($s['bytes'] ?? 0) . View::meter((float) ($s['bytes'] ?? 0) / $maxB, 'brand') . '</td>'
                . '<td class="pcdna-actions">' . ($svc
                    ? '<a class="pcdna-btn pcdna-btn-sm" href="' . self::manageUrl((int) $svc->id) . '">مدیریت</a>'
                        . '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::e(Data::serviceUrl((int) $svc->userid, (int) $svc->id)) . '" title="صفحه سرویس در WHMCS">#' . (int) $svc->id . '</a>'
                    : View::badge('بدون سرویس', 'muted')) . '</td></tr>';
        }
        return $t . '</tbody></table></div>';
    }

    // ------------------------------------------------------------------ 8. status & incidents

    /**
     * "وضعیت و رخدادها": the public status the customers see (/status.json) plus the
     * incident console (create / update / resolve). SPEC §8.2–8.3.
     */
    public static function status(array $state = []): string
    {
        $ctlUrl = Env::controllerUrl();
        $ping = self::ping();
        // Hint about the standalone public status page — shown whether or not the controller is up.
        $h = self::statusHint($ctlUrl);
        if (!$ping['ok']) {
            return $h . self::ctlError($ping);
        }
        $incPath = '/api/v1/incidents?all=1';
        $r = self::fetch(['/status.json', $incPath]);
        $pub = self::ok($r['/status.json']) ? (array) $r['/status.json']['data'] : null;
        $h .= self::publicStatusCard($pub, $r['/status.json']['error'] ?? '');
        $h .= self::incidentForm($state['incident_form'] ?? []);
        $inc = self::ok($r[$incPath]) ? (array) $r[$incPath]['data'] : null;
        if ($inc === null) {
            $h .= View::card('رخدادها', View::alert('bad', 'فهرست رخدادها دریافت نشد: ' . View::e((string) ($r[$incPath]['error'] ?? ''))), '', 'pcdna-flush', 'activity');
        } else {
            $h .= self::incidentList($inc);
        }
        return $h;
    }

    private static function statusHint(string $ctlUrl): string
    {
        $public = $ctlUrl !== '' ? $ctlUrl . '/status.json' : '/status.json';
        $body = '<p class="pcdna-muted">صفحهٔ وضعیت عمومی مشتریان یک صفحهٔ ایستا و مستقل در پوشهٔ '
            . '<code dir="ltr">status/</code> مخزن پروژه است. آن را روی هر میزبان ایستا (همان دامنهٔ WHMCS یا یک زیردامنه مثل '
            . View::ltr('status.example.com') . ') آپلود کنید؛ اگر روی دامنهٔ دیگری میزبانی شد، با پارامتر '
            . '<code dir="ltr">?api=</code> یا ثابت <code dir="ltr">API_BASE</code> آن را به کنترلر وصل کنید.</p>'
            . '<p class="pcdna-label">نشانی فایل عمومی وضعیت (JSON):</p>' . View::copyable($public, 'کپی نشانی');
        return View::card('صفحهٔ وضعیت عمومی', $body, '', '', 'globe');
    }

    private static function publicStatusCard(?array $pub, string $error): string
    {
        if ($pub === null || !isset($pub['status'])) {
            return View::card('آنچه مشتریان می‌بینند', View::alert('warn', 'وضعیت عمومی (/status.json) دریافت نشد'
                . ($error !== '' ? ': ' . View::e($error) : '.')), '', 'pcdna-flush', 'activity');
        }
        [$label, $tone] = self::OVERALL_STATUS[$pub['status']] ?? [(string) $pub['status'], 'muted'];
        $banner = '<div class="pcdna-status-banner pcdna-t-' . $tone . '">' . View::dot($tone)
            . '<strong>' . View::e($label) . '</strong>'
            . '<span class="pcdna-status-when">به‌روزرسانی: ' . View::e(View::ago($pub['updated_at'] ?? '')) . '</span></div>';
        $comps = '';
        foreach ((array) ($pub['components'] ?? []) as $c) {
            if (!is_array($c)) {
                continue;
            }
            [$cl, $ct] = self::COMPONENT_STATUS[$c['status'] ?? ''] ?? [(string) ($c['status'] ?? '—'), 'muted'];
            $comps .= '<li><span>' . View::e((string) ($c['name'] ?? '')) . '</span>' . View::badge($cl, $ct) . '</li>';
        }
        $nodes = is_array($pub['nodes'] ?? null) ? $pub['nodes'] : [];
        $nodesLine = isset($nodes['total'])
            ? '<p class="pcdna-status-nodes">نودها: <strong>' . View::n((int) ($nodes['online'] ?? 0)) . '</strong> آنلاین از <strong>'
                . View::n((int) $nodes['total']) . '</strong> نود (فقط شمارش؛ IP یا نام نودها هرگز افشا نمی‌شود).</p>'
            : '';
        $body = $banner . ($comps !== '' ? '<ul class="pcdna-status-comps">' . $comps . '</ul>' : '') . $nodesLine;
        return View::card('آنچه مشتریان می‌بینند', $body, '', '', 'activity');
    }

    private static function incidentForm(array $old): string
    {
        $sev = View::select('severity', ['minor' => 'کم‌اهمیت', 'major' => 'پراهمیت', 'maintenance' => 'تعمیرات برنامه‌ریزی‌شده'], $old['severity'] ?? 'minor');
        $st = View::select('status', ['investigating' => 'در حال بررسی', 'identified' => 'علت شناسایی شد', 'monitoring' => 'در حال پایش'], $old['status'] ?? 'investigating');
        $form = '<form method="post" action="' . View::url(['page' => 'status']) . '" class="pcdna-form">' . View::csrf()
            . '<input type="hidden" name="a" value="incident_create"><div class="pcdna-form-grid">'
            . '<label class="pcdna-col-2"><span>عنوان رخداد</span><input class="pcdna-input" name="title" required maxlength="160" placeholder="اختلال در دسترسی به برخی سایت‌ها" value="' . View::e($old['title'] ?? '') . '"></label>'
            . '<label><span>شدت</span>' . $sev . '</label>'
            . '<label><span>وضعیت اولیه</span>' . $st . '</label>'
            . '<label class="pcdna-col-2"><span>توضیح</span><textarea class="pcdna-input" name="body" rows="3" required placeholder="آنچه به مشتری نمایش داده می‌شود…">' . View::e($old['body'] ?? '') . '</textarea></label>'
            . '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('plus') . '<span>ثبت رخداد جدید</span></button></div></form>';
        return View::card('ثبت رخداد جدید', $form, '', '', 'plus');
    }

    private static function incidentList(array $incidents): string
    {
        // newest first by updated_at (fallback created_at)
        usort($incidents, function ($a, $b) {
            return strcmp((string) ($b['updated_at'] ?? $b['created_at'] ?? ''), (string) ($a['updated_at'] ?? $a['created_at'] ?? ''));
        });
        if (!$incidents) {
            return View::card('رخدادها', View::emptyState('هیچ رخدادی ثبت نشده است', 'با فرم بالا می‌توانید اولین رخداد را ثبت کنید.', 'activity'), '', 'pcdna-flush', 'activity');
        }
        $open = 0;
        $body = '';
        foreach ($incidents as $inc) {
            if (!is_array($inc)) {
                continue;
            }
            if (($inc['status'] ?? '') !== 'resolved') {
                $open++;
            }
            $body .= self::incidentCard($inc);
        }
        return View::card('رخدادها (' . View::n($open) . ' باز از ' . View::n(count($incidents)) . ')', '<div class="pcdna-incidents">' . $body . '</div>', '', 'pcdna-flush', 'activity');
    }

    private static function incidentCard(array $inc): string
    {
        $id = (int) ($inc['id'] ?? 0);
        $resolved = ($inc['status'] ?? '') === 'resolved';
        [$sevLabel, $sevTone] = self::INC_SEVERITY[$inc['severity'] ?? ''] ?? [(string) ($inc['severity'] ?? '—'), 'muted'];
        [$stLabel, $stTone] = self::INC_STATUS[$inc['status'] ?? ''] ?? [(string) ($inc['status'] ?? '—'), 'muted'];
        $head = '<div class="pcdna-incident-head"><div class="pcdna-incident-titles"><strong>#' . View::n($id) . ' — ' . View::e((string) ($inc['title'] ?? '')) . '</strong>'
            . '<div class="pcdna-incident-badges">' . View::badge($sevLabel, $sevTone) . View::badge($stLabel, $stTone) . '</div></div>'
            . '<span class="pcdna-incident-when">' . View::e(View::date($inc['updated_at'] ?? $inc['created_at'] ?? '', true)) . '</span></div>';
        $bodyText = (string) ($inc['body'] ?? '');
        $desc = $bodyText !== '' ? '<p class="pcdna-incident-body">' . nl2br(View::e($bodyText)) . '</p>' : '';
        // timeline (newest first)
        $updates = (array) ($inc['updates'] ?? []);
        usort($updates, function ($a, $b) {
            return strcmp((string) ($b['at'] ?? ''), (string) ($a['at'] ?? ''));
        });
        $tl = '';
        foreach ($updates as $u) {
            if (!is_array($u)) {
                continue;
            }
            [$uLabel, $uTone] = self::INC_STATUS[$u['status'] ?? ''] ?? [(string) ($u['status'] ?? ''), 'muted'];
            $tl .= '<li class="pcdna-t-' . $uTone . '"><div class="pcdna-tl-head">' . View::badge($uLabel, $uTone)
                . '<span class="pcdna-tl-time">' . View::e(View::date($u['at'] ?? '', true)) . '</span></div>'
                . ((string) ($u['body'] ?? '') !== '' ? '<p class="pcdna-tl-body">' . nl2br(View::e((string) $u['body'])) . '</p>' : '') . '</li>';
        }
        $timeline = $tl !== '' ? '<ul class="pcdna-timeline">' . $tl . '</ul>' : '';
        // actions for open incidents
        $actions = '';
        if (!$resolved) {
            // The update form and the quick-resolve form are SIBLINGS (nested <form> is invalid HTML).
            $upForm = '<form method="post" action="' . View::url(['page' => 'status']) . '" class="pcdna-form">' . View::csrf()
                . '<input type="hidden" name="a" value="incident_update"><input type="hidden" name="id" value="' . $id . '">'
                . '<div class="pcdna-form-grid"><label><span>وضعیت جدید</span>'
                . View::select('status', ['investigating' => 'در حال بررسی', 'identified' => 'علت شناسایی شد', 'monitoring' => 'در حال پایش', 'resolved' => 'برطرف شد'], $inc['status'] ?? 'monitoring') . '</label>'
                . '<label class="pcdna-col-2"><span>متن به‌روزرسانی</span><input class="pcdna-input" name="body" required maxlength="500" placeholder="آخرین وضعیت رسیدگی…"></label>'
                . '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary pcdna-btn-sm">' . View::icon('activity') . '<span>ثبت به‌روزرسانی</span></button></div></form>';
            $resolve = View::postButton(['page' => 'status'], 'incident_resolve', ['id' => (string) $id], 'برطرف شد', 'pcdna-btn pcdna-btn-sm', 'این رخداد به‌عنوان «برطرف‌شده» ثبت شود؟', 'check');
            $actions = '<div class="pcdna-incident-update"><div class="pcdna-incident-actions">' . $upForm . $resolve . '</div></div>';
        }
        $inner = $head . $desc . $timeline . $actions;
        if ($resolved) {
            return '<details class="pcdna-incident is-resolved"><summary>' . $head . '</summary><div class="pcdna-incident-detail">' . $desc . $timeline . '</div></details>';
        }
        return '<div class="pcdna-incident is-open">' . $inner . '</div>';
    }

    // ------------------------------------------------------------------ §13.5 audit log

    /** Known mutating actions (SPEC §13.2) → Persian labels for the filter dropdown and the table. */
    const AUDIT_ACTIONS = [
        'site.create' => 'ساخت سایت',
        'site.plan' => 'تغییر پلن سایت',
        'site.delete' => 'حذف سایت',
        'edge.add' => 'افزودن نود',
        'edge.rotate' => 'چرخش توکن نود',
        'edge.patch' => 'ویرایش نود',
        'edge.delete' => 'حذف نود',
        'edge.address.add' => 'افزودن آدرس نود',
        'edge.address.del' => 'حذف آدرس نود',
        'purge' => 'پاکسازی کش',
        'reseller.flag' => 'فعال‌سازی نماینده',
        'reseller.rate' => 'تغییر نرخ نماینده',
        'tunnel.enable_existing' => 'فعال‌سازی تونل سرویس‌های موجود',
    ];
    /** actor_kind → [label, tone]. */
    const AUDIT_KINDS = ['admin' => ['مدیر', 'brand'], 'capi' => ['API مشتری', 'violet'], 'system' => ['سیستم', 'muted']];
    /** time-range filter → seconds before now (mapped to the controller's ?since=). */
    const AUDIT_RANGES = ['24h' => ['۲۴ ساعت گذشته', 86400], '7d' => ['۷ روز گذشته', 604800],
        '30d' => ['۳۰ روز گذشته', 2592000], 'all' => ['همهٔ زمان‌ها', 0]];

    /**
     * «حسابرسی»: the controller audit log (SPEC §13.2/§13.5), newest-first, with
     * action/actor/time filters. Read-only; the filter form is GET (no mutation,
     * so inherently CSRF-safe) and the data is fetched through the same ≤10 s,
     * per-request-memoised path the other pages use.
     */
    public static function audit(array $get): string
    {
        $action = array_key_exists((string) ($get['action'] ?? ''), self::AUDIT_ACTIONS) ? (string) $get['action'] : '';
        $actor = View::clip(Env::input($get['actor'] ?? ''), 100);
        $range = array_key_exists((string) ($get['range'] ?? ''), self::AUDIT_RANGES) ? (string) $get['range'] : '7d';
        $limit = (int) ($get['limit'] ?? 100);
        $limit = in_array($limit, [50, 100, 200, 500], true) ? $limit : 100;

        $actions = ['' => 'همهٔ کنش‌ها'] + self::AUDIT_ACTIONS;
        $ranges = [];
        foreach (self::AUDIT_RANGES as $k => [$lbl]) {
            $ranges[$k] = $lbl;
        }
        $h = '<form method="get" action="addonmodules.php" class="pcdna-filters"><input type="hidden" name="module" value="' . View::e(Env::MODULE) . '">'
            . '<input type="hidden" name="page" value="audit">'
            . View::select('action', $actions, $action, ' aria-label="کنش"')
            . '<label class="pcdna-search">' . View::icon('search') . '<input type="search" name="actor" class="pcdna-input" dir="ltr" value="' . View::e($actor) . '" placeholder="عامل (مثلاً admin:root یا capi:۱۲)" aria-label="عامل"></label>'
            . View::select('range', $ranges, $range, ' aria-label="بازه زمانی"')
            . View::select('limit', [50 => '۵۰ مورد', 100 => '۱۰۰ مورد', 200 => '۲۰۰ مورد', 500 => '۵۰۰ مورد'], $limit, ' aria-label="تعداد"')
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('search') . '<span>اعمال</span></button></form>';

        $ping = self::ping();
        if (!$ping['ok']) {
            return $h . self::ctlError($ping);
        }
        $query = array_filter(['limit' => $limit, 'action' => $action, 'actor' => $actor], function ($v) {
            return $v !== '' && $v !== null;
        });
        $secs = self::AUDIT_RANGES[$range][1];
        if ($secs > 0) {
            $query['since'] = gmdate('Y-m-d\TH:i:s\Z', time() - $secs);
        }
        $path = '/api/v1/audit?' . http_build_query($query);
        $r = self::fetch([$path])[$path];
        // Older controller without the audit endpoint: feature-detect on 404 and degrade gracefully.
        if (($r['code'] ?? 0) === 404) {
            return $h . View::card('حسابرسی', View::alert('warn', 'این نسخه از کنترلر هنوز از گزارش حسابرسی (<code dir="ltr">/api/v1/audit</code>) پشتیبانی نمی‌کند. پس از به‌روزرسانی کنترلر، رخدادهای مدیریتی اینجا نمایش داده می‌شوند.'), '', 'pcdna-flush', 'history');
        }
        if (!self::ok($r)) {
            return $h . View::alert('bad', 'گزارش حسابرسی دریافت نشد: ' . View::e((string) $r['error']));
        }
        $entries = array_values(array_filter((array) $r['data'], 'is_array'));
        // The controller returns newest-first; sort defensively so the order is guaranteed regardless.
        usort($entries, function ($a, $b) {
            return strcmp((string) ($b['at'] ?? ''), (string) ($a['at'] ?? ''));
        });
        $body = $entries ? self::auditTable($entries)
            : View::emptyState('رخدادی با این فیلتر پیدا نشد', 'فیلترها را تغییر دهید یا بازهٔ زمانی را گسترده‌تر کنید.', 'history');
        // SPEC §18.3: the whole platform audit of the chosen range as CSV (controller GET /api/v1/audit/export)
        $export = '<a class="pcdna-btn pcdna-btn-sm pcdna-audit-export" href="' . View::url(['page' => 'audit', 'export' => 'csv', 'range' => $range]) . '">'
            . View::icon('download') . '<span>دریافت CSV</span></a>';
        return $h . View::card('حسابرسی (' . View::n(count($entries)) . ' مورد)', $body, $export, 'pcdna-flush', 'history');
    }

    const AUDIT_CSV_MAX = 16777216; // 16 MB

    /**
     * SPEC §18.3 «دریافت CSV» of the audit page: GET /api/v1/audit/export?from&to&format=csv with the admin key,
     * streamed as the controller made it (≤ 16 MB, text/csv only). Range = the page's range filter (all = from
     * the beginning). Returns [status, content type, body, filename].
     */
    public static function auditCsv(array $get): array
    {
        $range = array_key_exists((string) ($get['range'] ?? ''), self::AUDIT_RANGES) ? (string) $get['range'] : '7d';
        $secs = self::AUDIT_RANGES[$range][1];
        $now = time();
        $q = ['format' => 'csv', 'to' => gmdate('Y-m-d\TH:i:s\Z', $now)];
        if ($secs > 0) {
            $q['from'] = gmdate('Y-m-d\TH:i:s\Z', $now - $secs);
        }
        $file = 'pasargadcdn-audit-' . ($secs > 0 ? gmdate('Y-m-d', $now - $secs) . '-' : 'all-') . gmdate('Y-m-d', $now) . '.csv';
        try {
            [$code, $body, $type] = Env::api(30)->download('/api/v1/audit/export?' . http_build_query($q), self::AUDIT_CSV_MAX, 'text/csv, application/json;q=0.5');
        } catch (\Throwable $e) {
            return [502, 'text/plain; charset=utf-8', 'controller error: ' . $e->getMessage(), ''];
        }
        if ($body === null) {
            return [502, 'text/plain; charset=utf-8', 'controller error: export larger than 16 MB', ''];
        }
        if ($code === 404) {
            return [404, 'text/plain; charset=utf-8', 'this controller has no audit export yet (GET /api/v1/audit/export)', ''];
        }
        $ct = strtolower(trim(explode(';', (string) $type)[0]));
        if ($code !== 200 || !in_array($ct, ['text/csv', 'application/csv', 'text/plain'], true) || preg_match('/^(\xEF\xBB\xBF)?\s*</', (string) $body)) {
            return [502, 'text/plain; charset=utf-8', 'controller error: HTTP ' . $code . ' ' . $ct, ''];
        }
        return [200, 'text/csv; charset=utf-8', (string) $body, $file];
    }

    private static function auditTable(array $entries): string
    {
        $h = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-audit"><thead><tr>'
            . '<th>زمان</th><th>کنش</th><th>هدف</th><th>عامل</th><th>IP</th><th>جزئیات</th></tr></thead><tbody>';
        foreach ($entries as $e) {
            $act = (string) ($e['action'] ?? '');
            $actLabel = self::AUDIT_ACTIONS[$act] ?? ($act !== '' ? $act : '—');
            [$kLabel, $kTone] = self::AUDIT_KINDS[(string) ($e['actor_kind'] ?? '')] ?? [(string) ($e['actor_kind'] ?? '—'), 'muted'];
            $target = (string) ($e['target'] ?? '');
            $ip = (string) ($e['ip'] ?? '');
            $actor = (string) ($e['actor'] ?? '');
            $actorCell = View::badge($kLabel, $kTone) . ($actor !== '' ? ' ' . View::ltr($actor) : '');
            $h .= '<tr><td class="pcdna-nowrap">' . View::e(View::date($e['at'] ?? '', true)) . '</td>'
                . '<td><span class="pcdna-badge pcdna-t-muted" title="' . View::e($act) . '">' . View::e($actLabel) . '</span></td>'
                . '<td>' . ($target !== '' ? View::ltr($target) : '<span class="pcdna-muted">—</span>') . '</td>'
                . '<td>' . $actorCell . '</td>'
                . '<td>' . ($ip !== '' ? View::ltr($ip) : '<span class="pcdna-muted">—</span>') . '</td>'
                . '<td class="pcdna-audit-detail">' . self::auditDetail($e['detail'] ?? null) . '</td></tr>';
        }
        return $h . '</tbody></table></div>';
    }

    /** Compact, escaped rendering of the (secret-free) JSON `detail` field. */
    private static function auditDetail($detail): string
    {
        if ($detail === null || $detail === '' || $detail === []) {
            return '<span class="pcdna-muted">—</span>';
        }
        if (is_array($detail)) {
            $parts = [];
            foreach ($detail as $k => $v) {
                if (is_array($v)) {
                    $v = json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                } elseif (is_bool($v)) {
                    $v = $v ? 'true' : 'false';
                }
                $parts[] = '<span class="pcdna-kv"><b>' . View::e((string) $k) . '</b>: ' . View::e(View::clip((string) $v, 80)) . '</span>';
            }
            return implode(' ', $parts);
        }
        return '<code dir="ltr">' . View::e(View::clip((string) $detail, 160)) . '</code>';
    }

    // ------------------------------------------------------------------ §13.5 system health panel

    /**
     * «سلامت سامانه»: platform health summarising GET /healthz/deep (SPEC §13.1/§13.5).
     * Prefers the JSON /healthz/deep over scraping /metrics. Every field is optional —
     * an older controller that omits a block degrades to «نامشخص» instead of erroring.
     */
    public static function health(): string
    {
        $ping = self::ping();
        if (!$ping['ok']) {
            return self::ctlError($ping);
        }
        $r = self::fetch(['/healthz/deep']);
        $rr = $r['/healthz/deep'];
        // /healthz/deep answers 200 (ok) or 503 (down) but always carries a JSON body with `status`.
        $deep = is_array($rr['data'] ?? null) && isset($rr['data']['status']) ? (array) $rr['data'] : null;
        if ($deep === null) {
            if (($rr['code'] ?? 0) === 404) {
                return View::card('سلامت سامانه', View::alert('warn', 'این نسخه از کنترلر <code dir="ltr">/healthz/deep</code> را ارائه نمی‌کند؛ پس از به‌روزرسانی، خلاصهٔ سلامت سامانه اینجا نمایش داده می‌شود.'), '', 'pcdna-flush', 'heart');
            }
            return View::card('سلامت سامانه', View::alert('bad', 'وضعیت سلامت سامانه دریافت نشد: ' . View::e((string) ($rr['error'] ?? 'پاسخ نامعتبر'))), '', 'pcdna-flush', 'heart');
        }
        return self::healthPanel($deep);
    }

    /** Builds the banner + health tiles + technical-details block from a /healthz/deep body. */
    public static function healthPanel(array $deep): string
    {
        [$ovLabel, $ovTone] = ['سالم', 'ok'];
        if (($deep['status'] ?? 'ok') === 'degraded') {
            [$ovLabel, $ovTone] = ['اختلال جزئی', 'warn'];
        } elseif (($deep['status'] ?? 'ok') === 'down') {
            [$ovLabel, $ovTone] = ['خطا — سامانه در دسترس نیست', 'bad'];
        }
        $banner = '<div class="pcdna-status-banner pcdna-t-' . $ovTone . '" data-health-status="' . View::e((string) ($deep['status'] ?? '')) . '">'
            . View::dot($ovTone) . '<strong>' . View::e($ovLabel) . '</strong>'
            . '<span class="pcdna-status-when">' . View::ltr(Env::controllerUrl()) . '</span></div>';

        $tiles = '<div class="pcdna-health-tiles">';
        $na = '<span class="pcdna-muted">نامشخص</span>';

        // 1) edges online / enabled
        if (is_array($deep['edges'] ?? null)) {
            $ed = $deep['edges'];
            $on = (int) ($ed['online'] ?? 0);
            $en = (int) ($ed['enabled'] ?? 0);
            $tone = $en > 0 && $on === 0 ? 'bad' : ($on < $en ? 'warn' : 'ok');
            $tiles .= self::healthTile($tone, 'online', View::n($on) . '<small> / ' . View::n($en) . '</small>', 'نود آنلاین از فعال');
            // 2) probe failing
            $pf = isset($ed['probe_failing']) ? (int) $ed['probe_failing'] : null;
            $tiles .= $pf === null ? self::healthTile('muted', 'probe_failing', $na, 'نود ناسالم در بررسی سلامت')
                : self::healthTile($pf > 0 ? 'warn' : 'ok', 'probe_failing', View::n($pf), 'نود ناسالم در بررسی سلامت');
        } else {
            $tiles .= self::healthTile('muted', 'online', $na, 'نود آنلاین از فعال');
        }

        // 3) DNS sync (optional `dns` block, else PowerDNS reachability from `pdns`)
        $tiles .= self::dnsTile($deep);

        // 4) SSL expiring soon (optional `ssl` block)
        if (is_array($deep['ssl'] ?? null)) {
            $ssl = $deep['ssl'];
            $exp = (int) ($ssl['expiring'] ?? 0);
            $expired = (int) ($ssl['expired'] ?? 0);
            $failed = (int) ($ssl['failed'] ?? 0);
            $tone = ($expired > 0 || $failed > 0) ? 'bad' : ($exp > 0 ? 'warn' : 'ok');
            $val = View::n($exp) . ($expired > 0 ? ' <small>(' . View::n($expired) . ' منقضی)</small>' : ($failed > 0 ? ' <small>(' . View::n($failed) . ' ناموفق)</small>' : ''));
            $tiles .= self::healthTile($tone, 'ssl', $val, 'گواهی SSL رو به انقضا');
        } else {
            $tiles .= self::healthTile('muted', 'ssl', $na, 'گواهی SSL رو به انقضا');
        }

        // 5) backup last-success age
        if (is_array($deep['backup'] ?? null)) {
            $b = $deep['backup'];
            $failing = !empty($b['failing']);
            $ageH = isset($b['last_success_age_hours']) ? (float) $b['last_success_age_hours'] : null;
            $enabled = $b['enabled'] ?? true;
            $tone = $failing ? 'bad' : (!$enabled ? 'muted' : ($ageH === null || $ageH > 26 ? 'warn' : 'ok'));
            $val = $ageH === null ? ($enabled ? '<span class="pcdna-muted">—</span>' : 'خاموش') : self::humanAge((int) round($ageH * 3600));
            $tiles .= self::healthTile($tone, 'backup', $val, 'آخرین پشتیبان موفق');
        } else {
            $tiles .= self::healthTile('muted', 'backup', $na, 'آخرین پشتیبان موفق');
        }

        // 6) scheduler
        if (is_array($deep['scheduler'] ?? null)) {
            $s = $deep['scheduler'];
            $role = (string) ($s['role'] ?? '');
            $age = isset($s['last_run_age_seconds']) ? (int) $s['last_run_age_seconds'] : null;
            $roleLabels = ['leader' => 'رهبر', 'follower' => 'پیرو', 'disabled' => 'غیرفعال', 'not-running' => 'متوقف'];
            $stale = $age !== null && $age > 3600;
            $tone = in_array($role, ['not-running'], true) ? 'bad'
                : ($role === 'disabled' ? 'muted' : ($stale ? 'warn' : 'ok'));
            $val = '<span style="font-size:14px">' . View::e($roleLabels[$role] ?? ($role ?: '—')) . '</span>'
                . ($age !== null ? ' <small>' . self::humanAge($age) . '</small>' : '');
            $tiles .= self::healthTile($tone, 'scheduler', $val, 'زمان‌بند (Scheduler)');
        } else {
            $tiles .= self::healthTile('muted', 'scheduler', $na, 'زمان‌بند (Scheduler)');
        }

        // extra (also from /healthz/deep): open alerts + DB migrations
        if (is_array($deep['alerts'] ?? null)) {
            $open = (int) ($deep['alerts']['open'] ?? 0);
            $crit = (int) ($deep['alerts']['critical'] ?? 0);
            $tone = $crit > 0 ? 'bad' : ($open > 0 ? 'warn' : 'ok');
            $val = View::n($open) . ($crit > 0 ? ' <small>(' . View::n($crit) . ' بحرانی)</small>' : '');
            $tiles .= self::healthTile($tone, 'alerts', $val, 'هشدار باز کنترلر');
        }
        if (is_array($deep['database'] ?? null)) {
            $db = $deep['database'];
            $pending = isset($db['revision'], $db['head']) && $db['revision'] !== $db['head'];
            $okDb = !empty($db['ok']);
            $tone = !$okDb ? 'bad' : ($pending ? 'warn' : 'ok');
            $val = '<span style="font-size:14px">' . ($okDb ? ($pending ? 'مهاجرت معلق' : 'سالم') : 'خطا') . '</span>';
            $tiles .= self::healthTile($tone, 'database', $val, 'پایگاه‌داده / مهاجرت‌ها');
        }
        $tiles .= '</div>';

        // controller warnings (operator diagnostics from the controller) in a collapsed, Persian-headed block
        $warnings = array_values(array_filter((array) ($deep['warnings'] ?? []), 'is_string'));
        $wh = '';
        if ($warnings) {
            $items = '';
            foreach ($warnings as $w) {
                $items .= '<li>' . View::icon('warn') . '<span dir="ltr">' . View::e($w) . '</span></li>';
            }
            $wh = '<details class="pcdna-health-warns"><summary>' . View::n(count($warnings)) . ' یادداشت فنی از کنترلر</summary>'
                . '<ul class="pcdna-warnlist">' . $items . '</ul></details>';
        } else {
            $wh = '<p class="pcdna-okline">' . View::icon('check') . '<span>کنترلر هیچ هشدار سلامتی گزارش نکرده است.</span></p>';
        }

        $hint = '<p class="pcdna-muted pcdna-small">این خلاصه از <code dir="ltr">GET /healthz/deep</code> کنترلر خوانده می‌شود (ترجیحاً به‌جای متن Prometheus در <code dir="ltr">/metrics</code>). فیلدهای در دسترس‌نبوده با «نامشخص» نمایش داده می‌شوند.</p>';
        return View::card('سلامت سامانه', $banner . $tiles . $wh . $hint, '', '', 'heart');
    }

    private static function healthTile(string $tone, string $key, string $value, string $label): string
    {
        return '<div class="pcdna-health-tile pcdna-t-' . $tone . '" data-health="' . View::e($key) . '">'
            . '<span class="pcdna-health-n">' . $value . '</span>'
            . '<span class="pcdna-health-l">' . View::e($label) . '</span></div>';
    }

    private static function dnsTile(array $deep): string
    {
        $na = '<span class="pcdna-muted">نامشخص</span>';
        if (is_array($deep['dns'] ?? null)) {
            $d = $deep['dns'];
            $errors = (int) ($d['errors'] ?? 0);
            $ok = array_key_exists('ok', $d) ? !empty($d['ok']) : $errors === 0;
            $age = isset($d['last_sync_age_seconds']) ? (int) $d['last_sync_age_seconds'] : null;
            $stale = $age !== null && $age > 3600;
            $tone = (!$ok || $errors > 0) ? 'bad' : ($stale ? 'warn' : 'ok');
            $val = $age !== null ? self::humanAge($age) : ($ok ? '<span style="font-size:14px">به‌روز</span>' : '<span style="font-size:14px">خطا</span>');
            if ($errors > 0) {
                $val .= ' <small>(' . View::n($errors) . ' خطا)</small>';
            }
            return self::healthTile($tone, 'dns', $val, 'همگام‌سازی DNS');
        }
        // Fall back to PowerDNS reachability if the controller exposes it.
        if (is_array($deep['pdns'] ?? null)) {
            $servers = array_values(array_filter($deep['pdns'], 'is_array'));
            $down = count(array_filter($servers, function ($s) {
                return empty($s['ok']);
            }));
            $tone = $down > 0 ? 'bad' : 'ok';
            $val = $down > 0 ? '<span style="font-size:14px">' . View::n($down) . ' سرور قطع</span>' : '<span style="font-size:14px">در دسترس</span>';
            return self::healthTile($tone, 'dns', $val, 'سرورهای DNS (PowerDNS)');
        }
        return self::healthTile('muted', 'dns', $na, 'همگام‌سازی DNS');
    }

    /** "۳ ساعت پیش" / "۲٫۵ روز پیش" / "لحظاتی پیش" from an age in seconds. */
    private static function humanAge(int $seconds): string
    {
        if ($seconds < 0) {
            $seconds = 0;
        }
        if ($seconds < 120) {
            return 'لحظاتی پیش';
        }
        if ($seconds < 3600) {
            return View::n((int) floor($seconds / 60)) . ' دقیقه پیش';
        }
        if ($seconds < 86400) {
            return View::n($seconds / 3600, 1) . ' ساعت پیش';
        }
        return View::n($seconds / 86400, 1) . ' روز پیش';
    }

    // ------------------------------------------------------------------ 7. settings & diagnostics

    /** @return array list of ['status' => ok|warn|bad, 'title', 'detail', 'fix'] */
    public static function diagnostics(): array
    {
        $c = [];
        $add = function ($status, $title, $detail, $fix = '') use (&$c) {
            $c[] = ['status' => $status, 'title' => $title, 'detail' => $detail, 'fix' => $fix];
        };
        $server = Env::server();
        $add($server ? 'ok' : 'bad', 'سرور CDN تعریف شده', $server ? View::e(($server->name ?: 'Pasargad CDN') . ' (#' . (int) $server->id . ')') . ' — ' . View::ltr(Env::controllerUrl($server)) : 'هیچ سروری با ماژول Pasargad CDN وجود ندارد.',
            'System Settings → Servers → Add New Server: ماژول Pasargad CDN، Hostname کنترلر، Access Hash = ADMIN_API_KEY، تیک Secure. <a href="configservers.php">سرورها</a>');
        $add(function_exists('curl_init') ? 'ok' : 'bad', 'افزونه PHP curl', function_exists('curl_init') ? 'نصب است' : 'نصب نیست', 'افزونه php-curl را روی سرور WHMCS نصب کنید.');
        $ping = self::ping();
        if ($server) {
            $reach = $ping['ok'] || ($ping['code'] > 0);
            $add($reach ? 'ok' : 'bad', 'کنترلر در دسترس است', $reach ? 'زمان پاسخ ' . View::n($ping['ms']) . ' میلی‌ثانیه' : View::e((string) $ping['error']),
                'Hostname و تیک Secure سرور را بررسی کنید؛ از سرور WHMCS دستور curl https://HOST/api/v1/ping را اجرا کنید؛ فایروال کنترلر باید IP سرور WHMCS را بپذیرد.');
            $keyOk = $ping['ok'];
            $add($keyOk ? 'ok' : ($reach ? 'bad' : 'warn'), 'کلید API معتبر است', $keyOk ? 'احراز هویت موفق' : ($reach ? View::e((string) $ping['error']) : 'به دلیل در دسترس نبودن کنترلر بررسی نشد'),
                'Access Hash سرور در WHMCS باید دقیقاً برابر ADMIN_API_KEY فایل .env کنترلر باشد.');
        }
        if ($ping['ok']) {
            $r = self::fetch(['/api/v1/edges']);
            $edges = self::ok($r['/api/v1/edges']) ? (array) $r['/api/v1/edges']['data'] : [];
            $on = count(array_filter($edges, [self::class, 'edgeOnline']));
            $add($on > 0 ? ($on < count(array_filter($edges, function ($e) {
                return !empty($e['enabled']);
            })) ? 'warn' : 'ok') : 'bad', 'نود آنلاین', View::n($on) . ' نود آنلاین از ' . View::n(count($edges)),
                'روی نود: journalctl -u pcdn-agent -f ؛ پورت 80 نود باید باز باشد. <a href="' . View::url(['page' => 'edges']) . '">نودها</a>');
        }
        $products = Data::products();
        $add($products ? 'ok' : 'bad', 'محصولات CDN', $products ? View::n(count($products)) . ' محصول با ماژول Pasargad CDN' : 'محصولی وجود ندارد',
            '<a href="' . View::url(['page' => 'plans']) . '#wizard">راه‌اندازی خودکار محصولات</a>');
        if ($products) {
            $noGroup = array_filter($products, function ($p) {
                return (int) $p->servergroup <= 0;
            });
            $add($noGroup ? 'bad' : 'ok', 'گروه سرور محصولات', $noGroup ? 'بدون گروه سرور: ' . View::e(implode('، ', array_map(function ($p) {
                return $p->name;
            }, $noGroup))) : 'همه محصولات گروه سرور دارند', 'در تب Module Settings محصول، Server Group حاوی سرور CDN را انتخاب کنید.');
            $noDomain = array_filter($products, function ($p) {
                return empty($p->showdomainoptions);
            });
            $add($noDomain ? 'bad' : 'ok', 'نیاز به دامنه در سفارش', $noDomain ? 'بدون «Require Domain»: ' . View::e(implode('، ', array_map(function ($p) {
                return $p->name;
            }, $noDomain))) : 'همه محصولات دامنه را در سفارش می‌گیرند', 'در تب Details محصول تیک Require Domain را بزنید؛ دامنه سرویس همان دامنه روی CDN است.');
            $mode = function_exists('pasargadcdn_billing_mode') ? \pasargadcdn_billing_mode() : 'none';
            $label = Wizard::BILLING[$mode] ?? 'نامشخص';
            $metered = array_filter($products, function ($p) {
                return (int) $p->configoption1 > 0;
            });
            if ($mode === 'prepaid') {
                $noPrice = array_filter($metered, function ($p) {
                    $pp = \pasargadcdn_prepaid((array) $p);
                    return $pp !== null && $pp['price_per_gb'] === null;
                });
                $onOverage = array_filter($metered, function ($p) {
                    return \pasargadcdn_overage((array) $p) !== null;
                });
                $add($noPrice ? 'bad' : ($onOverage ? 'warn' : 'ok'), 'روش صورتحساب: ' . $label,
                    $noPrice ? 'قیمت هر گیگابایت برای این محصولات ثبت نشده و خرید خودکار ممکن نیست: ' . View::e(implode('، ', array_map(function ($p) {
                        return $p->name;
                    }, $noPrice)))
                    : ($onOverage ? 'این محصولات هنوز Overage WHMCS دارند و با فاکتور پایان ماه صورتحساب می‌شوند (نه کیف پول): ' . View::e(implode('، ', array_map(function ($p) {
                        return $p->name;
                    }, $onOverage))) : 'بسته‌های ' . View::n((int) Env::setting('block_gb', '10') ?: 10) . ' گیگابایتی، حداکثر ' . View::n((int) Env::setting('max_blocks', '20')) . ' بسته در ماه برای هر سرویس'),
                    'ویزارد پلن‌ها را با روش «پیش‌پرداخت» و تیک «به‌روزرسانی» اجرا کنید، یا «قیمت هر گیگابایت» را در تنظیمات ماژول وارد کنید.');
                $last = (int) Env::kvGet('prepaid_last_run', 0);
                $add($last > time() - 3600 ? 'ok' : 'bad', 'کران WHMCS (خرید خودکار و وصل مجدد)', $last ? 'آخرین اجرا: ' . View::e(View::date($last, true)) : 'هنوز اجرا نشده است',
                    'کران WHMCS باید هر ۵ دقیقه اجرا شود (crontab: php -q /path/to/crons/cron.php)؛ هوک AfterCronJob بعد از هر اجرا خرید ترافیک، وصل مجدد و ماه جدید را انجام می‌دهد.');
                foreach (self::automationChecks() as $chk) {
                    $add($chk[0], $chk[1], $chk[2], $chk[3]);
                }
            } elseif ($mode === 'overage') {
                $noOverage = array_filter($metered, function ($p) {
                    return \pasargadcdn_overage((array) $p) === null;
                });
                $add($noOverage ? 'warn' : 'ok', 'روش صورتحساب: ' . $label, $noOverage ? 'Overage غیرفعال برای: ' . View::e(implode('، ', array_map(function ($p) {
                    return $p->name;
                }, $noOverage))) . ' (سرویس در پایان ترافیک متوقف می‌شود)' : 'برای محصولات دارای سقف ترافیک تنظیم شده است',
                    'تب Other محصول → Overages Billing، یا ویزارد پلن‌ها با روش «فاکتور پایان ماه». در Automation Settings گزینه Overage Billing را هم فعال کنید.');
            } else {
                $add('ok', 'روش صورتحساب: ' . $label, 'سرویس‌ها در پایان ترافیک پلن تا ماه بعد قطع می‌شوند.', '');
            }
            $upgradeOk = true;
            if (count($products) > 1) {
                if (Env::hasTable('tblproduct_upgrade_products')) {
                    $n = Capsule::table('tblproduct_upgrade_products')->whereIn('product_id', array_map(function ($p) {
                        return (int) $p->id;
                    }, $products))->count();
                    $upgradeOk = $n > 0;
                } else {
                    $upgradeOk = (bool) array_filter($products, function ($p) {
                        return !empty($p->upgradepackages) && $p->upgradepackages !== 'a:0:{}';
                    });
                }
            }
            $add($upgradeOk ? 'ok' : 'warn', 'مسیرهای ارتقا/تنزل', $upgradeOk ? 'تنظیم شده' : 'مشتری نمی‌تواند پلن را از ناحیه کاربری تغییر دهد',
                'تب Upgrades محصول، یا اجرای مجدد ویزارد (مسیرهای جاافتاده را اضافه می‌کند).');
            $noMail = array_filter($products, function ($p) {
                return empty($p->welcomeemail);
            });
            $add($noMail ? 'warn' : 'ok', 'ایمیل خوش‌آمد', $noMail ? 'بدون ایمیل خوش‌آمد: ' . View::e(implode('، ', array_map(function ($p) {
                return $p->name;
            }, $noMail))) : 'تنظیم شده', 'تب Details محصول → Welcome Email: «' . Wizard::EMAIL_NAME . '».');
            // SPEC §16.8: monthly object-storage charges (only shown once a price is set)
            $sp = str_replace(',', '', trim(Env::setting('storage_price', '')));
            if ($sp !== '' && is_numeric($sp) && (float) $sp > 0) {
                $billed = (string) Env::kvGet('storage_billed_month', '');
                $add('ok', 'صورتحساب فضای ذخیره‌سازی', 'هر گیگابایت-ماه ' . View::n((float) $sp, 2) . ' — '
                    . ($mode === 'prepaid' ? 'فاکتور پرداخت از کیف پول' : 'قلم فاکتور بعدی (Billable Item)')
                    . ' — آخرین ماه صورتحساب‌شده: ' . ($billed !== '' ? View::e($billed) : 'هنوز هیچ'),
                    'کران WHMCS یک بار پس از پایان هر ماه (UTC، با دو ساعت تأخیر) مصرف ماه قبل را از کنترلر می‌خواند؛ هر سرویس در هر ماه فقط یک بار (جدول ' . Env::STORAGE_BILLS . ').');
            }
        }
        $hooks = is_file(dirname(__DIR__) . '/hooks.php');
        $active = false;
        try {
            $v = (string) Capsule::table('tblconfiguration')->where('setting', 'ActiveAddonModules')->value('value');
            $active = in_array(Env::MODULE, array_map('trim', explode(',', $v)), true);
        } catch (\Throwable $e) {
            $active = true;
        }
        $add($hooks && $active ? 'ok' : 'bad', 'هوک‌های سفارش فعال است', $hooks ? ($active ? 'hooks.php موجود و ماژول فعال است (بررسی دامنه در سبد خرید، ویجت)' : 'ماژول در فهرست ماژول‌های فعال نیست')
            : 'فایل hooks.php پیدا نشد', 'فایل‌های ماژول را کامل آپلود کنید و در System Settings → Addon Modules ماژول را فعال کنید.');
        $add(Env::kvReady() ? 'ok' : 'warn', 'جدول تنظیمات ماژول', Env::kvReady() ? Env::KV_TABLE . ' موجود است' : 'ساخته نشده (ویزارد نگاشت محصولات را به خاطر نمی‌سپارد)',
            'ماژول را یک بار غیرفعال و دوباره فعال کنید.');
        $pids = Env::cdnProductIds();
        if ($pids) {
            $live = Capsule::table('tblhosting')->whereIn('packageid', $pids)->where('domainstatus', 'Active')->count();
            $last = Capsule::table('tblhosting')->whereIn('packageid', $pids)->where('domainstatus', 'Active')->max('lastupdate');
            $fresh = $last && $last !== '0000-00-00 00:00:00' && strtotime((string) $last) > time() - 2 * 86400;
            $add(!$live ? 'ok' : ($fresh ? 'ok' : 'warn'), 'به‌روزرسانی مصرف (UsageUpdate)', !$live ? 'سرویس فعالی وجود ندارد'
                : ($last && $last !== '0000-00-00 00:00:00' ? 'آخرین اجرا: ' . View::e(View::date($last, true)) : 'هنوز اجرا نشده'),
                'در Automation Settings گزینه «Update Usage Statistics» را روشن کنید؛ کران روزانه WHMCS باید اجرا شود.');
        }
        return $c;
    }

    /**
     * WHMCS automation settings the prepaid flow relies on (read-only; nothing is changed).
     * @return array list of [status, title, detail, fix]
     */
    public static function automationChecks(): array
    {
        $cfg = [];
        try {
            foreach (Capsule::table('tblconfiguration')->whereIn('setting', ['AutoSuspension', 'AutoSuspensionDays', 'AutoUnsuspend',
                'NoAutoApplyCredit', 'AddFundsEnabled'])->get(['setting', 'value']) as $r) {
                $cfg[(string) $r->setting] = (string) $r->value;
            }
        } catch (\Throwable $e) {
            return [];
        }
        $on = function ($k) use ($cfg) {
            return isset($cfg[$k]) ? in_array(strtolower($cfg[$k]), ['on', '1', 'yes', 'true'], true) : null;
        };
        $unk = 'این تنظیم در پایگاه داده پیدا نشد (نسخه WHMCS متفاوت است)؛ دستی بررسی کنید.';
        $out = [];
        $v = $on('AddFundsEnabled');
        $out[] = [$v ? 'ok' : ($v === null ? 'warn' : 'bad'), 'شارژ کیف پول (Add Funds) فعال است', $v ? 'مشتری می‌تواند از clientarea.php?action=addfunds اعتبار بخرد'
            : ($v === null ? $unk : 'غیرفعال است؛ مشتری راهی برای شارژ کیف پول ندارد'), 'System Settings → Payment → Credit: گزینه «Enable Add Funds» را روشن کنید و حداقل/حداکثر شارژ را تعیین کنید.'];
        $v = $on('AutoUnsuspend');
        $out[] = [$v ? 'ok' : ($v === null ? 'warn' : 'bad'), 'رفع تعلیق خودکار پس از پرداخت (AutoUnsuspend)', $v ? 'روشن است' : ($v === null ? $unk : 'خاموش است؛ پس از پرداخت فاکتور تمدید از کیف پول، سرویس معلق وصل نمی‌شود'),
            'Automation Settings → Automatic Suspension: «Enable Unsuspension» را روشن کنید.'];
        $v = $on('AutoSuspension');
        $days = isset($cfg['AutoSuspensionDays']) ? (int) $cfg['AutoSuspensionDays'] : null;
        $out[] = [$v === null ? 'warn' : 'ok', 'تعلیق خودکار سرویس‌های معوق (AutoSuspension)', $v === null ? $unk
            : ($v ? 'روشن — ' . ($days === null ? '' : View::n($days) . ' روز پس از سررسید') : 'خاموش — سرویس‌های تمدیدنشده قطع نمی‌شوند'),
            'برای «قطع با اتمام اعتبار»، تعلیق خودکار را روشن و «Suspend Days» را ۰ (همان روز سررسید) قرار دهید.'];
        if ($v && $days !== null && $days > 0) {
            $c = &$out[count($out) - 1];
            $c[0] = 'warn';
            $c[2] .= ' (پیشنهاد: ۰ تا سرویس تمدیدنشده همان روز قطع و پس از شارژ کیف پول وصل شود)';
            unset($c);
        }
        $v = $on('NoAutoApplyCredit');
        $out[] = [$v === null ? 'warn' : ($v ? 'warn' : 'ok'), 'اعمال خودکار اعتبار روی فاکتورهای جدید', $v === null ? $unk
            : ($v ? 'خاموش است (NoAutoApplyCredit)؛ فاکتورهای تمدید CDN را این ماژول پس از هر شارژ و در کران از اعتبار پرداخت می‌کند، ولی فاکتور سایر محصولات دستی پرداخت می‌شوند'
                : 'روشن است؛ اعتبار موجود هنگام صدور فاکتور تمدید خودکار اعمال می‌شود'),
            'System Settings → Payment → Credit: «Automatically apply any available credit … when generating invoices» را روشن کنید (اختیاری).'];
        return $out;
    }

    // ------------------------------------------------------------------ §10.5 resellers

    public static function resellers(array $get, array $state = []): string
    {
        $usage = Resellers::usageByDomain(); // null when the controller is down
        $list = Resellers::listAll($usage);
        $month = \pasargadcdn_month();

        // KPIs
        $totalSites = 0;
        $totalGb = 0.0;
        $rev = [];
        foreach ($list as $r) {
            $totalSites += (int) $r['sites'];
            $totalGb += (float) $r['gb'];
            foreach ($r['revenue'] as $code => $amt) {
                $rev[$code] = ($rev[$code] ?? 0.0) + $amt;
            }
        }
        $revTxt = [];
        foreach ($rev as $code => $amt) {
            if ($amt > 0) {
                $revTxt[] = View::n($amt, $amt >= 100 ? 0 : 2) . ' <small>' . View::e($code) . '</small>';
            }
        }
        $active = count(array_filter($list, function ($r) {
            return $r['enabled'];
        }));
        $h = '<div class="pcdna-kpis">'
            . View::kpi('users', 'brand', 'نمایندگان فعال', View::n($active), View::n(count($list)) . ' نماینده ثبت‌شده')
            . View::kpi('globe', 'violet', 'زیرسایت‌ها', View::n($totalSites), 'مجموع سایت‌های همه نمایندگان')
            . View::kpi('activity', 'brand', 'مصرف این ماه', $usage === null ? '<span class="pcdna-muted">—</span>' : View::gb($totalGb), $usage === null ? 'کنترلر در دسترس نیست' : 'مجموع زیرسایت‌ها')
            . View::kpi('wallet', 'ok', 'درآمد عمده این ماه', $revTxt ? implode('<br>', $revTxt) : '<span class="pcdna-muted">۰</span>', 'خرید ترافیک پرداخت‌شده نمایندگان')
            . '</div>';
        if ($usage === null) {
            $h .= View::alert('warn', 'ارتباط با کنترلر برای مصرف لحظه‌ای برقرار نشد؛ بقیه اطلاعات از داده محلی نمایش داده می‌شود.');
        }

        // global settings
        $gform = '<form method="post" action="' . View::url(['page' => 'resellers']) . '" class="pcdna-form pcdna-form-inline">' . View::csrf()
            . '<input type="hidden" name="a" value="reseller_settings">'
            . '<label class="pcdna-inline-label"><span>قیمت عمده هر گیگابایت (پیش‌فرض)</span>'
            . '<input class="pcdna-input" name="reseller_rate" dir="ltr" inputmode="decimal" value="' . View::e(Resellers::globalRate()) . '" placeholder="مثلاً 2000"></label>'
            . '<label class="pcdna-inline-label"><span>حداکثر زیرسایت هر نماینده (۰ = نامحدود)</span>'
            . '<input class="pcdna-input" name="reseller_max_sites" dir="ltr" inputmode="numeric" value="' . View::e(Resellers::globalMaxSites()) . '"></label>'
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">ذخیره</button></form>'
            . '<p class="pcdna-muted pcdna-small">این مقادیر پیش‌فرض همه نمایندگان است و برای هر نماینده در جدول زیر قابل بازنویسی است. قیمت به ارز پیش‌فرض WHMCS.</p>';
        $h .= View::card('تنظیمات سراسری نمایندگی', $gform, '', '', 'settings');

        // add / flag a reseller
        $aform = '<form method="post" action="' . View::url(['page' => 'resellers']) . '" class="pcdna-form pcdna-form-inline">' . View::csrf()
            . '<input type="hidden" name="a" value="reseller_flag">'
            . '<label class="pcdna-inline-label"><span>مشتری (شناسه، ایمیل یا نام)</span>'
            . '<input class="pcdna-input" name="client" value="" placeholder="#123 یا user@example.com"></label>'
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('check') . '<span>ثبت به‌عنوان نماینده</span></button></form>';
        $h .= View::card('افزودن نماینده', $aform, '', '', 'users');

        // list
        if (!$list) {
            $h .= View::card('نمایندگان', View::emptyState('هنوز نماینده‌ای ثبت نشده است',
                'با فرم بالا یک مشتری را به‌عنوان نماینده فعال کنید. نماینده در پنل مشتری خود بخش «نمایندگی» را می‌بیند.', 'users'));
            return $h . self::resellerPurchases($month);
        }
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table"><thead><tr><th>مشتری</th><th>وضعیت</th><th>زیرسایت</th>'
            . '<th>مصرف ماه (GB)</th><th>درآمد ماه</th><th>تنظیمات</th></tr></thead><tbody>';
        foreach ($list as $r) {
            $uid = (int) $r['userid'];
            $revCell = [];
            foreach ($r['revenue'] as $code => $amt) {
                if ($amt > 0) {
                    $revCell[] = View::n($amt, $amt >= 100 ? 0 : 2) . ' <small>' . View::e($code) . '</small>';
                }
            }
            $form = '<details class="pcdna-menu"><summary class="pcdna-btn pcdna-btn-sm">' . View::icon('sliders') . '<span>ویرایش</span></summary>'
                . '<div class="pcdna-menu-list"><form method="post" action="' . View::url(['page' => 'resellers']) . '" class="pcdna-form">' . View::csrf()
                . '<input type="hidden" name="a" value="reseller_save"><input type="hidden" name="userid" value="' . $uid . '">'
                . '<label><span>قیمت هر گیگابایت (خالی = سراسری)</span><input class="pcdna-input" name="rate" dir="ltr" inputmode="decimal" value="'
                . ($r['rate'] !== null ? View::e(rtrim(rtrim(sprintf('%.9f', $r['rate']), '0'), '.')) : '') . '"></label>'
                . '<label><span>حداکثر زیرسایت (۰ = پیش‌فرض)</span><input class="pcdna-input" name="max_sites" dir="ltr" inputmode="numeric" value="' . (int) $r['max_sites'] . '"></label>'
                . '<label><span>وضعیت</span>' . View::select('enabled', ['1' => 'فعال', '0' => 'غیرفعال'], $r['enabled'] ? '1' : '0') . '</label>'
                . '<label><span>یادداشت</span><input class="pcdna-input" name="note" value="' . View::e($r['note']) . '" maxlength="191"></label>'
                . '<button type="submit" class="pcdna-btn pcdna-btn-sm pcdna-btn-primary">' . View::icon('check') . '<span>ذخیره</span></button></form></div></details>';
            $t .= '<tr><td><a href="' . View::e(Data::clientUrl($uid)) . '">' . View::e($r['name']) . '</a>'
                . '<div class="pcdna-small pcdna-muted">' . View::ltr($r['email'] ?: ('#' . $uid)) . '</div></td>'
                . '<td>' . ($r['enabled'] ? View::badge('فعال', 'ok') : View::badge('غیرفعال', 'muted')) . '</td>'
                . '<td class="pcdna-num">' . View::n($r['sites']) . ($r['suspended_sites'] > 0 ? '<div class="pcdna-small pcdna-c-bad">' . View::n($r['suspended_sites']) . ' قطع</div>' : '') . '</td>'
                . '<td class="pcdna-num">' . ($usage === null ? '<span class="pcdna-muted">—</span>' : View::n($r['gb'], 2)) . '</td>'
                . '<td class="pcdna-num">' . ($revCell ? implode('<br>', $revCell) : '<span class="pcdna-muted">۰</span>') . '</td>'
                . '<td class="pcdna-actions">' . $form . '</td></tr>';
        }
        $t .= '</tbody></table></div>';
        $h .= View::card('نمایندگان (' . View::n(count($list)) . ')', $t, '', 'pcdna-flush', 'users');
        return $h . self::resellerPurchases($month);
    }

    /** Wholesale traffic purchases of the resellers in $month. */
    public static function resellerPurchases(string $month): string
    {
        $list = Resellers::topups($month, 200);
        if (!$list) {
            return View::card('خریدهای ترافیک نمایندگان', View::emptyState('در این ماه خرید ترافیکی از کیف پول نمایندگان ثبت نشده است', '', 'wallet'), '', '', 'wallet');
        }
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table"><thead><tr><th>زمان</th><th>نماینده</th><th>حجم</th><th>مبلغ</th><th>فاکتور</th><th>وضعیت</th></tr></thead><tbody>';
        foreach ($list as $x) {
            [$st, $tone] = self::TOPUP_STATUS[$x->status] ?? [$x->status, 'muted'];
            $t .= '<tr><td class="pcdna-nowrap">' . View::e(View::date($x->created_at, true)) . '</td>'
                . '<td><a href="' . View::e(Data::clientUrl((int) $x->userid)) . '">' . View::e(Data::clientName($x)) . '</a></td>'
                . '<td class="pcdna-num">' . View::n($x->gb) . ' GB' . ((int) $x->blocks > 1 ? '<div class="pcdna-small pcdna-muted">' . View::n($x->blocks) . ' بسته</div>' : '') . '</td>'
                . '<td class="pcdna-num">' . View::n($x->amount, (float) $x->amount >= 100 ? 0 : 2) . ' <small>' . View::e($x->currency_code) . '</small></td>'
                . '<td>' . ($x->invoice_id ? '<a href="invoices.php?action=edit&amp;id=' . (int) $x->invoice_id . '">#' . View::n($x->invoice_id) . '</a>' : '—') . '</td>'
                . '<td>' . View::badge($st, $tone) . '</td></tr>';
        }
        $t .= '</tbody></table></div>';
        return View::card('خریدهای ترافیک نمایندگان (' . View::n(count($list)) . ')', $t, '', 'pcdna-flush', 'wallet');
    }

    public static function settings(): string
    {
        $servers = [0 => 'خودکار: اولین سرور فعال Pasargad CDN'];
        foreach (Env::servers() as $s) {
            $servers[(int) $s->id] = ($s->name ?: 'Pasargad CDN') . ' (#' . (int) $s->id . ') — ' . preg_replace('#^https?://#', '', Env::controllerUrl($s)) . (!empty($s->disabled) ? ' — غیرفعال' : '');
        }
        $form = '<form method="post" action="' . View::url(['page' => 'settings']) . '" class="pcdna-form pcdna-form-inline">' . View::csrf()
            . '<input type="hidden" name="a" value="save_server"><label class="pcdna-inline-label"><span>سرور کنترلر برای این پنل</span>'
            . View::select('server', $servers, (int) Env::setting('server', '0')) . '</label>'
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">ذخیره</button></form>'
            . '<p class="pcdna-muted pcdna-small">سایت‌های هر سرویس همیشه روی سرور خود آن سرویس مدیریت می‌شوند؛ این انتخاب برای داشبورد، نودها، رویدادها، گزارش مصرف، ویجت و بررسی سبد خرید است. '
            . 'سایر تنظیمات (ویجت، بررسی کنترلر هنگام پرداخت، دامنه‌های رزرو) در System Settings → Addon Modules هستند.</p>';
        $h = View::card('انتخاب سرور', $form, '', '', 'server');
        $list = '<ul class="pcdna-diag">';
        foreach (self::diagnostics() as $d) {
            $icon = ['ok' => 'check', 'warn' => 'warn', 'bad' => 'x'][$d['status']];
            $list .= '<li class="pcdna-d-' . $d['status'] . '" data-status="' . $d['status'] . '"><span class="pcdna-d-icon">' . View::icon($icon) . '</span><div><strong>' . View::e($d['title'])
                . '</strong><p>' . $d['detail'] . '</p>' . ($d['status'] !== 'ok' && $d['fix'] !== '' ? '<p class="pcdna-fix">' . View::icon('info') . '<span>' . $d['fix'] . '</span></p>' : '')
                . '</div></li>';
        }
        $list .= '</ul>';
        $h .= View::card('بررسی سلامت', $list, View::postButton(['page' => 'settings'], 'clear_cache', [], 'بازخوانی ویجت', 'pcdna-btn pcdna-btn-sm', '', 'refresh'), '', 'check');
        $h .= self::notifySettings();
        return $h;
    }

    /**
     * SPEC §23.5 / §23.8 / §23.10 (wave 14): customer alert channels the controller can send (GET /api/v1/notifications/status —
     * provider names and bot usernames only, never keys), the e-mail outbox cron, the support department of diagnostics tickets
     * and the public abuse page.
     */
    public static function notifySettings(): string
    {
        $ping = self::ping();
        $st = null;
        $code = 0;
        if ($ping['ok']) {
            $r = self::fetch(['/api/v1/notifications/status']);
            $code = (int) ($r['/api/v1/notifications/status']['code'] ?? 0);
            $st = self::ok($r['/api/v1/notifications/status']) ? $r['/api/v1/notifications/status']['data'] : null;
        }
        $on = function ($v) {
            return $v ? View::badge('پیکربندی شده', 'ok') : View::badge('خاموش', 'muted');
        };
        if ($st !== null) {
            $sms = is_array($st['sms'] ?? null) ? $st['sms'] : [];
            $dl = '<dl class="pcdna-dl pcdna-dl-cols" data-notify-status="1">'
                . '<div><dt>ایمیل</dt><dd>' . View::badge('با کران WHMCS', 'ok') . '</dd></div>'
                . '<div><dt>پیامک</dt><dd>' . $on(!empty($sms['configured'])) . (!empty($sms['provider']) ? ' ' . View::ltr((string) $sms['provider']) : '') . '</dd></div>';
            foreach (['bale' => 'بله', 'telegram' => 'تلگرام'] as $k => $label) {
                $x = is_array($st[$k] ?? null) ? $st[$k] : [];
                $dl .= '<div><dt>' . $label . '</dt><dd>' . $on(!empty($x['configured'])) . (!empty($x['username']) ? ' ' . View::ltr('@' . ltrim((string) $x['username'], '@')) : '') . '</dd></div>';
            }
            $dl .= '</dl>';
        } else {
            $dl = View::alert('info', $code === 404 ? 'کنترلر فعلی هشدارهای مشتری (پیامک، بله، تلگرام) را پشتیبانی نمی‌کند.' : 'وضعیت کانال‌های هشدار در دسترس نیست.');
        }
        $last = Env::kvGet('alertmail_last');
        $dept = (int) Env::setting('support_department', '0');
        $dl .= '<ul class="pcdna-bullets"><li>ایمیل هشدارها با کران WHMCS از صف کنترلر خوانده و با قالب «Pasargad CDN Alert» فرستاده می‌شود'
            . (Env::enabled('alert_email', true) ? '' : ' — <strong>خاموش (تنظیم «ایمیل هشدارهای مشتری»)</strong>')
            . (is_array($last) && !empty($last['at']) ? ' (آخرین اجرا: ' . View::e(View::ago(gmdate('Y-m-d\TH:i:s\Z', (int) $last['at']))) . '، ' . View::n((int) ($last['sent'] ?? 0)) . ' ارسال)' : '') . '.</li>'
            . '<li>بخش پشتیبانی تیکت‌های «گزارش عیب‌یابی»: ' . ($dept > 0 ? '#' . View::n($dept) : 'اولین بخش') . ' (تنظیم «بخش پشتیبانی گزارش عیب‌یابی»).</li>'
            . '<li>صفحهٔ عمومی «گزارش تخلف»: ' . (Env::enabled('abuse_page', false) ? '<a href="../index.php?m=pasargadcdn_admin&amp;page=abuse" target="_blank" rel="noopener">روشن</a>' : 'خاموش') . '.</li></ul>';
        return View::card('هشدارهای مشتری، پشتیبانی و گزارش تخلف', $dl, '', '', 'mail');
    }

    // ------------------------------------------------------------------ «مدیریت کامل» (admin mode of the client app)

    public static function manage(int $sid): string
    {
        $svc = $sid > 0 ? Data::serviceQuery()->where('h.id', $sid)->first(array_merge(Data::SERVICE_COLS, ['p.id as pid'])) : null;
        if (!$svc) {
            return View::alert('bad', 'سرویس CDN با این شناسه پیدا نشد.') . '<p><a href="' . View::url(['page' => 'sites']) . '">بازگشت به فهرست سایت‌ها</a></p>';
        }
        $domain = Env::domain((string) $svc->domain);
        $boot = ['serviceId' => $sid, 'domain' => $domain, 'active' => true, 'site' => null, 'error' => null,
            'admin' => [
                'serviceUrl' => Data::serviceUrl((int) $svc->userid, $sid),
                'clientUrl' => Data::clientUrl((int) $svc->userid),
                'backUrl' => View::url(['page' => 'sites'], false),
                'client' => Data::clientName($svc),
                'status' => (string) $svc->domainstatus,
            ]];
        $server = Capsule::table('tblservers')->where('id', (int) $svc->server)->first();
        if (!$server || $server->type !== 'pasargadcdn') {
            $boot['error'] = 'سرور CDN برای این سرویس تنظیم نشده است (فیلد Server سرویس در WHMCS).';
        } elseif (!Env::validHostname($domain)) {
            $boot['error'] = 'دامنه این سرویس معتبر نیست.';
        } else {
            try {
                $boot['site'] = Env::api(10, $server)->get(ApiClient::site($domain));
            } catch (\Throwable $e) {
                $boot['error'] = $e->getMessage();
                if ($e instanceof ApiException && $e->getCode() === 404) {
                    $boot['error'] = 'سایت این سرویس روی کنترلر وجود ندارد. از منوی سایت‌ها «ساخت روی CDN» را اجرا کنید.';
                }
            }
        }
        $boot['billing'] = function_exists('pasargadcdn_billing') ? \pasargadcdn_billing(['pid' => (int) $svc->pid,
            'clientsdetails' => ['currency' => (int) ($svc->currency ?? 0)]]) : null;
        $boot['wallet'] = function_exists('pasargadcdn_wallet') ? \pasargadcdn_wallet(['pid' => (int) $svc->pid, 'userid' => (int) $svc->userid,
            'serviceid' => $sid]) : null;
        $base = '../modules/servers/pasargadcdn';
        $assets = function_exists('pasargadcdn_assets') ? \pasargadcdn_assets($base) : ['css' => $base . '/assets/app.css', 'scripts' => []];
        $api = View::url(['page' => 'api', 'service' => $sid] + (Env::whmcsToken() !== '' ? ['token' => Env::whmcsToken()] : []), false);
        $h = '<div class="pcdna-manage-head"><a class="pcdna-btn pcdna-btn-sm" href="' . View::url(['page' => 'sites']) . '">→ سایت‌ها</a>'
            . '<h3>مدیریت کامل ' . View::ltr($domain) . '</h3><span class="pcdna-muted">سرویس #' . View::n($sid) . ' · ' . View::e(Data::clientName($svc)) . ' · '
            . self::whmcsBadge((string) $svc->domainstatus) . '</span></div>';
        $h .= '<link rel="stylesheet" href="' . View::e($assets['css']) . '">'
            . '<div id="pcdn-app" class="pcdn" dir="rtl" lang="fa" data-api="' . View::e($api) . '" data-csrf="' . View::e(Env::csrf()) . '" data-admin="1">'
            . '<noscript><div class="pcdn-alert pcdn-alert-danger">برای مدیریت CDN، جاوااسکریپت مرورگر را فعال کنید.</div></noscript>'
            . '<div class="pcdn-boot-loading" role="status">در حال بارگذاری پنل CDN…</div></div>'
            . '<script type="application/json" id="pcdn-boot">' . (function_exists('pasargadcdn_boot_json') ? \pasargadcdn_boot_json($boot) : '{}') . '</script>';
        foreach ($assets['scripts'] as $s) {
            $h .= '<script src="' . View::e($s) . '" defer></script>';
        }
        return $h;
    }
}
