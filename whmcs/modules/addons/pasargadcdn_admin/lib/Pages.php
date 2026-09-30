<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use WHMCS\Database\Capsule;

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
        'edges' => ['نودها', 'server'],
        'plans' => ['پلن‌ها و قیمت‌گذاری', 'tag'],
        'analytics' => ['آنالیتیکس', 'chart'],
        'usage' => ['گزارش مصرف', 'wallet'],
        'events' => ['رویدادهای امنیتی', 'shield'],
        'status' => ['وضعیت و رخدادها', 'activity'],
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
            $cur = $id === $page || ($page === 'manage' && $id === 'sites');
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

    private static function ok(array $r): bool
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

    private static function whmcsBadge(string $s): string
    {
        [$t, $tone] = self::WHMCS_STATUS[$s] ?? [$s, 'muted'];
        return View::badge($t, $tone);
    }

    private static function cdnBadge(?string $s): string
    {
        if ($s === null) {
            return View::badge('روی CDN نیست', 'bad-soft');
        }
        [$t, $tone] = self::CDN_STATUS[$s] ?? [$s, 'muted'];
        return View::badge($t, $tone);
    }

    private static function manageUrl(int $sid): string
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
        if ($ping['ok']) {
            $r = self::fetch(['/api/v1/overview', '/api/v1/edges', '/api/v1/events?limit=8', '/api/v1/sites', '/api/v1/alerts/status']);
            $ov = self::ok($r['/api/v1/overview']) ? $r['/api/v1/overview']['data'] : null;
            $edges = self::ok($r['/api/v1/edges']) ? $r['/api/v1/edges']['data'] : null;
            $events = self::ok($r['/api/v1/events?limit=8']) ? $r['/api/v1/events?limit=8']['data'] : null;
            $sites = self::ok($r['/api/v1/sites']) ? $r['/api/v1/sites']['data'] : null;
            $alerts = self::ok($r['/api/v1/alerts/status']) ? $r['/api/v1/alerts/status']['data'] : null;
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
        $h .= View::kpi('globe', 'brand', 'سایت‌های روی CDN', $ov ? View::n($ov['sites']['total'] ?? 0) : $na,
            $ov ? View::n($by['active'] ?? 0) . ' فعال · ' . View::n($by['pending_ns'] ?? 0) . ' در انتظار NS · '
                . View::n(($by['suspended'] ?? 0) + ($by['over_quota'] ?? 0)) . ' متوقف' : 'داده کنترلر در دسترس نیست');
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

        // top sites + latest events
        $byDomain = Data::servicesByDomain();
        $top = '';
        if ($ov && !empty($ov['top_sites'])) {
            $top .= '<div class="pcdna-table-wrap"><table class="pcdna-table"><thead><tr><th>دامنه</th><th>ترافیک</th><th>درخواست</th><th></th></tr></thead><tbody>';
            $max = max(1, (float) ($ov['top_sites'][0]['bytes'] ?? 1));
            foreach (array_slice($ov['top_sites'], 0, 10) as $s) {
                $svc = $byDomain[strtolower((string) ($s['domain'] ?? ''))] ?? null;
                $top .= '<tr><td>' . View::ltr($s['domain'] ?? '?') . '</td><td class="pcdna-num">' . View::bytes($s['bytes'] ?? 0)
                    . View::meter((float) ($s['bytes'] ?? 0) / $max, 'brand') . '</td><td class="pcdna-num">' . View::n($s['requests'] ?? 0) . '</td><td class="pcdna-actions">'
                    . ($svc ? '<a class="pcdna-btn pcdna-btn-sm" href="' . self::manageUrl((int) $svc->id) . '">مدیریت</a>'
                        . '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::e(Data::serviceUrl((int) $svc->userid, (int) $svc->id))
                        . '" title="صفحه سرویس در WHMCS">#' . (int) $svc->id . '</a>' : View::badge('بدون سرویس', 'muted'))
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

    /**
     * @param array $edges edge objects
     * @param bool $actions render the per-row action menu
     * @param array|null $series map of edge id => daily uptime rows for the inline sparkline
     */
    private static function edgeTable(array $edges, bool $actions, ?array $series = null): string
    {
        if (!$edges) {
            return View::emptyState('هنوز نودی ثبت نشده است', 'برای شروع، از صفحه «نودها» اولین نود را اضافه کنید.', 'server');
        }
        $h = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-edges"><thead><tr><th>نام / IP</th><th>منطقه / گروه</th><th>وضعیت</th>'
            . '<th>بار لحظه‌ای</th><th>در دسترس‌بودن</th><th>آخرین ارتباط</th>' . ($actions ? '<th><span class="pcdna-sr">عملیات</span></th>' : '') . '</tr></thead><tbody>';
        foreach ($edges as $e) {
            $online = self::edgeOnline($e);
            $fresh = !empty($e['enabled']) && empty($e['last_seen_at']);
            $status = empty($e['enabled']) ? View::badge('غیرفعال', 'muted') : ($online ? View::badge('آنلاین', 'ok')
                : ($fresh ? View::badge('در انتظار نصب', 'warn', ' title="agent هنوز به کنترلر وصل نشده است"') : View::badge('آفلاین', 'bad')));
            $err = trim((string) ($e['last_error'] ?? ''));
            [$gl, $gt] = self::EDGE_GROUPS[$e['group'] ?? 'general'] ?? [(string) ($e['group'] ?? ''), 'muted'];
            $id = (int) ($e['id'] ?? 0);
            $h .= '<tr data-edge="' . $id . '"' . (!empty($e['enabled']) && !$online && !$fresh ? ' class="is-bad"' : '') . ($err !== '' ? ' data-has-error="1"' : '')
                . (!empty($e['shed']) ? ' data-shed="1"' : '') . '><td><strong>' . View::ltr($e['name'] ?? '') . '</strong>'
                . '<div class="pcdna-small pcdna-muted">' . View::ltr($e['ipv4'] ?? '') . (!empty($e['ipv6']) ? '<br>' . View::ltr($e['ipv6']) : '') . '</div></td>'
                . '<td><span class="pcdna-badges">' . (($e['region'] ?? '') === 'home' ? View::badge('ایران', 'brand') : View::badge('خارج', 'violet'))
                . View::badge($gl, $gt === 'violet' ? 'violet' : 'muted', ' data-group="' . View::e($e['group'] ?? 'general') . '"') . '</span></td>'
                . '<td>' . $status . self::edgeWarnBadges($e) . '</td><td class="pcdna-load-cell">' . self::loadCell($e) . '</td>'
                . '<td class="pcdna-uptime-cell">' . self::uptimeCell($e, $series[$id] ?? null) . '</td>'
                . '<td title="' . View::e($e['last_seen_at'] ?? '') . '">' . View::e(View::ago($e['last_seen_at'] ?? null))
                . (!empty($e['applied_version']) ? '<div class="pcdna-small pcdna-muted" title="نسخه تنظیمات اعمال‌شده">' . View::ltr(substr((string) $e['applied_version'], 0, 8), 'pcdna-code') . '</div>' : '') . '</td>';
            if ($actions) {
                $q = ['page' => 'edges'];
                $h .= '<td class="pcdna-actions">'
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
                $h .= '<tr class="pcdna-errrow"><td colspan="' . ($actions ? 7 : 6) . '"><span class="pcdna-err-label">' . View::icon('warn') . 'آخرین خطا:</span> '
                    . '<code dir="ltr" title="' . View::e(View::clip($err, 600)) . '">' . View::e(View::clip($err, 300)) . '</code></td></tr>';
            }
        }
        return $h . '</tbody></table></div>';
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
        foreach (self::groupTotals($edges) as $g => $t) {
            [$label] = self::EDGE_GROUPS[$g];
            $peak = max($t['rx'], $t['tx']);
            $h .= '<div class="pcdna-group" data-group-card="' . $g . '"><div class="pcdna-group-head">' . View::badge('گروه ' . $label, $g === 'tunnel' ? 'violet' : 'muted')
                . '<span class="pcdna-small pcdna-muted">' . View::n($t['online']) . ' آنلاین از ' . View::n($t['edges']) . ' نود فعال'
                . ($t['shed'] ? ' · <span class="pcdna-c-bad">' . View::n($t['shed']) . ' خارج از DNS</span>' : '') . '</span></div>'
                . '<div class="pcdna-group-val"><span dir="ltr">↓' . View::e(self::mbps($t['rx'])) . ' ↑' . View::e(self::mbps($t['tx'])) . '</span>'
                . ($t['cap'] > 0 ? '<small>از ظرفیت ' . View::e(self::mbps($t['cap'])) . '</small>' : '') . '</div>'
                . ($t['cap'] > 0 ? View::meter(min(1, $peak / $t['cap']), $peak / $t['cap'] > .8 ? 'warn' : 'brand') : '')
                . '<div class="pcdna-small pcdna-muted">' . View::n($t['conns']) . ' اتصال همزمان</div></div>';
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
            $r = self::fetch([$up]);
            $usage = self::ok($r[$up]) ? (array) ($r[$up]['data']['sites'] ?? []) : null;
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
                . ($suggest !== '' ? '<div class="pcdna-tn-line">' . $suggest . '</div>' : '') . '</td>'
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
        return $h;
    }

    // ------------------------------------------------------------------ 3. edges

    public static function edges(?array $newToken = null, array $old = [], array $get = []): string
    {
        if (($get['view'] ?? '') === 'availability') {
            return self::availability();
        }
        $ping = self::ping();
        $h = '';
        $ctlUrl = Env::controllerUrl();
        if ($newToken) {
            $cmd = 'sudo ./install.sh --controller ' . $ctlUrl . ' --token ' . $newToken['token'];
            $h .= '<section class="pcdna-card pcdna-token" data-token-panel="1"><header class="pcdna-card-head"><h3>' . View::icon('key') . '<span>'
                . View::e($newToken['title']) . '</span></h3></header><div class="pcdna-card-body">'
                . View::alert('warn', '<strong>این توکن فقط همین یک بار نمایش داده می‌شود</strong> و جایی ذخیره یا ثبت نمی‌شود. همین حالا آن را کپی کنید.')
                . '<p class="pcdna-label">توکن نود ' . View::ltr($newToken['name']) . '</p>' . View::copyable($newToken['token'], 'کپی توکن')
                . '<p class="pcdna-label">دستور نصب روی سرور نود (در پوشه <code dir="ltr">edge</code> مخزن پروژه):</p>' . View::copyable($cmd, 'کپی دستور')
                . '<p class="pcdna-muted">پس از اجرای دستور، حداکثر یک دقیقه بعد نود «آنلاین» می‌شود و در پاسخ DNS سایت‌ها قرار می‌گیرد.</p></div></section>';
        }
        if (!$ping['ok']) {
            return $h . self::ctlError($ping);
        }
        $r = self::fetch(['/api/v1/edges']);
        $edges = self::ok($r['/api/v1/edges']) ? (array) $r['/api/v1/edges']['data'] : null;
        $online = 0;
        foreach ((array) $edges as $e) {
            $online += self::edgeOnline($e) ? 1 : 0;
        }
        $series = $edges !== null ? self::uptimeSeries($edges) : null;
        if ($edges !== null) {
            foreach (self::saturated($edges) as $e) {
                $h .= View::alert(!empty($e['shed']) ? 'bad' : 'warn', 'نود ' . View::ltr($e['name'] ?? '') . (!empty($e['shed'])
                    ? ' اشباع شده و موقتاً از پاسخ DNS خارج است؛ ترافیک به نودهای دیگر همان گروه می‌رود. ظرفیت اضافه کنید یا نود جدید به این گروه بیاورید.'
                    : ' بیش از ۸۰٪ ظرفیت خود بار دارد.'));
            }
            $h .= View::card('گروه‌های نود', self::groupCards($edges), '', '', 'activity');
        }
        $h .= View::card('نودهای CDN' . ($edges !== null ? ' (' . View::n($online) . ' آنلاین از ' . View::n(count($edges)) . ')' : ''),
            $edges === null ? View::alert('bad', 'فهرست نودها دریافت نشد: ' . View::e((string) $r['/api/v1/edges']['error'])) : self::edgeTable($edges, true, $series),
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
        return $h;
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
            $h .= self::productCards($products, $pricing, $currencies);
        } else {
            $h .= View::alert('info', 'هنوز محصولی با ماژول Pasargad CDN وجود ندارد. با فرم زیر چهار پلن سایت (پایه، حرفه‌ای، تجاری، سازمانی) و سه پلن تونل / VPN (تونل پایه، حرفه‌ای، نامحدود) را با قیمت، ایمیل خوش‌آمد، فیلد Origin IP و مسیر ارتقا بسازید.');
        }
        $h .= self::wizardForm($state['input'] ?? Wizard::defaults($currencies), $currencies, (array) ($state['errors'] ?? []), !$products || !empty($state['errors']));
        return $h;
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
            . '<span>راه‌اندازی خودکار محصولات</span></h3><span class="pcdna-muted pcdna-small">گروه، ۴ پلن سایت + ۳ پلن تونل، قیمت‌ها، ایمیل خوش‌آمد، فیلد Origin IP و مسیر ارتقا — قابل اجرای مجدد</span></summary><div class="pcdna-card-body">';
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
            . '</div></fieldset>';

        // feature matrix, one table per plan family (site plans, tunnel plans)
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
            $fields = $fam === 'tunnel'
                ? ['bw', 'tunnel', 'tpaths', 'tconn', 'tmbps', 'group', 'records', 'ssl', 'lb', 'pools', 'fw', 'rate', 'waf', 'ddos', 'image', 'customssl', 'dnssec', 'page', 'rl']
                : ['bw', 'records', 'ssl', 'rate', 'waf', 'ddos', 'lb', 'image', 'customssl', 'dnssec', 'page', 'fw', 'rl', 'pools', 'tunnel', 'tpaths', 'tconn', 'tmbps', 'group'];
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
                    $h .= '<td>' . (isset(Wizard::FLAGS[$f])
                            ? '<label class="pcdna-switch"><input type="checkbox" name="' . $nm . '" value="1"' . ($v ? ' checked' : '') . $aria . '><span></span></label>'
                            : '<input class="pcdna-input pcdna-input-num" name="' . $nm . '" dir="ltr" inputmode="numeric" value="' . (int) $v . '"' . $aria . '>') . '</td>';
                }
                $h .= '</tr>';
            }
            $h .= '</tbody></table></div>';
        }
        $h .= '<p class="pcdna-muted pcdna-small">ترافیک ۰ یعنی نامحدود. استخر توزیع بار فقط وقتی «توزیع بار» روشن باشد اعمال می‌شود. '
            . 'پلن‌های تونل برای Xray / V2Ray پشت CDN هستند (ترافیک آپلود و دانلود هر دو حساب می‌شود) و با «گروه نودها = تونل» فقط به نودهای گروه تونل (صفحه «نودها») هدایت می‌شوند؛ '
            . 'اگر نود آنلاینی در آن گروه نباشد، همه نودها پاسخ می‌دهند. «اتصال همزمان هر نود» ۰ یعنی نامحدود (هر جریان WebSocket/gRPC یک اتصال است). '
            . '«سقف سرعت اتصال» ۰ یعنی بدون سقف و فعلاً روی جریان‌های تونل اعمال نمی‌شود. مسیر ارتقا فقط بین پلن‌های هم‌خانواده ساخته می‌شود. '
            . 'این مقادیر در Module Settings محصول (configoption1..19) ذخیره می‌شوند و با ChangePackage روی سرویس‌های موجود اعمال می‌شوند.</p></fieldset>';

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

    private static function check(string $name, bool $on, string $label): string
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
        $r = self::fetch([$path])[$path];
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
            . '<th>مصرف (GB)</th><th>پلن + خرید (GB)</th><th>مازاد (GB)</th><th>مبلغ</th></tr></thead><tbody>';
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
                . '<td class="pcdna-num">' . $amountCell . '</td></tr>';
        }
        $t .= '</tbody><tfoot><tr><th colspan="2">جمع</th><th class="pcdna-num">' . View::n($tot['used'], 2) . '</th><th class="pcdna-num">'
            . ($tot['bought_gb'] > 0 ? '<span class="pcdna-bought">+ ' . View::n($tot['bought_gb']) . '</span>' : '') . '</th><th class="pcdna-num">'
            . View::n($tot['over'], 2) . '</th><th class="pcdna-num">' . (($bought || $amounts) ? implode('<br>', array_merge($bought, $amounts)) : '—') . '</th></tr></tfoot></table></div>';
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
            'خرید پیش‌پرداخت (GB)', 'مبلغ خرید پیش‌پرداخت', 'فاکتورهای خرید'], ',', '"', '\\');
        foreach ($rows as $r) {
            fputcsv($fh, [$r['service'] ?: '', self::csvSafe($r['client']), $r['domain'], self::csvSafe($r['product']), $r['status'],
                number_format($r['used'], 3, '.', ''), $r['limit'] > 0 ? number_format($r['limit'], 3, '.', '') : '',
                number_format($r['over'], 3, '.', ''), $r['amount'] === null ? '' : number_format($r['amount'], 2, '.', ''),
                $r['currency'], $r['requests'], $r['bought_gb'] ?: '', $r['bought'] > 0 ? number_format($r['bought'], 2, '.', '') : '',
                implode(' ', $r['invoices'])], ',', '"', '\\');
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
        return $h;
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
