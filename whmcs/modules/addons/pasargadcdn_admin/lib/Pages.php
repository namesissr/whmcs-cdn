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
        'usage' => ['گزارش مصرف', 'chart'],
        'events' => ['رویدادهای امنیتی', 'shield'],
        'settings' => ['تنظیمات و سلامت', 'settings'],
    ];

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

    // ------------------------------------------------------------------ 1. dashboard

    public static function dashboard(): string
    {
        $ping = self::ping();
        $ov = $edges = $events = $sites = null;
        if ($ping['ok']) {
            $r = self::fetch(['/api/v1/overview', '/api/v1/edges', '/api/v1/events?limit=8', '/api/v1/sites']);
            $ov = self::ok($r['/api/v1/overview']) ? $r['/api/v1/overview']['data'] : null;
            $edges = self::ok($r['/api/v1/edges']) ? $r['/api/v1/edges']['data'] : null;
            $events = self::ok($r['/api/v1/events?limit=8']) ? $r['/api/v1/events?limit=8']['data'] : null;
            $sites = self::ok($r['/api/v1/sites']) ? $r['/api/v1/sites']['data'] : null;
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
        $h .= View::kpi('users', 'brand', 'سرویس‌های WHMCS', View::n($counts['Active'] ?? 0) . ' <small>فعال</small>',
            View::n($counts['Suspended'] ?? 0) . ' معلق · ' . View::n($counts['Pending'] ?? 0) . ' در انتظار');
        $h .= '</div>';

        // warnings
        $warn = self::warnings($ping, $ov, $sites);
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
        $h .= View::card('سلامت نودها', $edges === null ? '<p class="pcdna-muted">فهرست نودها در دسترس نیست.</p>' : self::edgeTable($edges, false),
            '<a class="pcdna-btn pcdna-btn-sm" href="' . View::url(['page' => 'edges']) . '">مدیریت نودها</a>', '', 'server');

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

    private static function edgeTable(array $edges, bool $actions): string
    {
        if (!$edges) {
            return View::emptyState('هنوز نودی ثبت نشده است', 'برای شروع، از صفحه «نودها» اولین نود را اضافه کنید.', 'server');
        }
        $h = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-edges"><thead><tr><th>نام</th><th>منطقه</th><th>IP</th><th>وضعیت</th>'
            . '<th>آخرین ارتباط</th><th>نسخه تنظیمات</th>' . ($actions ? '<th><span class="pcdna-sr">عملیات</span></th>' : '') . '</tr></thead><tbody>';
        foreach ($edges as $e) {
            $online = self::edgeOnline($e);
            $fresh = !empty($e['enabled']) && empty($e['last_seen_at']);
            $status = empty($e['enabled']) ? View::badge('غیرفعال', 'muted') : ($online ? View::badge('آنلاین', 'ok')
                : ($fresh ? View::badge('در انتظار نصب', 'warn', ' title="agent هنوز به کنترلر وصل نشده است"') : View::badge('آفلاین', 'bad')));
            $err = trim((string) ($e['last_error'] ?? ''));
            $h .= '<tr' . (!empty($e['enabled']) && !$online && !$fresh ? ' class="is-bad"' : '') . ($err !== '' ? ' data-has-error="1"' : '') . '><td><strong>' . View::ltr($e['name'] ?? '') . '</strong></td>'
                . '<td>' . (($e['region'] ?? '') === 'home' ? View::badge('ایران', 'brand') : View::badge('خارج', 'violet')) . '</td>'
                . '<td>' . View::ltr($e['ipv4'] ?? '') . (!empty($e['ipv6']) ? '<br>' . View::ltr($e['ipv6'], 'pcdna-small') : '') . '</td>'
                . '<td>' . $status . '</td><td title="' . View::e($e['last_seen_at'] ?? '') . '">' . View::e(View::ago($e['last_seen_at'] ?? null)) . '</td>'
                . '<td>' . (!empty($e['applied_version']) ? View::ltr(substr((string) $e['applied_version'], 0, 8), 'pcdna-code') : '—') . '</td>';
            if ($actions) {
                $id = (int) ($e['id'] ?? 0);
                $q = ['page' => 'edges'];
                $h .= '<td class="pcdna-actions">'
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
                $cdnCell = self::cdnBadge((string) ($site['status'] ?? ''));
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
            $t .= '<tr data-service="' . $sid . '"><td class="pcdna-domain-cell"><a class="pcdna-domain" href="' . self::manageUrl($sid) . '">' . View::ltr($domain !== '' ? $domain : '—') . '</a>'
                . '<div class="pcdna-small pcdna-muted"><a href="' . View::e(Data::serviceUrl((int) $svc->userid, $sid)) . '" title="صفحه سرویس در WHMCS">#' . View::n($sid) . '</a> · '
                . View::e($svc->product) . '</div></td>'
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

    public static function edges(?array $newToken = null, array $old = []): string
    {
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
        $h .= View::card('نودهای CDN' . ($edges !== null ? ' (' . View::n($online) . ' آنلاین از ' . View::n(count($edges)) . ')' : ''),
            $edges === null ? View::alert('bad', 'فهرست نودها دریافت نشد: ' . View::e((string) $r['/api/v1/edges']['error'])) : self::edgeTable($edges, true),
            '', 'pcdna-flush', 'server');

        $form = '<form method="post" action="' . View::url(['page' => 'edges']) . '" class="pcdna-form" autocomplete="off">' . View::csrf()
            . '<input type="hidden" name="a" value="edge_add"><div class="pcdna-form-grid">'
            . '<label><span>نام نود</span><input class="pcdna-input" name="name" dir="ltr" required maxlength="64" pattern="[A-Za-z0-9_.\-]{1,64}" placeholder="ir-thr-1" value="' . View::e($old['name'] ?? '') . '">'
            . '<small>حروف انگلیسی، عدد، نقطه، خط تیره</small></label>'
            . '<label><span>IPv4 عمومی</span><input class="pcdna-input" name="ipv4" dir="ltr" required maxlength="15" placeholder="5.160.10.20" value="' . View::e($old['ipv4'] ?? '') . '"></label>'
            . '<label><span>IPv6 (اختیاری)</span><input class="pcdna-input" name="ipv6" dir="ltr" maxlength="45" placeholder="2a01:…" value="' . View::e($old['ipv6'] ?? '') . '"></label>'
            . '<label><span>منطقه</span>' . View::select('region', ['home' => 'ایران (home)', 'global' => 'خارج از ایران (global)'], $old['region'] ?? 'home') . '</label>'
            . '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('plus') . '<span>افزودن نود و ساخت توکن</span></button></div></form>';
        $regions = '<ul class="pcdna-bullets"><li><strong>ایران (home):</strong> نودهای داخل ایران. با GeoDNS، کاربران ایرانی ابتدا به این نودها هدایت می‌شوند؛ '
            . 'ترافیک داخلی ارزان‌تر است و در قطعی اینترنت بین‌الملل، سایت برای کاربران داخل در دسترس می‌ماند.</li>'
            . '<li><strong>خارج (global):</strong> نودهای خارج از ایران برای بازدیدکنندگان خارجی و به‌عنوان پشتیبان وقتی همه نودهای ایران از دسترس خارج شوند.</li>'
            . '<li>بدون GeoDNS همه نودهای سالم به‌صورت تصادفی در پاسخ DNS قرار می‌گیرند. نود «آنلاین» یعنی در ۳ دقیقه اخیر با کنترلر ارتباط داشته است.</li>'
            . '<li>غیرفعال کردن نود آن را برای نگهداری از DNS خارج می‌کند؛ «توکن جدید» توکن فعلی را باطل می‌کند.</li></ul>';
        $h .= '<div class="pcdna-grid-2">' . View::card('افزودن نود جدید', $form, '', '', 'plus') . View::card('منطقه‌ها و وضعیت نودها', $regions, '', '', 'info') . '</div>';
        return $h;
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
            $h .= View::alert('info', 'هنوز محصولی با ماژول Pasargad CDN وجود ندارد. با فرم زیر چهار پلن آماده (پایه، حرفه‌ای، تجاری، سازمانی) را با قیمت، ایمیل خوش‌آمد، فیلد Origin IP و مسیر ارتقا بسازید.');
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
            $f = $plan['features'] ?? [];
            $feat = function ($on, $label) {
                return '<span class="pcdna-feat' . ($on ? ' is-on' : '') . '">' . View::icon($on ? 'check' : 'x') . '<span>' . View::e($label) . '</span></span>';
            };
            $field = Wizard::originField($pid);
            $body = '<dl class="pcdna-dl pcdna-dl-3">'
                . '<div><dt>ترافیک پلن</dt><dd>' . ($o ? View::n($o['included_gb']) . ' GB' : (($plan['bandwidth_limit_gb'] ?? 0) ? View::n($plan['bandwidth_limit_gb']) . ' GB' : 'نامحدود')) . '</dd></div>'
                . '<div><dt>سقف قطع روی CDN</dt><dd>' . (($plan['bandwidth_limit_gb'] ?? 0) ? View::n($plan['bandwidth_limit_gb']) . ' GB' : 'نامحدود') . '</dd></div>'
                . '<div><dt>ترافیک اضافه</dt><dd>' . ($o ? View::n($o['price_per_gb'], $o['price_per_gb'] >= 100 ? 0 : 2) . ' برای هر گیگابایت<div class="pcdna-small pcdna-muted">ذخیره در WHMCS: ' . View::n($p->overagesbwprice, 4) . ' برای هر مگابایت</div>' : 'غیرفعال') . '</dd></div>'
                . '<div><dt>رکورد DNS</dt><dd>' . View::n($plan['max_records'] ?? 0) . '</dd></div>'
                . '<div><dt>قوانین فایروال / صفحه / نرخ</dt><dd>' . View::n($f['max_firewall_rules'] ?? 0) . ' / ' . View::n($f['max_page_rules'] ?? 0) . ' / ' . View::n($f['max_ratelimit_rules'] ?? 0) . '</dd></div>'
                . '<div><dt>استخر توزیع بار</dt><dd>' . View::n($f['max_pools'] ?? 0) . '</dd></div>'
                . '<div><dt>گروه سرور</dt><dd>' . ((int) $p->servergroup > 0 ? View::e($p->servergroup_name ?: '#' . (int) $p->servergroup) : View::badge('تنظیم نشده', 'bad')) . '</dd></div>'
                . '<div><dt>راه‌اندازی</dt><dd>' . View::e(self::AUTOSETUP[(string) $p->autosetup] ?? (string) $p->autosetup) . '</dd></div>'
                . '<div><dt>ایمیل خوش‌آمد</dt><dd>' . (!empty($p->welcomeemail) ? View::e($emails[(int) $p->welcomeemail] ?? '#' . (int) $p->welcomeemail) : View::badge('ندارد', 'warn')) . '</dd></div>'
                . '<div><dt>فیلد Origin IP</dt><dd>' . ($field ? View::badge('دارد', 'ok') : View::badge('ندارد', 'muted')) . '</dd></div>'
                . '<div><dt>مسیر ارتقا</dt><dd>' . (isset($upg[$pid]) ? View::n(count($upg[$pid])) . ' محصول' : View::badge('ندارد', 'warn')) . '</dd></div>'
                . '<div><dt>نیاز به دامنه</dt><dd>' . (!empty($p->showdomainoptions) ? View::badge('بله', 'ok') : View::badge('خیر', 'bad')) . '</dd></div>'
                . '</dl><div class="pcdna-feats">' . $feat($plan['ssl_allowed'] ?? false, 'SSL رایگان') . $feat($f['waf'] ?? false, 'WAF')
                . $feat($f['ddos'] ?? false, 'DDoS') . $feat(($f['load_balancer'] ?? false) && ($f['max_pools'] ?? 0) > 0, 'توزیع بار')
                . $feat($f['image_optimization'] ?? false, 'بهینه‌سازی تصویر') . $feat($f['custom_ssl'] ?? false, 'گواهی اختصاصی')
                . $feat($f['dnssec'] ?? false, 'DNSSEC') . '</div>';
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
            . '<span>راه‌اندازی خودکار محصولات</span></h3><span class="pcdna-muted pcdna-small">گروه، ۴ پلن، قیمت‌ها، ایمیل خوش‌آمد، فیلد Origin IP و مسیر ارتقا — قابل اجرای مجدد</span></summary><div class="pcdna-card-body">';
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

        $h .= '<fieldset class="pcdna-fieldset"><legend>ترافیک اضافه (Overage)</legend>'
            . '<div class="pcdna-checks-row">' . self::check('overage', $in['overage'], 'صورتحساب ترافیک اضافه فعال باشد (به جای قطع سرویس در پایان ترافیک پلن)') . '</div>'
            . '<div class="pcdna-form-grid">'
            . '<label><span>قیمت هر گیگابایت اضافه (' . View::e($def ? $def->code : '') . ')</span><input class="pcdna-input" name="overage_price" dir="ltr" inputmode="decimal" value="'
            . View::e(Wizard::fmt((float) $in['overage_price'])) . '" data-per-mb="1"><small data-per-mb-out="1">WHMCS قیمت را به ازای هر مگابایت ذخیره می‌کند: '
            . View::n(Wizard::perMb((float) $in['overage_price']), 4) . ' هر MB</small></label>'
            . '<label><span>سقف ترافیک اضافه (درصد از ترافیک پلن)</span><input class="pcdna-input" name="overage_allow" dir="ltr" inputmode="numeric" value="' . (int) $in['overage_allow'] . '">'
            . '<small>مثلاً ۱۰۰ یعنی سرویس ۱۰۰ گیگابایتی حداکثر تا ۲۰۰ گیگابایت ادامه می‌دهد و سپس روی CDN متوقف می‌شود (محافظت در برابر صورتحساب ناخواسته).</small></label>'
            . '</div><p class="pcdna-muted pcdna-small">ترافیک پلن به‌عنوان «Soft Limit» پهنای باند در WHMCS ثبت می‌شود و WHMCS در پایان ماه مازاد را فاکتور می‌کند '
            . '(Automation Settings → Overage Billing). قیمت در ارزهای دیگر با نرخ تبدیل WHMCS محاسبه می‌شود.</p></fieldset>';

        $h .= '<fieldset class="pcdna-fieldset"><legend>ایمیل خوش‌آمد</legend><div class="pcdna-checks-row">'
            . self::check('email', $in['email'], 'قالب ایمیل «' . Wizard::EMAIL_NAME . '» ساخته و به محصولات وصل شود (نیم‌سرورها از کنترلر خوانده می‌شوند)')
            . self::check('email_update', $in['email_update'], 'به‌روزرسانی: اگر قالبی با این نام وجود دارد متن آن بازنویسی شود')
            . '</div></fieldset>';

        // feature matrix
        $h .= '<fieldset class="pcdna-fieldset"><legend>امکانات پلن‌ها</legend><div class="pcdna-table-wrap"><table class="pcdna-table pcdna-matrix"><thead><tr><th></th>';
        foreach (Wizard::PLANS as $key => $d) {
            $p = $in['plans'][$key];
            $h .= '<th><label class="pcdna-check"><input type="checkbox" name="plan[' . $key . '][enabled]" value="1"' . ($p['enabled'] ? ' checked' : '') . '><span>'
                . View::e($d['title']) . '</span></label></th>';
        }
        $h .= '</tr></thead><tbody><tr><th>نام محصول</th>';
        foreach (Wizard::PLANS as $key => $d) {
            $h .= '<td><input class="pcdna-input" name="plan[' . $key . '][name]" maxlength="100" value="' . View::e($in['plans'][$key]['name']) . '" aria-label="نام محصول ' . View::e($d['title']) . '"></td>';
        }
        $h .= '</tr>';
        foreach (['bw', 'records', 'ssl', 'rate', 'waf', 'ddos', 'lb', 'image', 'customssl', 'dnssec', 'page', 'fw', 'rl', 'pools'] as $f) {
            $h .= '<tr><th>' . View::e(Wizard::FIELD_LABELS[$f]) . '</th>';
            foreach (Wizard::PLANS as $key => $d) {
                $v = $in['plans'][$key][$f];
                $nm = 'plan[' . $key . '][' . $f . ']';
                $aria = ' aria-label="' . View::e(Wizard::FIELD_LABELS[$f] . ' — ' . $d['title']) . '"';
                $h .= '<td>' . (isset(Wizard::FLAGS[$f])
                        ? '<label class="pcdna-switch"><input type="checkbox" name="' . $nm . '" value="1"' . ($v ? ' checked' : '') . $aria . '><span></span></label>'
                        : '<input class="pcdna-input pcdna-input-num" name="' . $nm . '" dir="ltr" inputmode="numeric" value="' . (int) $v . '"' . $aria . '>') . '</td>';
            }
            $h .= '</tr>';
        }
        $h .= '</tbody></table></div><p class="pcdna-muted pcdna-small">ترافیک ۰ یعنی نامحدود. استخر توزیع بار فقط وقتی «توزیع بار» روشن باشد اعمال می‌شود. '
            . 'این مقادیر در Module Settings محصول (configoption1..14) ذخیره می‌شوند و با ChangePackage روی سرویس‌های موجود اعمال می‌شوند.</p></fieldset>';

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
        $tot = ['used' => 0.0, 'over' => 0.0, 'amount' => []];
        foreach ((array) ($r['data']['sites'] ?? []) as $s) {
            $ext = (string) ($s['external_id'] ?? '');
            $svc = ($ext !== '' && ctype_digit($ext) && isset($services[(int) $ext])) ? $services[(int) $ext] : ($ix[strtolower((string) ($s['domain'] ?? ''))] ?? null);
            $used = round((float) ($s['bytes'] ?? 0) / 1073741824, 3);
            $o = $svc && function_exists('pasargadcdn_overage') ? \pasargadcdn_overage((array) $svc) : null;
            $limit = $o ? (float) $o['included_gb'] : (float) ($s['bandwidth_limit_gb'] ?? 0);
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
                'requests' => (int) ($s['requests'] ?? 0),
            ];
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
        $amounts = [];
        foreach ($tot['amount'] as $code => $a) {
            $amounts[] = $money($a) . ' <small>' . View::e($code) . '</small>';
        }
        $h .= '<div class="pcdna-kpis pcdna-kpis-3">' . View::kpi('activity', 'brand', 'کل ترافیک ماه', View::gb($tot['used']), View::n(count($rows)) . ' سایت')
            . View::kpi('warn', 'warn', 'ترافیک مازاد', View::gb($tot['over']), 'بیش از ترافیک پلن')
            . View::kpi('tag', 'violet', 'مبلغ تخمینی مازاد', $amounts ? implode('<br>', $amounts) : '<span class="pcdna-muted">۰</span>', 'فاکتور نهایی را WHMCS صادر می‌کند') . '</div>';
        if (!$rows) {
            return $h . View::card('', View::emptyState('برای این ماه مصرفی ثبت نشده است', '', 'chart'));
        }
        $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-usage"><thead><tr><th>دامنه / محصول</th><th>سرویس / مشتری</th>'
            . '<th>مصرف (GB)</th><th>ترافیک پلن (GB)</th><th>مازاد (GB)</th><th>مبلغ تخمینی</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $t .= '<tr' . ($r['over'] > 0 ? ' class="is-warn"' : '') . '><td class="pcdna-nowrap">' . View::ltr($r['domain'])
                . '<div class="pcdna-small pcdna-muted">' . View::e($r['product'] ?: '—') . '</div></td>'
                . '<td>' . ($r['service'] ? '<a href="' . View::e(Data::serviceUrl($r['userid'], $r['service'])) . '">#' . View::n($r['service']) . '</a>'
                    . '<div class="pcdna-small"><a href="' . View::e(Data::clientUrl($r['userid'])) . '">' . View::e($r['client']) . '</a></div>'
                    : View::badge('بدون سرویس', 'muted')) . '</td>'
                . '<td class="pcdna-num">' . View::n($r['used'], 2) . ($r['limit'] > 0 ? View::meter($r['used'] / $r['limit']) : '') . '</td>'
                . '<td class="pcdna-num">' . ($r['limit'] > 0 ? View::n($r['limit']) : 'نامحدود') . '</td>'
                . '<td class="pcdna-num">' . ($r['over'] > 0 ? '<strong>' . View::n($r['over'], 2) . '</strong>' : '<span class="pcdna-muted">۰</span>') . '</td>'
                . '<td class="pcdna-num">' . ($r['amount'] === null ? '<span class="pcdna-muted" title="صورتحساب ترافیک اضافه برای این محصول فعال نیست">—</span>'
                    : ($r['amount'] > 0 ? '<strong>' . $money($r['amount']) . '</strong> <small>' . View::e($r['currency']) . '</small>' : '<span class="pcdna-muted">۰</span>')) . '</td></tr>';
        }
        $t .= '</tbody><tfoot><tr><th colspan="2">جمع</th><th class="pcdna-num">' . View::n($tot['used'], 2) . '</th><th></th><th class="pcdna-num">'
            . View::n($tot['over'], 2) . '</th><th class="pcdna-num">' . ($amounts ? implode('<br>', $amounts) : '—') . '</th></tr></tfoot></table></div>';
        $h .= View::card('مصرف ' . View::digits($month), $t . '<p class="pcdna-muted pcdna-small pcdna-pad">مبلغ تخمینی = مازاد × قیمت هر گیگابایت محصول × نرخ ارز مشتری. '
                . 'WHMCS مازاد را بر اساس مصرفی که کران روزانه (UsageUpdate) ثبت کرده در پایان ماه فاکتور می‌کند؛ ممکن است با این گزارش لحظه‌ای کمی تفاوت داشته باشد.</p>', '', 'pcdna-flush', 'chart');
        return $h;
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
        fputcsv($fh, ['شناسه سرویس', 'مشتری', 'دامنه', 'محصول', 'وضعیت', 'مصرف (GB)', 'ترافیک پلن (GB)', 'مازاد (GB)', 'مبلغ تخمینی', 'ارز', 'درخواست‌ها'], ',', '"', '\\');
        foreach ($rows as $r) {
            fputcsv($fh, [$r['service'] ?: '', self::csvSafe($r['client']), $r['domain'], self::csvSafe($r['product']), $r['status'],
                number_format($r['used'], 3, '.', ''), $r['limit'] > 0 ? number_format($r['limit'], 3, '.', '') : '',
                number_format($r['over'], 3, '.', ''), $r['amount'] === null ? '' : number_format($r['amount'], 2, '.', ''),
                $r['currency'], $r['requests']], ',', '"', '\\');
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
            $noOverage = array_filter($products, function ($p) {
                return (int) $p->configoption1 > 0 && (!function_exists('pasargadcdn_overage') || \pasargadcdn_overage((array) $p) === null);
            });
            $add($noOverage ? 'warn' : 'ok', 'صورتحساب ترافیک اضافه', $noOverage ? 'غیرفعال برای: ' . View::e(implode('، ', array_map(function ($p) {
                return $p->name;
            }, $noOverage))) . ' (سرویس در پایان ترافیک متوقف می‌شود)' : 'برای محصولات دارای سقف ترافیک تنظیم شده است',
                'تب Other محصول → Overages Billing، یا ویزارد پلن‌ها با گزینه ترافیک اضافه. در Automation Settings گزینه Overage Billing را هم فعال کنید.');
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
