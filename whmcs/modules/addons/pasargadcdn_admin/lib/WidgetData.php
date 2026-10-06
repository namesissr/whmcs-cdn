<?php

namespace PasargadCdn\Admin;

if (class_exists(__NAMESPACE__ . '\\WidgetData', false)) {
    return;
}

/**
 * Data + HTML of the admin home widget. One controller call (/api/v1/overview,
 * 5 s timeout) at most every 5 minutes; failures are cached for 1 minute so a
 * controller outage never slows the admin home page down repeatedly.
 */
final class WidgetData
{
    const KEY = 'pasargadcdn_admin_widget';
    const TTL = 300;
    const TTL_ERROR = 60;

    public static function get(bool $refresh = false): array
    {
        if (!$refresh) {
            $c = Env::cacheGet(self::KEY);
            if (is_array($c) && isset($c['ok'])) {
                $c['cached'] = true;
                return $c;
            }
        }
        try {
            $o = Env::api(5)->get('/api/v1/overview');
            $sec = 0;
            foreach ((array) ($o['month']['security'] ?? []) as $v) {
                $sec += (int) $v;
            }
            $data = [
                'ok' => true,
                'sites' => (int) ($o['sites']['total'] ?? 0),
                'active' => (int) ($o['sites']['by_status']['active'] ?? 0),
                'pending' => (int) ($o['sites']['by_status']['pending_ns'] ?? 0),
                'edges_online' => (int) ($o['edges']['online'] ?? 0),
                'edges_total' => (int) ($o['edges']['enabled'] ?? ($o['edges']['total'] ?? 0)),
                'bytes' => (float) ($o['month']['bytes'] ?? 0),
                'requests' => (int) ($o['month']['requests'] ?? 0),
                'threats' => $sec,
                'at' => time(),
            ];
            Env::cacheSet(self::KEY, $data, self::TTL);
        } catch (\Throwable $e) {
            $data = ['ok' => false, 'error' => $e->getMessage(), 'at' => time()];
            Env::cacheSet(self::KEY, $data, self::TTL_ERROR);
        }
        $data['cached'] = false;
        return $data;
    }

    public static function render(array $d): string
    {
        $link = View::e(View::$link);
        $css = '<style>.pcdnw{direction:rtl;text-align:right;font-family:"PCDN Vazirmatn",Vazirmatn,Tahoma,sans-serif;font-size:13px;line-height:1.7;padding:4px 2px}'
            . '.pcdnw-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:0 0 8px}'
            . '.pcdnw-k{background:#f6f8fb;border:1px solid #e3e8ef;border-radius:8px;padding:6px 10px;min-width:0}'
            . '.pcdnw-k b{display:block;font-size:17px;color:#0f172a;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}'
            . '.pcdnw-k span{color:#5b6475;font-size:12px}.pcdnw-bad{color:#b42318}.pcdnw-ok{color:#067647}'
            . '.pcdnw-foot{display:flex;justify-content:space-between;gap:8px;color:#5b6475;font-size:12px}</style>';
        if (empty($d['ok'])) {
            return $css . '<div class="pcdnw"><p class="pcdnw-bad">ارتباط با کنترلر CDN برقرار نشد.</p>'
                . '<p style="color:#5b6475;font-size:12px">' . View::e(View::clip((string) ($d['error'] ?? ''), 160)) . '</p>'
                . '<div class="pcdnw-foot"><a href="' . $link . '&amp;page=settings">بررسی سلامت</a></div></div>';
        }
        $edgeTone = $d['edges_online'] > 0 && $d['edges_online'] >= $d['edges_total'] ? 'pcdnw-ok' : 'pcdnw-bad';
        return $css . '<div class="pcdnw"><div class="pcdnw-grid">'
            . '<div class="pcdnw-k"><span>سایت‌ها</span><b>' . View::n($d['sites']) . '</b><span>' . View::n($d['active']) . ' فعال · '
            . View::n($d['pending']) . ' در انتظار NS</span></div>'
            . '<div class="pcdnw-k"><span>نودهای آنلاین</span><b class="' . $edgeTone . '">' . View::n($d['edges_online']) . ' / '
            . View::n($d['edges_total']) . '</b><span>نود فعال</span></div>'
            . '<div class="pcdnw-k"><span>ترافیک این ماه</span><b>' . View::bytes($d['bytes']) . '</b><span>'
            . View::n($d['requests']) . ' درخواست</span></div>'
            . '<div class="pcdnw-k"><span>تهدیدهای متوقف‌شده</span><b>' . View::n($d['threats']) . '</b><span>این ماه</span></div>'
            . '</div><div class="pcdnw-foot"><a href="' . $link . '">داشبورد CDN</a><span>به‌روزرسانی: '
            . View::ago(gmdate('Y-m-d\TH:i:s\Z', (int) $d['at'])) . '</span></div></div>';
    }
}
