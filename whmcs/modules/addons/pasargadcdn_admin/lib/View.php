<?php

namespace PasargadCdn\Admin;

if (class_exists(__NAMESPACE__ . '\\View', false)) {
    return;
}

/**
 * HTML helpers for the admin pages. Every dynamic value goes through e().
 */
final class View
{
    /** @var string addonmodules.php?module=pasargadcdn_admin */
    public static $link = 'addonmodules.php?module=pasargadcdn_admin';

    public static function e($v): string
    {
        return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /** Module URL with extra query parameters (already escaped for HTML attributes). */
    public static function url(array $q = [], bool $escape = true): string
    {
        $u = self::$link . ($q ? '&' . http_build_query($q, '', '&', PHP_QUERY_RFC3986) : '');
        return $escape ? self::e($u) : $u;
    }

    public static function digits(string $s): string
    {
        return strtr($s, ['0' => '۰', '1' => '۱', '2' => '۲', '3' => '۳', '4' => '۴', '5' => '۵', '6' => '۶',
            '7' => '۷', '8' => '۸', '9' => '۹', ',' => '٬', '.' => '٫']);
    }

    /** Persian formatted number. */
    public static function n($v, int $dec = 0): string
    {
        $v = (float) $v;
        if ($dec > 0 && abs($v - round($v)) < 0.000001) {
            $dec = 0;
        }
        return self::digits(number_format($v, $dec, '.', ','));
    }

    public static function bytes($b): string
    {
        $b = (float) $b;
        $u = ['بایت', 'KB', 'MB', 'GB', 'TB', 'PB'];
        $i = 0;
        while ($b >= 1024 && $i < count($u) - 1) {
            $b /= 1024;
            $i++;
        }
        return self::n($b, $i === 0 ? 0 : ($b < 10 ? 2 : 1)) . ' ' . $u[$i];
    }

    public static function gb($gb): string
    {
        return self::n($gb, (float) $gb < 10 ? 2 : 1) . ' GB';
    }

    /** Left-to-right fragment (domains, IPs, codes) inside RTL text. */
    public static function ltr($s, string $cls = ''): string
    {
        return '<bdi dir="ltr" class="pcdna-ltr' . ($cls !== '' ? ' ' . self::e($cls) : '') . '">' . self::e($s) . '</bdi>';
    }

    public static function badge(string $text, string $tone = 'muted', string $extra = ''): string
    {
        return '<span class="pcdna-badge pcdna-t-' . self::e($tone) . '"' . $extra . '>' . self::e($text) . '</span>';
    }

    public static function dot(string $tone): string
    {
        return '<span class="pcdna-dot pcdna-t-' . self::e($tone) . '" aria-hidden="true"></span>';
    }

    /** Jalali date (Y/m/d) when intl is available, else the Gregorian Y-m-d. */
    public static function date($ts, bool $time = false): string
    {
        if ($ts === null || $ts === '' || $ts === '0000-00-00' || $ts === '0000-00-00 00:00:00') {
            return '—';
        }
        $t = is_numeric($ts) ? (int) $ts : strtotime((string) $ts);
        if (!$t) {
            return '—';
        }
        if (class_exists('\\IntlDateFormatter')) {
            $f = new \IntlDateFormatter('fa_IR@calendar=persian', \IntlDateFormatter::NONE, \IntlDateFormatter::NONE,
                date_default_timezone_get(), \IntlDateFormatter::TRADITIONAL, $time ? 'yyyy/MM/dd HH:mm' : 'yyyy/MM/dd');
            $s = $f->format($t);
            if (is_string($s) && $s !== '') {
                return self::digits(strtr($s, ['۰' => '0', '۱' => '1', '۲' => '2', '۳' => '3', '۴' => '4', '۵' => '5',
                    '۶' => '6', '۷' => '7', '۸' => '8', '۹' => '9']));
            }
        }
        return self::digits(date($time ? 'Y-m-d H:i' : 'Y-m-d', $t));
    }

    /** "۳ دقیقه پیش" */
    public static function ago($iso): string
    {
        if (!$iso) {
            return 'هرگز';
        }
        $t = strtotime((string) $iso);
        if (!$t) {
            return '—';
        }
        $d = time() - $t;
        if ($d < 0) {
            $d = 0;
        }
        if ($d < 60) {
            return 'لحظاتی پیش';
        }
        if ($d < 3600) {
            return self::n(floor($d / 60)) . ' دقیقه پیش';
        }
        if ($d < 86400) {
            return self::n(floor($d / 3600)) . ' ساعت پیش';
        }
        return self::n(floor($d / 86400)) . ' روز پیش';
    }

    public static function clip(string $s, int $n): string
    {
        if (function_exists('mb_strlen') && mb_strlen($s) > $n) {
            return mb_substr($s, 0, $n - 1) . '…';
        }
        return $s;
    }

    /** Hidden CSRF inputs for a POST form (own token + WHMCS's token when present). */
    public static function csrf(): string
    {
        $h = '<input type="hidden" name="pcdn_csrf" value="' . self::e(Env::csrf()) . '">';
        $w = Env::whmcsToken();
        if ($w !== '') {
            $h .= '<input type="hidden" name="token" value="' . self::e($w) . '">';
        }
        return $h;
    }

    /**
     * Small POST form with one button.
     * @param array $fields extra hidden fields
     */
    public static function postButton(array $q, string $action, array $fields, string $label, string $cls = 'pcdna-btn',
                                      string $confirm = '', string $icon = ''): string
    {
        $h = '<form method="post" action="' . self::url($q) . '" class="pcdna-inline"'
            . ($confirm !== '' ? ' data-confirm="' . self::e($confirm) . '"' : '') . '>' . self::csrf()
            . '<input type="hidden" name="a" value="' . self::e($action) . '">';
        foreach ($fields as $k => $v) {
            $h .= '<input type="hidden" name="' . self::e($k) . '" value="' . self::e($v) . '">';
        }
        return $h . '<button type="submit" class="' . self::e($cls) . '" title="' . self::e($label) . '">' . ($icon !== '' ? self::icon($icon) : '')
            . '<span>' . self::e($label) . '</span></button></form>';
    }

    public static function alert(string $tone, string $html, string $icon = ''): string
    {
        $icon = $icon ?: ['ok' => 'check', 'bad' => 'x', 'warn' => 'warn', 'info' => 'info'][$tone] ?? 'info';
        return '<div class="pcdna-alert pcdna-alert-' . self::e($tone) . '" role="' . ($tone === 'bad' ? 'alert' : 'status') . '">'
            . self::icon($icon) . '<div>' . $html . '</div></div>';
    }

    public static function card(string $title, string $body, string $actions = '', string $cls = '', string $icon = ''): string
    {
        return '<section class="pcdna-card' . ($cls !== '' ? ' ' . self::e($cls) : '') . '">'
            . ($title !== '' || $actions !== '' ? '<header class="pcdna-card-head"><h3>' . ($icon ? self::icon($icon) : '') . '<span>'
                . self::e($title) . '</span></h3>' . ($actions !== '' ? '<div class="pcdna-card-actions">' . $actions . '</div>' : '')
                . '</header>' : '')
            . '<div class="pcdna-card-body">' . $body . '</div></section>';
    }

    public static function kpi(string $icon, string $tone, string $label, string $value, string $sub = ''): string
    {
        return '<div class="pcdna-kpi"><span class="pcdna-kpi-icon pcdna-t-' . self::e($tone) . '">' . self::icon($icon) . '</span>'
            . '<div class="pcdna-kpi-body"><div class="pcdna-kpi-label">' . self::e($label) . '</div>'
            . '<div class="pcdna-kpi-value">' . $value . '</div>'
            . ($sub !== '' ? '<div class="pcdna-kpi-sub">' . $sub . '</div>' : '') . '</div></div>';
    }

    public static function emptyState(string $title, string $html = '', string $icon = 'info'): string
    {
        return '<div class="pcdna-empty">' . self::icon($icon) . '<strong>' . self::e($title) . '</strong>'
            . ($html !== '' ? '<p>' . $html . '</p>' : '') . '</div>';
    }

    public static function meter(float $ratio, string $tone = ''): string
    {
        $r = max(0.0, min(1.0, $ratio));
        $tone = $tone ?: ($ratio >= 1 ? 'bad' : ($ratio >= 0.8 ? 'warn' : 'brand'));
        return '<span class="pcdna-meter" role="presentation"><span class="pcdna-t-' . $tone . '" style="width:'
            . round($r * 100, 1) . '%"></span></span>';
    }

    /** Copyable code block. */
    public static function copyable(string $text, string $label = 'کپی'): string
    {
        return '<div class="pcdna-copy"><code dir="ltr">' . self::e($text) . '</code>'
            . '<button type="button" class="pcdna-btn pcdna-btn-sm" data-copy="' . self::e($text) . '">'
            . self::icon('copy') . '<span>' . self::e($label) . '</span></button></div>';
    }

    public static function select(string $name, array $options, $current, string $attrs = ''): string
    {
        $h = '<select name="' . self::e($name) . '" class="pcdna-input"' . $attrs . '>';
        foreach ($options as $v => $label) {
            $h .= '<option value="' . self::e($v) . '"' . ((string) $v === (string) $current ? ' selected' : '') . '>'
                . self::e($label) . '</option>';
        }
        return $h . '</select>';
    }

    const ICONS = [
        'dashboard' => 'M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z',
        'globe' => 'M12 2a10 10 0 100 20 10 10 0 000-20zM2 12h20M12 2c2.5 2.7 4 6.2 4 10s-1.5 7.3-4 10c-2.5-2.7-4-6.2-4-10s1.5-7.3 4-10z',
        'server' => 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01',
        'tag' => 'M20.6 13.4l-7.2 7.2a2 2 0 01-2.8 0L3 13V3h10l7.6 7.6a2 2 0 010 2.8zM7.5 7.5h.01',
        'chart' => 'M3 3v18h18M7 15l4-4 3 3 5-6',
        'shield' => 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
        'settings' => 'M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z',
        'check' => 'M20 6L9 17l-5-5',
        'x' => 'M18 6L6 18M6 6l12 12',
        'warn' => 'M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01',
        'info' => 'M12 22a10 10 0 100-20 10 10 0 000 20zM12 16v-4M12 8h.01',
        'refresh' => 'M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0114.8-3.4L23 10M1 14l4.6 4.4A9 9 0 0020.5 15',
        'copy' => 'M9 9h11v11H9zM5 15H4a1 1 0 01-1-1V4a1 1 0 011-1h10a1 1 0 011 1v1',
        'external' => 'M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3',
        'plus' => 'M12 5v14M5 12h14',
        'trash' => 'M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6',
        'key' => 'M21 2l-2 2m-7.6 7.6a5.5 5.5 0 11-7.8 7.8 5.5 5.5 0 017.8-7.8zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
        'power' => 'M18.4 6.6a9 9 0 11-12.8 0M12 2v10',
        'search' => 'M11 19a8 8 0 100-16 8 8 0 000 16zM21 21l-4.3-4.3',
        'download' => 'M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3',
        'zap' => 'M13 2L3 14h9l-1 8 10-12h-9z',
        'activity' => 'M22 12h-4l-3 9L9 3l-3 9H2',
        'sliders' => 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
        'users' => 'M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M9 11a4 4 0 100-8 4 4 0 000 8zM23 21v-2a4 4 0 00-3-3.9M16 3.1a4 4 0 010 7.8',
        'more' => 'M12 13a1 1 0 100-2 1 1 0 000 2zM19 13a1 1 0 100-2 1 1 0 000 2zM5 13a1 1 0 100-2 1 1 0 000 2z',
        'wand' => 'M15 4V2M15 16v-2M8 9h2M20 9h2M17.8 11.8L19 13M17.8 6.2L19 5M3 21l9-9M12.2 6.2L11 5',
        'sync' => 'M21 12a9 9 0 01-15.5 6.2L3 16M3 12a9 9 0 0115.5-6.2L21 8M21 3v5h-5M3 21v-5h5',
        'wallet' => 'M4 7h15a1.5 1.5 0 011.5 1.5v10A1.5 1.5 0 0119 20H5a1.5 1.5 0 01-1.5-1.5v-12A2.5 2.5 0 016 4h11v3M16 13.5h.01',
        'mail' => 'M4 4h16a2 2 0 012 2v12a2 2 0 01-2 2H4a2 2 0 01-2-2V6a2 2 0 012-2zM22 6l-10 7L2 6',
        'history' => 'M3 3v6h6M3.5 13a9 9 0 103-7.7L3 9M12 7v5l4 2',
        'heart' => 'M20.8 5.6a5.5 5.5 0 00-7.8 0L12 6.6l-1-1a5.5 5.5 0 00-7.8 7.8L12 21l8.8-8.6a5.5 5.5 0 000-7.8z',
    ];

    public static function icon(string $name): string
    {
        $d = self::ICONS[$name] ?? self::ICONS['info'];
        return '<svg class="pcdna-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            . 'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="' . $d . '"/></svg>';
    }
}
