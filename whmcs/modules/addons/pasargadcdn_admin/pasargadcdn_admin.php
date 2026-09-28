<?php
/**
 * Pasargad CDN — WHMCS admin addon («مدیریت CDN پاسارگاد»).
 *
 * Admin panel for the self-hosted CDN: dashboard, sites, edges, plans &
 * pricing (product wizard), usage report, security events, diagnostics and
 * «مدیریت کامل» (the customer app opened in admin mode for any service).
 *
 * Requires the provisioning module in modules/servers/pasargadcdn.
 * hooks.php (checkout validation + admin home widget) only runs while this
 * addon is activated.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/Env.php';

use PasargadCdn\Admin\Env;

function pasargadcdn_admin_config()
{
    $servers = ['0' => 'خودکار (اولین سرور فعال Pasargad CDN)'];
    try {
        foreach (WHMCS\Database\Capsule::table('tblservers')->where('type', 'pasargadcdn')->orderBy('id')->get(['id', 'name', 'hostname']) as $s) {
            $servers[(string) $s->id] = ($s->name ?: 'Pasargad CDN') . ' (#' . $s->id . ' — ' . $s->hostname . ')';
        }
    } catch (\Throwable $e) {
        // config page still renders without the list
    }
    return [
        'name' => 'مدیریت CDN پاسارگاد',
        'description' => 'پنل مدیریت CDN پاسارگاد: داشبورد، سایت‌ها، نودها، پلن‌ها و قیمت‌گذاری، گزارش مصرف، رویدادهای امنیتی و بررسی سلامت. '
            . 'به ماژول سرور Pasargad CDN (modules/servers/pasargadcdn) نیاز دارد.',
        'author' => 'Pasargad Mizban',
        'language' => 'english',
        'version' => '1.0.0',
        'fields' => [
            'server' => [
                'FriendlyName' => 'سرور کنترلر',
                'Type' => 'dropdown',
                'Options' => $servers,
                'Default' => '0',
                'Description' => 'سرور Pasargad CDN برای داشبورد، نودها، گزارش‌ها، ویجت و بررسی سبد خرید',
            ],
            'widget' => [
                'FriendlyName' => 'ویجت صفحه اصلی',
                'Type' => 'yesno',
                'Default' => 'yes',
                'Description' => 'نمایش ویجت CDN در صفحه اصلی مدیریت (با حافظه موقت ۵ دقیقه‌ای)',
            ],
            'cartcheck' => [
                'FriendlyName' => 'بررسی دامنه با کنترلر هنگام پرداخت',
                'Type' => 'yesno',
                'Default' => 'yes',
                'Description' => 'پیش از ثبت سفارش CDN، از کنترلر می‌پرسد دامنه قبلاً ثبت نشده باشد (حداکثر ۵ ثانیه؛ در صورت قطعی کنترلر سفارش مسدود نمی‌شود)',
            ],
            'reserved' => [
                'FriendlyName' => 'دامنه‌های رزرو',
                'Type' => 'text',
                'Size' => '60',
                'Default' => 'pasargadmizban.com',
                'Description' => 'دامنه‌هایی که خودشان و زیردامنه‌هایشان قابل سفارش CDN نیستند (با کاما جدا کنید)',
            ],
        ],
    ];
}

function pasargadcdn_admin_activate()
{
    try {
        Env::ensureTable();
        return ['status' => 'success', 'description' => 'ماژول فعال شد. در System Settings → Addon Modules به نقش‌های مدیر دسترسی بدهید، سپس از «پلن‌ها و قیمت‌گذاری» محصولات را بسازید.'];
    } catch (\Throwable $e) {
        return ['status' => 'error', 'description' => 'ساخت جدول ' . Env::KV_TABLE . ' ناموفق بود: ' . $e->getMessage()];
    }
}

/** Nothing is deleted: products, services, templates and the settings table stay intact. */
function pasargadcdn_admin_deactivate()
{
    return ['status' => 'success', 'description' => 'ماژول غیرفعال شد. هیچ داده‌ای حذف نشد؛ بررسی سبد خرید و ویجت تا فعال‌سازی مجدد اجرا نمی‌شوند.'];
}

function pasargadcdn_admin_upgrade($vars)
{
    try {
        Env::ensureTable();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: addon upgrade could not create ' . Env::KV_TABLE . ': ' . $e->getMessage());
        }
    }
}

function pasargadcdn_admin_output($vars)
{
    require_once __DIR__ . '/lib/View.php';
    require_once __DIR__ . '/lib/Data.php';
    require_once __DIR__ . '/lib/Wizard.php';
    require_once __DIR__ . '/lib/WidgetData.php';
    require_once __DIR__ . '/lib/Pages.php';
    require_once __DIR__ . '/lib/Admin.php';
    echo PasargadCdn\Admin\Admin::output(is_array($vars) ? $vars : [], $_GET, $_POST,
        strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')));
}

function pasargadcdn_admin_sidebar($vars)
{
    $link = htmlspecialchars((string) ($vars['modulelink'] ?? 'addonmodules.php?module=pasargadcdn_admin'), ENT_QUOTES, 'UTF-8');
    $items = ['dashboard' => 'داشبورد', 'sites' => 'سایت‌ها', 'edges' => 'نودها', 'plans' => 'پلن‌ها و قیمت‌گذاری',
        'usage' => 'گزارش مصرف', 'events' => 'رویدادهای امنیتی', 'settings' => 'تنظیمات و سلامت'];
    $h = '<span class="header"><i class="fas fa-bolt"></i> CDN پاسارگاد</span><ul class="menu" dir="rtl" style="text-align:right">';
    foreach ($items as $page => $label) {
        $h .= '<li><a href="' . $link . '&amp;page=' . $page . '">' . $label . '</a></li>';
    }
    return $h . '</ul>';
}
