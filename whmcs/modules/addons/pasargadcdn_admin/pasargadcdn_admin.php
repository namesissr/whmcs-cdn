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
        'version' => '1.4.0',
        'fields' => [
            'server' => [
                'FriendlyName' => 'سرور کنترلر',
                'Type' => 'dropdown',
                'Options' => $servers,
                'Default' => '0',
                'Description' => 'سرور Pasargad CDN برای داشبورد، نودها، گزارش‌ها، ویجت و بررسی سبد خرید',
            ],
            'billing' => [
                'FriendlyName' => 'روش صورتحساب ترافیک',
                'Type' => 'dropdown',
                'Options' => [
                    'prepaid' => 'پیش‌پرداخت از کیف پول (قطع با اتمام اعتبار، وصل پس از شارژ)',
                    'overage' => 'فاکتور ترافیک اضافه در پایان ماه',
                    'cut' => 'قطع در پایان ترافیک پلن',
                ],
                'Default' => 'prepaid',
                'Description' => 'در حالت پیش‌پرداخت، پس از اتمام ترافیک پلن بسته‌های ترافیک از اعتبار (Credit) مشتری خریده می‌شود',
            ],
            'block_gb' => [
                'FriendlyName' => 'اندازه بسته ترافیک (GB)',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '10',
                'Description' => 'حالت پیش‌پرداخت: هر خرید خودکار چند گیگابایت باشد',
            ],
            'gb_price' => [
                'FriendlyName' => 'قیمت هر گیگابایت (اختیاری)',
                'Type' => 'text',
                'Size' => '12',
                'Default' => '',
                'Description' => 'خالی = قیمتی که در ویزارد پلن‌ها برای هر محصول ثبت شده (ارز پیش‌فرض WHMCS)',
            ],
            'storage_price' => [
                'FriendlyName' => 'قیمت هر گیگابایت-ماه ذخیره‌سازی',
                'Type' => 'text',
                'Size' => '12',
                'Default' => '',
                'Description' => 'فضای ذخیره‌سازی ابری (S3): میانگین حجم ذخیره‌شده‌ی هر سرویس در ماه (گیگابایت-ماه) × این قیمت (ارز پیش‌فرض WHMCS)، یک بار پس از پایان هر ماه فاکتور می‌شود — در حالت پیش‌پرداخت فاکتوری که از کیف پول پرداخت می‌شود، در حالت‌های دیگر قلمی در فاکتور بعدی. خالی یا ۰ = صورتحساب جداگانه ندارد (مثلاً وقتی گزینه‌ی Storage GB را قیمت‌گذاری کرده‌اید)',
            ],
            'max_blocks' => [
                'FriendlyName' => 'حداکثر خرید خودکار در ماه (بسته)',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '20',
                'Description' => 'محافظت از مشتری در برابر هزینه ناخواسته (مثلاً حمله): پس از این تعداد بسته در یک ماه، خرید خودکار متوقف می‌شود',
            ],
            'warn_email' => [
                'FriendlyName' => 'ایمیل هشدار ۹۰٪',
                'Type' => 'yesno',
                'Default' => 'yes',
                'Description' => 'وقتی ۹۰٪ ترافیک مصرف شده و اعتبار برای بسته بعدی کافی نیست، یک بار در ماه به مشتری ایمیل شود',
            ],
            'forecast_email' => [
                'FriendlyName' => 'ایمیل پیش‌بینی اتمام ترافیک',
                'Type' => 'yesno',
                'Default' => 'yes',
                'Description' => 'وقتی طبق روند مصرف پیش‌بینی می‌شود ترافیک پلن زودتر از پایان ماه تمام شود، یک بار در ماه به مشتری ایمیل «پیش‌بینی اتمام ترافیک» ارسال و در پنل مشتری بنر نمایش داده شود',
            ],
            'forecast_margin_days' => [
                'FriendlyName' => 'حاشیه پیش‌بینی (روز)',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '5',
                'Description' => 'اگر ترافیک پلن دست‌کم این تعداد روز پیش از پایان ماه تمام شود، هشدار پیش‌بینی ارسال می‌شود',
            ],
            'upgrade_topups' => [
                'FriendlyName' => 'آستانه پیشنهاد ارتقا (تعداد بسته در ماه)',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '3',
                'Description' => 'اگر مشتری در یک ماه بیش از این تعداد بسته ترافیک بخرد، پیشنهاد ارتقای پلن (بنر و نشان مدیریت) نمایش داده می‌شود',
            ],
            'upgrade_over_ratio' => [
                'FriendlyName' => 'آستانه پیشنهاد ارتقا (نسبت مصرف به پلن)',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '1.5',
                'Description' => 'اگر مصرف ماه از این نسبت برابرِ ترافیک پلن بیشتر شود، پیشنهاد ارتقا نمایش داده می‌شود (مثلاً ۱.۵ یعنی ۱۵۰٪ ترافیک پلن)',
            ],
            'tunnel_email' => [
                'FriendlyName' => 'ایمیل قطعی سرور پشت تونل',
                'Type' => 'yesno',
                'Default' => 'yes',
                'Description' => 'کران WHMCS رویدادهای تونل کنترلر را می‌خواند و برای قطع و وصل دوباره‌ی سرور پشت تونل به صاحب سرویس ایمیل «قطعی سرور پشت تونل» / «اتصال دوباره برقرار شد» می‌فرستد (هر رویداد یک بار)',
            ],
            'owner_sync' => [
                'FriendlyName' => 'همگام‌سازی مالکیت دامنه‌ها',
                'Type' => 'yesno',
                'Default' => 'yes',
                'Description' => 'کران WHMCS شناسه‌ی مشتری هر سرویس فعال/معلق CDN را روی سایتی که هنوز مالک ندارد ثبت می‌کند (حداکثر ۱۰۰ سایت در هر اجرا) تا محافظت در برابر ثبت زیردامنه‌ی دامنه‌ی مشتری دیگر برای سرویس‌های قدیمی هم کامل باشد',
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
            'reseller_rate' => [
                'FriendlyName' => 'قیمت عمده هر گیگابایت نمایندگان',
                'Type' => 'text',
                'Size' => '12',
                'Default' => '',
                'Description' => 'قیمت پیش‌فرض هر گیگابایت برای نمایندگان (ارز پیش‌فرض WHMCS)؛ برای هر نماینده قابل بازنویسی است',
            ],
            'reseller_max_sites' => [
                'FriendlyName' => 'حداکثر زیرسایت هر نماینده',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '20',
                'Description' => 'سقف پیش‌فرض تعداد زیرسایت‌هایی که هر نماینده می‌تواند بسازد (۰ = نامحدود)؛ برای هر نماینده قابل بازنویسی است',
            ],
            // ---- Wave 10 (SPEC §18.5): public pricing page + referral programme — all off by default
            'pricing_enabled' => [
                'FriendlyName' => 'صفحهٔ عمومی قیمت‌ها',
                'Type' => 'yesno',
                'Default' => '',
                'Description' => 'صفحهٔ مقایسهٔ پلن‌ها بدون نیاز به ورود: index.php?m=pasargadcdn_admin&page=pricing (و &format=json برای سایت اصلی)؛ ۱۰ دقیقه کش',
            ],
            'pricing_hidden' => [
                'FriendlyName' => 'پلن‌های پنهان در صفحهٔ قیمت',
                'Type' => 'text',
                'Size' => '30',
                'Default' => '',
                'Description' => 'شناسهٔ محصولاتی که در صفحهٔ قیمت نمایش داده نشوند (با کاما جدا کنید)',
            ],
            'referral_enabled' => [
                'FriendlyName' => 'برنامهٔ معرفی',
                'Type' => 'yesno',
                'Default' => '',
                'Description' => 'هر مشتری لینک cart.php?ref=… دارد؛ پس از پرداخت اولین فاکتور CDN مشتری معرفی‌شده و گذشت مهلت، به هر دو اعتبار (Credit) WHMCS داده می‌شود',
            ],
            'referral_reward_referrer' => [
                'FriendlyName' => 'پاداش معرف',
                'Type' => 'text',
                'Size' => '12',
                'Default' => '0',
                'Description' => 'مبلغ اعتبار برای معرف (به ارز پاداش؛ ۰ = بدون پاداش)',
            ],
            'referral_reward_referred' => [
                'FriendlyName' => 'پاداش مشتری معرفی‌شده',
                'Type' => 'text',
                'Size' => '12',
                'Default' => '0',
                'Description' => 'مبلغ اعتبار خوش‌آمد برای مشتری جدید (به ارز پاداش؛ ۰ = بدون پاداش)',
            ],
            'referral_currency' => [
                'FriendlyName' => 'ارز پاداش',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '',
                'Description' => 'کد ارز WHMCS مبلغ‌های بالا (مثلاً IRT)؛ خالی = ارز پیش‌فرض. برای مشتری با ارز دیگر با نرخ WHMCS تبدیل می‌شود',
            ],
            'referral_delay_days' => [
                'FriendlyName' => 'مهلت پرداخت پاداش (روز)',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '7',
                'Description' => 'پاداش این تعداد روز پس از پرداخت فاکتور داده می‌شود (کران روزانه)؛ بازپرداخت در این مدت پاداش را لغو می‌کند',
            ],
            'referral_monthly_cap' => [
                'FriendlyName' => 'سقف پاداش ماهانهٔ هر معرف',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '5',
                'Description' => 'حداکثر تعداد پاداش هر معرف در یک ماه (۰ = نامحدود)؛ بقیه به ماه بعد منتقل می‌شوند',
            ],
            'referral_public_domains' => [
                'FriendlyName' => 'دامنه‌های ایمیل عمومی',
                'Type' => 'text',
                'Size' => '60',
                'Default' => '',
                'Description' => 'هم‌دامنه بودن ایمیل معرف و مشتری جدید معرفی را رد می‌کند، مگر برای این سرویس‌دهنده‌های عمومی (خالی = فهرست پیش‌فرض: gmail.com، yahoo.com، outlook.com، …)',
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
    require_once __DIR__ . '/lib/Resellers.php';
    require_once __DIR__ . '/lib/Pages.php';
    require_once __DIR__ . '/lib/OwnerSync.php';
    require_once __DIR__ . '/lib/Referrals.php';
    require_once __DIR__ . '/lib/Operator.php';
    require_once __DIR__ . '/lib/Transfer.php';
    require_once __DIR__ . '/lib/Admin.php';
    echo PasargadCdn\Admin\Admin::output(is_array($vars) ? $vars : [], $_GET, $_POST,
        strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')));
}

/**
 * Wave 10 (SPEC §18.5): the addon's client-area routes —
 *   index.php?m=pasargadcdn_admin&page=pricing[&format=json][&lang=fa|en]  public plan comparison (no login)
 *   index.php?m=pasargadcdn_admin&page=referral                          the client's referral link and counts
 * Both are off until enabled in the addon settings.
 */
function pasargadcdn_admin_clientarea($vars)
{
    require_once __DIR__ . '/lib/View.php';
    require_once __DIR__ . '/lib/Pricing.php';
    require_once __DIR__ . '/lib/Referrals.php';
    $get = array_filter($_GET, 'is_string');
    $clientId = 0;
    try {
        if (class_exists('\\WHMCS\\Authentication\\CurrentUser')) {
            $c = (new \WHMCS\Authentication\CurrentUser())->client();
            $clientId = $c ? (int) $c->id : 0;
        } else {
            $clientId = (int) ($_SESSION['uid'] ?? 0);
        }
    } catch (\Throwable $e) {
        $clientId = (int) ($_SESSION['uid'] ?? 0);
    }
    if (($get['page'] ?? 'pricing') === 'referral') {
        $lang = PasargadCdn\Admin\Pricing::lang($get);
        $title = PasargadCdn\Admin\Referrals::tx('title', $lang);
        $html = $clientId > 0 && PasargadCdn\Admin\Referrals::enabled()
            ? PasargadCdn\Admin\Referrals::cardHtml($clientId, $lang, true)
            : '<div class="alert alert-info">' . htmlspecialchars(PasargadCdn\Admin\Referrals::tx('off', $lang), ENT_QUOTES, 'UTF-8') . '</div>';
        return ['pagetitle' => $title, 'breadcrumb' => ['index.php?m=pasargadcdn_admin&page=referral' => $title],
            'templatefile' => 'pricing', 'requirelogin' => true, 'forcessl' => false, 'vars' => ['pcdn_html' => $html, 'pcdn_lang' => $lang]];
    }
    return PasargadCdn\Admin\Pricing::clientArea($get, $clientId) ?? [];
}

function pasargadcdn_admin_sidebar($vars)
{
    $link = htmlspecialchars((string) ($vars['modulelink'] ?? 'addonmodules.php?module=pasargadcdn_admin'), ENT_QUOTES, 'UTF-8');
    $items = ['dashboard' => 'داشبورد', 'sites' => 'سایت‌ها', 'edges' => 'نودها', 'plans' => 'پلن‌ها و قیمت‌گذاری',
        'operator' => 'دامنه‌های اپراتور', 'analytics' => 'آنالیتیکس', 'usage' => 'گزارش مصرف', 'resellers' => 'نمایندگان', 'events' => 'رویدادهای امنیتی',
        'status' => 'وضعیت و رخدادها', 'health' => 'سلامت سامانه', 'audit' => 'حسابرسی', 'referrals' => 'معرفی‌ها', 'settings' => 'تنظیمات و سلامت'];
    $h = '<span class="header"><i class="fas fa-bolt"></i> CDN پاسارگاد</span><ul class="menu" dir="rtl" style="text-align:right">';
    foreach ($items as $page => $label) {
        $h .= '<li><a href="' . $link . '&amp;page=' . $page . '">' . $label . '</a></li>';
    }
    return $h . '</ul>';
}
