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
    $depts = ['0' => 'اولین بخش پشتیبانی'];
    try {
        foreach (WHMCS\Database\Capsule::table('tblticketdepartments')->orderBy('order')->get(['id', 'name']) as $d) {
            $depts[(string) $d->id] = (string) $d->name . ' (#' . $d->id . ')';
        }
    } catch (\Throwable $e) {
        // config page still renders without the list
    }
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
        // 1.7.0 (SPEC §23, wave 14): alert e-mail outbox + templates, support department, public abuse page
        'version' => '1.7.0',
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
            // SPEC §20: domain sharing with other client accounts
            'share_max_members' => [
                'FriendlyName' => 'حداکثر اعضای اشتراک هر دامنه',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '20',
                'Description' => 'اعضا و دعوت‌های در انتظار یک دامنه (اشتراک دامنه با حساب‌های دیگر)',
            ],
            'share_max_pending' => [
                'FriendlyName' => 'حداکثر دعوت در انتظار هر مالک',
                'Type' => 'text',
                'Size' => '6',
                'Default' => '50',
                'Description' => 'دعوت‌های پذیرفته‌نشدهٔ همهٔ دامنه‌های یک مشتری (دعوت‌ها پس از ۷ روز منقضی می‌شوند)',
            ],
            'share_notify_owner' => [
                'FriendlyName' => 'ایمیل پذیرش دعوت به مالک',
                'Type' => 'yesno',
                'Default' => 'on',
                'Description' => 'وقتی کسی دعوت مدیریت دامنه را بپذیرد، به مالک سرویس ایمیل «پذیرش دعوت مدیریت دامنه» فرستاده شود',
            ],
            // SPEC §19.3: customer-initiated domain transfer (client app «انتقال دامنه»)
            'transfer_customer' => [
                'FriendlyName' => 'انتقال توسط مشتری',
                'Type' => 'yesno',
                'Default' => 'on',
                'Description' => 'مالک سرویس می‌تواند از برنامهٔ CDN درخواست انتقال دامنه به حساب مشتری دیگری بفرستد؛ با پذیرش گیرنده، همان انتقال کامل مشتری به مشتری انجام می‌شود',
            ],
            'transfer_approval' => [
                'FriendlyName' => 'تأیید مدیر لازم است',
                'Type' => 'yesno',
                'Default' => '',
                'Description' => 'درخواست پذیرفته‌شده تا تأیید یا رد مدیر در زبانهٔ «انتقال دامنه» افزونه منتظر می‌ماند',
            ],
            // SPEC §23 (wave 14)
            'alert_email' => [
                'FriendlyName' => 'ایمیل هشدارهای مشتری',
                'Type' => 'yesno',
                'Default' => 'on',
                'Description' => 'کران WHMCS صف ایمیل هشدارهای مشتری (قطعی سرور اصلی، انقضای SSL، ترافیک، رخدادهای سکو، اطلاعیهٔ تخلف) را از کنترلر می‌خواند و با قالب «Pasargad CDN Alert» / «Pasargad CDN Abuse Notice» می‌فرستد؛ پیامک، بله و تلگرام را خود کنترلر می‌فرستد',
            ],
            'support_department' => [
                'FriendlyName' => 'بخش پشتیبانی گزارش عیب‌یابی',
                'Type' => 'dropdown',
                'Options' => $depts,
                'Default' => '0',
                'Description' => 'تیکت‌هایی که مشتری با «ارسال گزارش عیب‌یابی به پشتیبانی» از پنل CDN باز می‌کند به این بخش می‌روند',
            ],
            'abuse_page' => [
                'FriendlyName' => 'صفحهٔ عمومی گزارش تخلف',
                'Type' => 'yesno',
                'Default' => '',
                'Description' => 'فرم بدون نیاز به ورود index.php?m=pasargadcdn_admin&page=abuse (با اثبات کار در مرورگر) و پیگیری وضعیت با شناسه؛ روی کنترلر هم باید ABUSE_ENABLED=true باشد',
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
        pasargadcdn_admin_w14();
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
    // 1.7.0 (SPEC §23): alert e-mail claim table + the «Pasargad CDN Alert» / «Pasargad CDN Abuse Notice» templates (idempotent)
    $from = is_array($vars) ? (string) ($vars['version'] ?? '') : '';
    if ($from === '' || version_compare($from, '1.7.0', '<')) {
        pasargadcdn_admin_w14();
    }
}

/** SPEC §23 (wave 14) schema + templates; never throws (logged). Idempotent: safe on every activation / upgrade. */
function pasargadcdn_admin_w14(): void
{
    try {
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/TunnelAlerts.php';
        require_once __DIR__ . '/lib/AlertMail.php';
        PasargadCdn\Admin\AlertMail::ensure();
        PasargadCdn\Admin\AlertMail::ensureTemplates();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: 1.7.0 upgrade (alert e-mails) failed: ' . $e->getMessage());
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
    require_once __DIR__ . '/lib/Sharing.php';
    require_once __DIR__ . '/lib/CustomerTransfer.php';
    require_once __DIR__ . '/lib/FeatureEditor.php';
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
    // SPEC §20.3: «دامنه‌های اشتراکی» (members) and its JSON proxy for the client app
    if (in_array($get['page'] ?? '', ['shared', 'sharedapi'], true)) {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/Data.php';
        require_once __DIR__ . '/lib/Sharing.php';
        return PasargadCdn\Admin\Sharing::clientArea($get, array_filter($_POST, 'is_scalar'), strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')), $clientId) ?? [];
    }
    // SPEC §19.3: transfer requests addressed to this client — accept / decline (link of the request e-mail)
    if (($get['page'] ?? '') === 'transfer') {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/Data.php';
        require_once __DIR__ . '/lib/Pages.php';
        require_once __DIR__ . '/lib/Operator.php';
        require_once __DIR__ . '/lib/Transfer.php';
        require_once __DIR__ . '/lib/CustomerTransfer.php';
        PasargadCdn\Admin\Env::loadServerModule();
        return PasargadCdn\Admin\CustomerTransfer::clientArea($get, array_filter($_POST, 'is_scalar'), strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')), $clientId);
    }
    // SPEC §23.10: the public abuse report form + status lookup (no login; off unless the setting «صفحهٔ عمومی گزارش تخلف» is on)
    if (($get['page'] ?? '') === 'abuse') {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/AbusePage.php';
        return PasargadCdn\Admin\AbusePage::clientArea($get, array_filter($_POST, 'is_scalar'), strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')));
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
        'operator' => 'دامنه‌های اپراتور', 'transfer' => 'انتقال دامنه', 'analytics' => 'آنالیتیکس', 'usage' => 'گزارش مصرف', 'resellers' => 'نمایندگان', 'events' => 'رویدادهای امنیتی',
        'status' => 'وضعیت و رخدادها', 'health' => 'سلامت سامانه', 'audit' => 'حسابرسی', 'referrals' => 'معرفی‌ها', 'shares' => 'اشتراک‌ها',
        'releases' => 'عملیات (انتشار، پشتیبان، SLO)', 'abuse' => 'گزارش‌های تخلف', 'settings' => 'تنظیمات و سلامت'];
    $h = '<span class="header"><i class="fas fa-bolt"></i> CDN پاسارگاد</span><ul class="menu" dir="rtl" style="text-align:right">';
    foreach ($items as $page => $label) {
        $h .= '<li><a href="' . $link . '&amp;page=' . $page . '">' . $label . '</a></li>';
    }
    return $h . '</ul>';
}
