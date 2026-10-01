<?php

namespace PasargadCdn;

if (class_exists(__NAMESPACE__ . '\\I18n', false)) {
    return;
}

/**
 * Server-side half of the client app's language (SPEC §16.10).
 *
 * The client app is Persian or English. lang() picks the language of a client-area page from,
 * in order: the viewer's in-app choice (cookie pcdn_lang, set by assets/i18n.js), the WHMCS
 * session language ($_SESSION['Language'], set when the client picks a language), the client's
 * saved language, the WHMCS default language — 'farsi'/'persian' map to fa, 'english' to en and
 * anything else to fa. api.php answers in the language the app sends (X-PCDN-Lang).
 *
 * Messages are written in Persian; tr() returns the English text from EN (keyed by the Persian
 * source, like the app's own dictionary) when the current language is English. Placeholders are
 * sprintf-style (%s). $current stays 'fa' unless a client-facing entry point sets it, so admin
 * pages, cron and the admin addon keep Persian.
 */
class I18n
{
    /** Language of the messages produced in this request: 'fa' | 'en'. */
    public static string $current = 'fa';

    const EN = [
        // ClientApi (api.php answers)
        'دسترسی شما به این سرویس فقط‌خواندنی است؛ برای تغییر تنظیمات از مالک حساب بخواهید دسترسی «مدیریت محصولات» را به شما بدهد.'
            => 'Your access to this service is read-only; to change settings, ask the account owner to grant you the “Manage products” permission.',
        'لطفاً دوباره وارد حساب کاربری شوید.' => 'Please log in to your account again.',
        'درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.' => 'Invalid request; reload the page.',
        'مسیر نامعتبر است.' => 'Invalid path.',
        'سرویس یافت نشد.' => 'Service not found.',
        'این زیرسایت به‌دلیل اتمام اعتبار نمایندگی موقتاً قطع است.' => 'This sub-site is temporarily suspended because the reseller credit ran out.',
        'این سرویس فعال نیست.' => 'This service is not active.',
        'حجم درخواست بیش از حد مجاز است.' => 'The request is too large.',
        'بدنه درخواست باید JSON معتبر باشد.' => 'The request body must be valid JSON.',
        'پارامتر نامعتبر است.' => 'Invalid parameter.',
        'سرور CDN برای این سرویس تنظیم نشده است.' => 'No CDN server is configured for this service.',
        'اتصال به سرور CDN برقرار نشد.' => 'Could not connect to the CDN server.',
        'خطای سرور CDN (HTTP %s)' => 'CDN server error (HTTP %s)',
        'درخواست توسط سرور CDN رد شد (HTTP %s)' => 'The CDN server rejected the request (HTTP %s)',
        'دریافت گواهی از سرور CDN ممکن نشد.' => 'Could not get the certificate from the CDN server.',
        'سرور CDN هنوز گواهی CA اتصال مبدأ را منتشر نکرده است.' => 'The CDN server has not published the origin-pull CA certificate yet.',
        'دریافت گواهی از سرور CDN ممکن نشد (HTTP %s)' => 'Could not get the certificate from the CDN server (HTTP %s)',
        'پاسخ سرور CDN گواهی معتبری نبود.' => 'The CDN server did not return a valid certificate.',
        'عملیات نامعتبر است.' => 'Invalid operation.',
        'یافت نشد.' => 'Not found.',
        'ساخت زیرسایت ناموفق بود.' => 'Sub-site creation failed.',
        'متد مجاز نیست.' => 'Method not allowed.',
        // ApiClient (controller connection; shown in the client app's error screen)
        'اتصال به سرور CDN برقرار نشد' => 'Could not connect to the CDN server',
        'اتصال به سرور CDN برقرار نشد: %s' => 'Could not connect to the CDN server: %s',
        '، ' => ', ',
        // Reseller (sub-site ops of the client app's reseller panel)
        'هیچ سروری از نوع Pasargad CDN تنظیم نشده است.' => 'No Pasargad CDN server is configured.',
        'جدول نمایندگان آماده نیست.' => 'The reseller table is not ready.',
        'حساب شما به‌عنوان نماینده فعال نیست.' => 'Your account is not active as a reseller.',
        'دامنه معتبر نیست.' => 'The domain is not valid.',
        'آی‌پی سرور اصلی (Origin) باید یک IPv4 عمومی معتبر باشد.' => 'The origin server IP must be a valid public IPv4 address.',
        'نام مشتری نهایی را وارد کنید.' => 'Enter the end customer name.',
        'به سقف تعداد سایت‌های مجاز (%s) رسیده‌اید.' => 'You have reached the allowed number of sites (%s).',
        'این دامنه قبلاً به‌عنوان زیرسایت نمایندگی ثبت شده است.' => 'This domain is already registered as a reseller sub-site.',
        'این دامنه به یک سرویس WHMCS تعلق دارد و به‌عنوان زیرسایت نمایندگی قابل ثبت نیست.'
            => 'This domain belongs to a WHMCS service and cannot be registered as a reseller sub-site.',
        'سرور CDN تنظیم نشده است؛ با پشتیبانی تماس بگیرید.' => 'No CDN server is configured; contact support.',
        'ساخت سایت روی کنترلر ناموفق بود: %s' => 'Creating the site on the controller failed: %s',
        'ثبت محلی زیرسایت ناموفق بود: %s' => 'Saving the sub-site locally failed: %s',
        'زیرسایت یافت نشد.' => 'Sub-site not found.',
        'حذف سایت از کنترلر ناموفق بود: %s' => 'Deleting the site from the controller failed: %s',
        'حذف رکورد محلی ناموفق بود: %s' => 'Deleting the local record failed: %s',
        'زیرسایت حذف شد.' => 'Sub-site deleted.',
        'سرور CDN تنظیم نشده است.' => 'No CDN server is configured.',
        // templates/clientarea.tpl
        'برای مدیریت CDN، جاوااسکریپت مرورگر را فعال کنید.' => 'Enable JavaScript in your browser to manage the CDN.',
        'در حال بارگذاری پنل CDN…' => 'Loading the CDN panel…',
    ];

    /** WHMCS language name (or our own code) → 'fa' | 'en'; anything unknown is Persian. */
    public static function map($name): string
    {
        $n = strtolower(trim((string) $name));
        return in_array($n, ['english', 'en'], true) ? 'en' : 'fa';
    }

    /**
     * Language of the client app for this request (see the class comment). $client is the
     * module's clientsdetails array when the caller has it.
     */
    public static function lang(array $client = []): string
    {
        $cookie = strtolower((string) ($_COOKIE['pcdn_lang'] ?? ''));
        if ($cookie === 'fa' || $cookie === 'en') {
            return $cookie;
        }
        foreach ([$_SESSION['Language'] ?? null, $client['language'] ?? null] as $v) {
            if (is_string($v) && trim($v) !== '') {
                return self::map($v);
            }
        }
        try {
            if (class_exists('\WHMCS\Database\Capsule')) {
                $v = \WHMCS\Database\Capsule::table('tblconfiguration')->where('setting', 'Language')->value('value');
                if (is_string($v) && trim($v) !== '') {
                    return self::map($v);
                }
            }
        } catch (\Throwable $e) {
            // no settings table (tests) — Persian
        }
        return 'fa';
    }

    /** $fa in the current language; extra arguments fill %s placeholders. */
    public static function tr(string $fa, ...$args): string
    {
        $s = (self::$current === 'en' && isset(self::EN[$fa])) ? self::EN[$fa] : $fa;
        return $args ? vsprintf($s, $args) : $s;
    }
}
