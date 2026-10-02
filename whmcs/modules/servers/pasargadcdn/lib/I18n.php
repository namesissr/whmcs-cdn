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
        // SPEC §20 domain sharing (ClientApi shared context, owner page, lib/Shares.php)
        'نقش شما در این دامنه اجازهٔ این کار را نمی‌دهد.' => 'Your role on this domain does not allow this.',
        'عضو یا دعوت پیدا نشد.' => 'Member or invitation not found.',
        'ایمیل نامعتبر است.' => 'Invalid e-mail address.',
        'نقش نامعتبر است.' => 'Invalid role.',
        'نمی‌توانید خودتان را دعوت کنید.' => 'You cannot invite yourself.',
        'این ایمیل عضو تیم حساب خود شماست؛ برای دسترسی او از «مدیریت کاربران» حساب کاربری خود استفاده کنید.' => 'This e-mail belongs to your own account team; give them access with your account\'s user management instead.',
        'این شخص همین حالا عضو این دامنه است؛ نقش او را تغییر دهید.' => 'This person is already a member of this domain; change their role instead.',
        'برای این ایمیل یک دعوت در انتظار هست؛ آن را لغو و دوباره دعوت کنید.' => 'There is already a pending invitation for this e-mail; revoke it and invite again.',
        'حداکثر %s عضو (و دعوت در انتظار) برای هر دامنه مجاز است.' => 'At most %s members (including pending invitations) are allowed per domain.',
        'حداکثر %s دعوت در انتظار مجاز است؛ دعوت‌های قدیمی را لغو کنید.' => 'At most %s pending invitations are allowed; revoke old ones.',
        'ذخیره ممکن نشد؛ دوباره تلاش کنید.' => 'Could not save; please try again.',
        'دعوت پیدا نشد یا قبلاً استفاده شده است.' => 'Invitation not found or already used.',
        'این دعوت منقضی شده است؛ از مالک دامنه بخواهید دوباره دعوت کند.' => 'This invitation has expired; ask the domain owner to invite you again.',
        'این دعوت برای ایمیل دیگری است؛ با حسابی وارد شوید که ایمیل اصلی آن همان ایمیل دعوت است.' => 'This invitation is for another e-mail address; log in with the account whose primary e-mail is the invited address.',
        'نمی‌توانید دعوت دامنهٔ خودتان را بپذیرید.' => 'You cannot accept an invitation to your own domain.',
        'شما همین حالا عضو این دامنه هستید.' => 'You are already a member of this domain.',
        'ظرفیت اعضای این دامنه پر است؛ با مالک دامنه هماهنگ کنید.' => 'This domain has no room for more members; contact the domain owner.',
        'اپراتور پلتفرم' => 'Platform operator',
        'سرویس یافت نشد.' => 'Service not found.',
        'انتقال دامنه توسط مشتری فعال نیست.' => 'Customer domain transfers are not enabled.',
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
        // Wave 10 (SPEC §18): downloads, waiting_room / access body checks, client error reports
        'دریافت فایل از سرور CDN ممکن نشد.' => 'Could not get the file from the CDN server.',
        'فایل دریافتی از سرور CDN بیش از حد بزرگ است.' => 'The file from the CDN server is too large.',
        'فایل دریافتی از سرور CDN معتبر نبود.' => 'The CDN server did not return a valid file.',
        'باید فهرست باشد.' => 'Must be a list.',
        'حداکثر %s مورد مجاز است.' => 'At most %s items are allowed.',
        'دست‌کم یک مسیر لازم است.' => 'At least one path is required.',
        'پیشوند مسیر باید با / شروع شود، بدون * و ? باشد و حداکثر ۲۵۶ نویسه؛ مسیرهای /__pcdn/ رزرو شده‌اند.'
            => 'A path prefix must start with /, contain no * or ? and be at most 256 characters; /__pcdn/ paths are reserved.',
        'آدرس IP یا شبکهٔ نامعتبر است (شبکه حداکثر /8 برای IPv4 و /16 برای IPv6).'
            => 'Invalid IP address or network (networks at most /8 for IPv4 and /16 for IPv6).',
        'ایمیل یا @دامنهٔ نامعتبر است (مثل a@b.com یا @company.com).' => 'Invalid e-mail or @domain (like a@b.com or @company.com).',
        'فیلد ناشناخته است.' => 'Unknown field.',
        'باید روشن یا خاموش باشد.' => 'Must be on or off.',
        'مقدار نامعتبر است.' => 'Invalid value.',
        'باید عدد صحیح بین %s و %s باشد.' => 'Must be a whole number between %s and %s.',
        'متن حداکثر ۵۰۰ نویسه و بدون نویسهٔ کنترلی باشد.' => 'Text must be at most 500 characters without control characters.',
        'شناسهٔ برنامه فقط حروف کوچک انگلیسی، عدد و - باشد (حداکثر ۳۲ نویسه).' => 'The app ID may only contain lowercase letters, digits and - (at most 32 characters).',
        'شناسهٔ برنامه‌ها باید یکتا باشد.' => 'App IDs must be unique.',
        'نام برنامه لازم است (حداکثر ۱۰۰ نویسه، یک خط).' => 'The app name is required (at most 100 characters, one line).',
        'گزارش خطا بیش از حد مجاز است؛ کمی بعد دوباره تلاش کنید.' => 'Too many error reports; try again a little later.',
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
        'این دامنه به یک سرویس ثبت‌شده تعلق دارد و به‌عنوان زیرسایت نمایندگی قابل ثبت نیست.'
            => 'This domain already belongs to a registered service and cannot be registered as a reseller sub-site.',
        'سرور CDN تنظیم نشده است؛ با پشتیبانی تماس بگیرید.' => 'No CDN server is configured; contact support.',
        'ساخت سایت روی کنترلر ناموفق بود: %s' => 'Creating the site on the controller failed: %s',
        'ثبت محلی زیرسایت ناموفق بود: %s' => 'Saving the sub-site locally failed: %s',
        'زیرسایت یافت نشد.' => 'Sub-site not found.',
        'حذف سایت از کنترلر ناموفق بود: %s' => 'Deleting the site from the controller failed: %s',
        'حذف رکورد محلی ناموفق بود: %s' => 'Deleting the local record failed: %s',
        'زیرسایت حذف شد.' => 'Sub-site deleted.',
        'سرور CDN تنظیم نشده است.' => 'No CDN server is configured.',
        // Growth: onboarding / e-mail report opt-in (ClientApi local ops) and reseller white-label
        'ذخیره تنظیمات ممکن نشد؛ دوباره تلاش کنید.' => 'Could not save the setting; try again.',
        'ذخیره برند ممکن نشد؛ دوباره تلاش کنید.' => 'Could not save the brand; try again.',
        'نام برند حداکثر %s نویسه است.' => 'The brand name is limited to %s characters.',
        'لوگو باید تصویر PNG، JPEG، WebP یا GIF و حداکثر ۶۴ کیلوبایت باشد.' => 'The logo must be a PNG, JPEG, WebP or GIF image of at most 64 KB.',
        // Growth: free-trial checkout rules (addon CartValidator, in the visitor's language)
        'در هر سفارش فقط یک سرویس آزمایشی CDN مجاز است.' => 'Only one free CDN trial is allowed per order.',
        'برای این دامنه قبلاً از دوره آزمایشی CDN استفاده شده است. برای ادامه یکی از پلن‌های CDN را سفارش دهید.'
            => 'This domain has already used the free CDN trial. Order one of the CDN plans to continue.',
        'هر مشتری فقط یک بار می‌تواند از دوره آزمایشی رایگان CDN استفاده کند. برای ادامه یکی از پلن‌های CDN را سفارش دهید.'
            => 'Each customer can use the free CDN trial only once. Order one of the CDN plans to continue.',
        // C1: public suffixes and parent/child domains of other clients (checkout + reseller sub-sites)
        '«%s» یک پسوند عمومی دامنه است و نمی‌توان آن را به‌عنوان سایت روی CDN ثبت کرد؛ نام کامل دامنه خود را وارد کنید (مثلاً example.ir).'
            => '“%s” is a public domain suffix and cannot be added to the CDN as a site; enter your full domain name (for example example.ir).',
        'دامنه %s زیردامنه یا دامنه اصلی سایتی است که متعلق به مشتری دیگری روی CDN است و قابل ثبت نیست. اگر مالک دامنه هستید با پشتیبانی تماس بگیرید.'
            => 'The domain %s is a subdomain or parent domain of a site that belongs to another customer on the CDN and cannot be added. If you own the domain, contact support.',
        // C1 checkout answers of the controller's POST /api/v1/domain-check (addon CartValidator)
        'دامنه %s از قبل روی CDN پاسارگاد ثبت شده است. اگر مالک این دامنه هستید با پشتیبانی تماس بگیرید.'
            => 'The domain %s is already registered on Pasargad CDN. If you own this domain, contact support.',
        'دامنه %s برای CDN معتبر نیست؛ نام دامنه را بدون http و مسیر وارد کنید (مثلاً example.com).'
            => 'The domain %s is not valid for the CDN; enter the domain name without http and path (for example example.com).',
        'دامنه %s روی CDN قابل ثبت نیست. برای بررسی با پشتیبانی تماس بگیرید.'
            => 'The domain %s cannot be added to the CDN. Contact support to look into it.',
        // Security review (controller/app/tenancy.py, routes_capi.py) — controller details (translated by controller())
        'این دامنه پسوند عمومی (مثل com یا co.ir) است و نمی‌تواند سایت باشد'
            => 'This domain is a public suffix (like com or co.ir) and cannot be a site',
        'این دامنه قبلاً ثبت شده است' => 'This domain is already registered',
        'این دامنه زیردامنهٔ سایت دیگری است که متعلق به حساب دیگری است؛ زیردامنه‌ها و دامنهٔ والد فقط برای همان مالک قابل ثبت‌اند'
            => 'This domain is a subdomain of another site that belongs to another account; subdomains and parent domains can only be added by the same owner',
        'این دامنه دامنهٔ والدِ سایت دیگری است که متعلق به حساب دیگری است؛ زیردامنه‌ها و دامنهٔ والد فقط برای همان مالک قابل ثبت‌اند'
            => 'This domain is the parent domain of another site that belongs to another account; subdomains and parent domains can only be added by the same owner',
        'سرویس معلق است؛ تا رفع تعلیق فقط خواندن از طریق API مجاز است'
            => 'The service is suspended; until it is unsuspended the API only allows reading',
        // SPEC §16.8 object storage — controller details (translated by controller(), see below)
        'نام باکت باید %s تا %s کاراکتر از حروف کوچک انگلیسی، رقم و - باشد و با حرف یا رقم شروع و تمام شود' => 'The bucket name must be %s to %s characters of lowercase English letters, digits and -, and start and end with a letter or digit',
        'باکت یافت نشد' => 'Bucket not found',
        'فضای ذخیره‌سازی در پلن این سرویس فعال نیست' => 'Object storage is not included in this service\'s plan',
        'باکتی با این نام برای این سرویس وجود دارد' => 'This service already has a bucket with this name',
        'حداکثر %s باکت برای هر سرویس مجاز است' => 'At most %s buckets are allowed per service',
        'فضای ذخیره‌سازی این سرویس پر است؛ باکت جدید ساخته نمی‌شود' => 'This service\'s storage is full; no new bucket can be created',
        'این نام باکت در دسترس نیست' => 'This bucket name is not available',
        'این باکت مبدأ رکورد %s است؛ ابتدا رکورد را تغییر دهید' => 'This bucket is the origin of record %s; change the record first',
        'باکت خالی نیست؛ ابتدا همه فایل‌ها را حذف کنید' => 'The bucket is not empty; delete all of its files first',
        'مبدأ فضای ذخیره‌سازی (storage) فقط برای رکورد پروکسی‌شده (CDN) مجاز است' => 'A storage origin is only allowed on a proxied (CDN) record',
        'برای هر رکورد فقط یکی از pool یا storage را تعیین کنید' => 'Set only one of pool or storage per record',
        'فضای ذخیره‌سازی در پلن شما فعال نیست' => 'Object storage is not included in your plan',
        'باکت %s برای این سرویس وجود ندارد' => 'Bucket %s does not exist for this service',
        'فضای ذخیره‌سازی روی این کنترلر پیکربندی نشده است' => 'Object storage is not configured on this controller',
        'مبدأ فضای ذخیره‌سازی (storage) فقط برای رکوردهای A، AAAA و CNAME پروکسی‌شده مجاز است' => 'A storage origin is only allowed on proxied A, AAAA and CNAME records',
        // SPEC §16.9 edge functions — controller details (translated by controller(), see below)
        'این قابلیت در پلن شما فعال نیست' => 'This feature is not included in your plan',
        'حداکثر %s مورد در پلن شما مجاز است' => 'Your plan allows at most %s items',
        'مجموع کد توابع این سایت حداکثر %s کیلوبایت است' => 'The total code of this site\'s functions is limited to %s KB',
        'مسیر تابع «%s» (%s) با مسیر تونل «%s» (%s) هم‌پوشانی دارد' => 'The route of function “%s” (%s) overlaps tunnel path “%s” (%s)',
        'توابع لبه با تونلی که پاسخ پیش‌فرض آن decoy یا 404 است اجرا نمی‌شوند؛ fallback تونل را origin کنید یا توابع را خاموش کنید'
            => 'Edge functions do not run while the tunnel answers unknown paths with a decoy or 404; set the tunnel fallback to origin or turn functions off',
        'hours باید بین 1 و %s باشد' => 'hours must be between 1 and %s',
        // SPEC §17.2 WAF learning mode — controller details (translated by controller(), see below)
        'پیشنهاد نامعتبر یا منقضی است: %s' => 'Invalid or expired proposal: %s',
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

    /**
     * A controller error detail in the current language (SPEC §16.8 / §16.10): the controller writes its
     * details in Persian; on an English request a known one (an EN key, %s parts matched as wildcards)
     * is answered in English, anything else is returned unchanged (the app shows it after an English
     * lead-in).
     */
    public static function controller(string $detail): string
    {
        if (self::$current !== 'en' || $detail === '') {
            return $detail;
        }
        if (isset(self::EN[$detail])) {
            return self::EN[$detail];
        }
        foreach (self::EN as $fa => $en) {
            if (strpos($fa, '%s') === false) {
                continue;
            }
            $re = '/^' . str_replace('%s', '(.{1,200}?)', preg_quote($fa, '/')) . '$/uD';
            if (preg_match($re, $detail, $m)) {
                array_shift($m);
                return vsprintf($en, $m);
            }
        }
        return $detail;
    }

    /** $fa in the current language; extra arguments fill %s placeholders. */
    public static function tr(string $fa, ...$args): string
    {
        $s = (self::$current === 'en' && isset(self::EN[$fa])) ? self::EN[$fa] : $fa;
        return $args ? vsprintf($s, $args) : $s;
    }
}
