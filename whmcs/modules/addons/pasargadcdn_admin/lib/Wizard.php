<?php

namespace PasargadCdn\Admin;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Wizard', false)) {
    return;
}

/**
 * «راه‌اندازی خودکار محصولات»: product group, four unified CDN plans (each includes tunnel / VPN-over-CDN,
 * SPEC §7 — no separate tunnel product) with pricing, server group, «Origin IP» custom field, upgrade paths
 * and the welcome email.
 *
 * Idempotent: everything is looked up before it is created; existing products,
 * prices and the email template are only changed when the admin ticks
 * «به‌روزرسانی». plan() is read-only (preview); apply() runs the same plan in
 * one DB transaction.
 */
final class Wizard
{
    const GROUP_NAME = 'CDN و امنیت وب';
    const SERVER_GROUP_NAME = 'CDN Servers';
    const EMAIL_NAME = 'Pasargad CDN Welcome';
    const EMAIL_EXHAUSTED = 'Pasargad CDN Traffic Exhausted';
    const EMAIL_WARNING = 'Pasargad CDN Traffic Warning';
    const EMAIL_FORECAST = 'Pasargad CDN Traffic Forecast';
    /** Wave 7 (SPEC §15.7): origin-down / back-up e-mails of tunnel services (sent by TunnelAlerts). */
    const EMAIL_TUNNEL_DOWN = 'Pasargad CDN Tunnel Origin Down';
    const EMAIL_TUNNEL_UP = 'Pasargad CDN Tunnel Origin Up';
    /** Wave 7: «بسته‌ی ترافیک افزوده» product add-ons, one per size (WHMCS add-ons carry no configurable options). */
    const ADDON_NAME = 'بسته‌ی ترافیک افزوده';
    const ADDON_SIZES = [10, 50, 100];
    const BILLING = [
        'prepaid' => 'پیش‌پرداخت از کیف پول (پیشنهادی)',
        'overage' => 'فاکتور ترافیک اضافه در پایان ماه',
        'cut' => 'قطع در پایان ترافیک پلن (بدون هزینه اضافه)',
    ];
    const ORIGIN_FIELD = 'Origin IP|IP سرور اصلی (اختیاری)';
    const ORIGIN_REGEX = '/^$|^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/';

    const CYCLES = ['monthly' => 'ماهانه', 'quarterly' => 'سه‌ماهه', 'semiannually' => 'شش‌ماهه', 'annually' => 'سالانه'];
    /** months and discount multiplier used for the default prices */
    const CYCLE_FACTOR = ['monthly' => 1, 'quarterly' => 2.85, 'semiannually' => 5.4, 'annually' => 10];
    const SETUP_COL = ['monthly' => 'msetupfee', 'quarterly' => 'qsetupfee', 'semiannually' => 'ssetupfee',
        'annually' => 'asetupfee', 'biennially' => 'bsetupfee', 'triennially' => 'tsetupfee'];

    /** plan field => configoption number (19 = edge group, a string) */
    const FLAGS = ['ssl' => 3, 'waf' => 5, 'ddos' => 6, 'lb' => 7, 'image' => 8, 'customssl' => 9, 'dnssec' => 10, 'tunnel' => 15];
    const NUMS = ['records' => 2, 'rate' => 4, 'page' => 11, 'fw' => 12, 'rl' => 13, 'pools' => 14, 'tpaths' => 16, 'tconn' => 17, 'tmbps' => 18];
    const GROUP_OPTION = 19;
    const EDGE_GROUPS = ['general' => 'عمومی', 'tunnel' => 'تونل'];
    const NUM_MAX = ['bw' => 1000000, 'records' => 100000, 'rate' => 100000, 'page' => 10000, 'fw' => 10000, 'rl' => 10000, 'pools' => 1000,
        'tpaths' => 50, 'tconn' => 1000000, 'tmbps' => 100000];
    /** plan families: upgrade paths are created within a family only. All plans are one family now
     *  (tunnel is included in every CDN plan), but the family plumbing is kept for the upgrade-path grouping. */
    const FAMILIES = ['site' => 'پلن‌های CDN'];

    const FIELD_LABELS = [
        'bw' => 'ترافیک ماهانه (GB)', 'records' => 'رکورد DNS', 'rate' => 'محدودیت درخواست هر IP (req/s)',
        'ssl' => 'SSL رایگان', 'waf' => 'WAF', 'ddos' => 'حفاظت DDoS', 'lb' => 'توزیع بار', 'image' => 'بهینه‌سازی تصویر',
        'customssl' => 'گواهی اختصاصی', 'dnssec' => 'DNSSEC', 'page' => 'قوانین صفحه', 'fw' => 'قوانین فایروال',
        'rl' => 'قوانین محدودیت نرخ', 'pools' => 'استخر توزیع بار', 'tunnel' => 'حالت تونل (VPN)', 'tpaths' => 'مسیر تونل',
        'tconn' => 'اتصال همزمان هر نود', 'tmbps' => 'سقف سرعت اتصال (Mbps)', 'group' => 'گروه نودها',
    ];

    // Tunnel (VPN-over-CDN, SPEC §7) is included in every CDN plan: no separate product, no extra cost —
    // tunnel traffic is billed from the same plan's bandwidth/wallet. Served by the «general» edge group
    // (all nodes). Per-tier limits below scale with the plan; prices/overage are unchanged from the CDN-only plans.
    const PLANS = [
        'basic' => ['title' => 'پایه', 'name' => 'CDN پایه', 'family' => 'site', 'bw' => 100, 'records' => 50, 'rate' => 0, 'ssl' => 1, 'waf' => 0,
            'ddos' => 1, 'lb' => 0, 'image' => 0, 'customssl' => 0, 'dnssec' => 1, 'page' => 3, 'fw' => 5, 'rl' => 1, 'pools' => 0,
            'tunnel' => 1, 'tpaths' => 3, 'tconn' => 300, 'tmbps' => 0, 'group' => 'general'],
        'pro' => ['title' => 'حرفه‌ای', 'name' => 'CDN حرفه‌ای', 'family' => 'site', 'bw' => 500, 'records' => 200, 'rate' => 0, 'ssl' => 1, 'waf' => 1,
            'ddos' => 1, 'lb' => 0, 'image' => 1, 'customssl' => 1, 'dnssec' => 1, 'page' => 10, 'fw' => 20, 'rl' => 5, 'pools' => 0,
            'tunnel' => 1, 'tpaths' => 10, 'tconn' => 2000, 'tmbps' => 0, 'group' => 'general'],
        'business' => ['title' => 'تجاری', 'name' => 'CDN تجاری', 'family' => 'site', 'bw' => 2000, 'records' => 500, 'rate' => 0, 'ssl' => 1, 'waf' => 1,
            'ddos' => 1, 'lb' => 1, 'image' => 1, 'customssl' => 1, 'dnssec' => 1, 'page' => 25, 'fw' => 50, 'rl' => 15, 'pools' => 3,
            'tunnel' => 1, 'tpaths' => 20, 'tconn' => 5000, 'tmbps' => 0, 'group' => 'general'],
        'enterprise' => ['title' => 'سازمانی', 'name' => 'CDN سازمانی', 'family' => 'site', 'bw' => 10000, 'records' => 2000, 'rate' => 0, 'ssl' => 1,
            'waf' => 1, 'ddos' => 1, 'lb' => 1, 'image' => 1, 'customssl' => 1, 'dnssec' => 1, 'page' => 100, 'fw' => 200, 'rl' => 50, 'pools' => 10,
            'tunnel' => 1, 'tpaths' => 30, 'tconn' => 0, 'tmbps' => 0, 'group' => 'general'],
    ];

    /** Default monthly price per plan by currency kind (unchanged — tunnel is included at no extra cost). */
    const BASE_PRICE = [
        'irt' => ['basic' => 150000, 'pro' => 450000, 'business' => 1200000, 'enterprise' => 4500000],
        'irr' => ['basic' => 1500000, 'pro' => 4500000, 'business' => 12000000, 'enterprise' => 45000000],
        'usd' => ['basic' => 5, 'pro' => 15, 'business' => 40, 'enterprise' => 150],
    ];
    const BASE_OVERAGE = ['irt' => 3000, 'irr' => 30000, 'usd' => 0.1];

    // ------------------------------------------------------------------ input

    public static function currencyKind($c): string
    {
        $code = strtoupper(trim((string) ($c->code ?? '')));
        $txt = (string) ($c->prefix ?? '') . (string) ($c->suffix ?? '');
        if ($code === 'IRR' || strpos($txt, 'ریال') !== false) {
            return 'irr';
        }
        if (in_array($code, ['IRT', 'TMN', 'TOM', 'TOMAN'], true) || strpos($txt, 'تومان') !== false) {
            return 'irt';
        }
        return 'usd';
    }

    public static function defaultCurrency(array $currencies)
    {
        foreach ($currencies as $c) {
            if (!empty($c->default)) {
                return $c;
            }
        }
        return $currencies[0] ?? null;
    }

    public static function nice(float $v): float
    {
        if ($v >= 100000) {
            return round($v / 1000) * 1000;
        }
        if ($v >= 1000) {
            return round($v / 100) * 100;
        }
        return round($v, 2);
    }

    /** Default monthly price of $key in currency $c. */
    public static function basePrice(string $key, $c, array $currencies): float
    {
        $kind = self::currencyKind($c);
        $def = self::defaultCurrency($currencies);
        if ($kind === 'usd' && $def && (int) $def->id !== (int) $c->id && (float) $c->rate > 0) {
            // A foreign currency next to a Toman/Rial default: convert with the WHMCS rate.
            $dk = self::currencyKind($def);
            return self::nice(self::BASE_PRICE[$dk][$key] * (float) $c->rate);
        }
        return (float) self::BASE_PRICE[$kind][$key];
    }

    public static function defaultDescription(array $p): string
    {
        $li = [];
        $li[] = $p['bw'] > 0 ? self::fa($p['bw']) . ' گیگابایت ترافیک ماهانه' : 'ترافیک ماهانه نامحدود';
        if (!empty($p['tunnel'])) {
            $li[] = 'تونل VPN پشت CDN برای Xray / V2Ray / sing-box: gRPC، XHTTP، WebSocket، HTTPUpgrade و HTTP/2';
            $li[] = 'تا ' . self::fa($p['tpaths']) . ' مسیر تونل با پیکربندی آماده سرور و کلاینت (لینک و QR)';
            // tmbps is not advertised: the edges cannot enforce a per-stream rate on tunnel traffic yet.
            $li[] = $p['tconn'] > 0 ? 'تا ' . self::fa($p['tconn']) . ' اتصال همزمان روی هر نود' : 'اتصال همزمان نامحدود';
            if (($p['group'] ?? 'general') === 'tunnel') {
                $li[] = 'نودهای اختصاصی تونل داخل ایران با توزیع بار خودکار';
            }
            $li[] = 'آی‌پی سرور شما پنهان می‌ماند؛ صفحه استتار و محدودسازی کشور';
        }
        $li[] = 'تا ' . self::fa($p['records']) . ' رکورد DNS روی نیم‌سرورهای پاسارگاد';
        if ($p['ssl']) {
            $li[] = 'SSL رایگان Let\'s Encrypt (دامنه و wildcard) با تمدید خودکار';
        }
        $sec = [];
        if ($p['waf']) {
            $sec[] = 'فایروال برنامه وب (WAF)';
        }
        if ($p['ddos']) {
            $sec[] = 'حفاظت DDoS و حالت زیر حمله';
        }
        if ($sec) {
            $li[] = implode(' و ', $sec);
        }
        $li[] = self::fa($p['fw']) . ' قانون فایروال، ' . self::fa($p['page']) . ' قانون صفحه، ' . self::fa($p['rl']) . ' قانون محدودیت نرخ';
        if ($p['lb'] && $p['pools'] > 0) {
            $li[] = 'توزیع بار بین چند سرور با ' . self::fa($p['pools']) . ' استخر و بررسی سلامت';
        }
        $extra = [];
        if ($p['image']) {
            $extra[] = 'بهینه‌سازی تصویر';
        }
        if ($p['customssl']) {
            $extra[] = 'گواهی SSL اختصاصی';
        }
        if ($p['dnssec']) {
            $extra[] = 'DNSSEC';
        }
        if ($extra) {
            $li[] = implode('، ', $extra);
        }
        return "<ul>\n<li>" . implode("</li>\n<li>", $li) . "</li>\n</ul>";
    }

    private static function fa($n): string
    {
        return View::n($n);
    }

    /** Form defaults (currencies from tblcurrencies, nameservers from the controller when reachable). */
    public static function defaults(array $currencies): array
    {
        $def = self::defaultCurrency($currencies);
        $kind = $def ? self::currencyKind($def) : 'irt';
        $in = [
            'group_name' => self::GROUP_NAME, 'servergroup' => 'new', 'server_id' => Env::server() ? (int) Env::server()->id : 0,
            'autosetup' => 'payment', 'hidden' => false,
            'billing' => self::currentBilling(), 'overage' => self::currentBilling() === 'overage',
            'overage_price' => (float) self::BASE_OVERAGE[$kind], 'overage_allow' => 100,
            'email' => true, 'email_update' => false, 'update' => false, 'plans' => [],
            'addon' => true, 'addon_sizes' => self::ADDON_SIZES,
        ];
        $existing = self::existingServerGroup();
        if ($existing) {
            $in['servergroup'] = (int) $existing->id;
        }
        $i = 0;
        foreach (self::PLANS as $key => $p) {
            $row = $p;
            $row['enabled'] = true;
            $row['desc'] = self::defaultDescription($p);
            $row['prices'] = [];
            foreach ($currencies as $c) {
                $m = self::basePrice($key, $c, $currencies);
                foreach (self::CYCLE_FACTOR as $cycle => $f) {
                    $row['prices'][(int) $c->id][$cycle] = self::fmt(self::nice($m * $f));
                }
            }
            $in['plans'][$key] = $row;
            $i++;
        }
        return $in;
    }

    public static function fmt(float $v): string
    {
        return rtrim(rtrim(number_format($v, 2, '.', ''), '0'), '.');
    }

    /** Parses the wizard form. @return array [input, errors] */
    public static function fromPost(array $post, array $currencies): array
    {
        $e = [];
        $str = function ($v, int $max) {
            $v = Env::input($v);
            return function_exists('mb_substr') ? mb_substr($v, 0, $max) : substr($v, 0, $max);
        };
        $numv = function ($v) {
            $v = str_replace([',', '٬', ' '], '', strtr(Env::input($v), ['۰' => '0', '۱' => '1', '۲' => '2', '۳' => '3',
                '۴' => '4', '۵' => '5', '۶' => '6', '۷' => '7', '۸' => '8', '۹' => '9', '٫' => '.']));
            return $v;
        };
        $in = [
            'group_name' => $str($post['group_name'] ?? '', 100),
            'servergroup' => ($post['servergroup'] ?? 'new') === 'new' ? 'new' : (int) ($post['servergroup'] ?? 0),
            'server_id' => (int) ($post['server_id'] ?? 0),
            'autosetup' => in_array($post['autosetup'] ?? '', ['payment', 'order', 'on', ''], true) ? (string) $post['autosetup'] : 'payment',
            'hidden' => !empty($post['hidden']),
            'billing' => array_key_exists((string) ($post['billing'] ?? ''), self::BILLING) ? (string) $post['billing'] : 'prepaid',
            'overage' => false,
            'overage_price' => 0.0,
            'overage_allow' => 0,
            'email' => !empty($post['email']),
            'email_update' => !empty($post['email_update']),
            'update' => !empty($post['update']),
            'plans' => [],
            'addon' => !empty($post['addon']),
            'addon_sizes' => self::ADDON_SIZES,
        ];
        // Wave 7: add-on traffic sizes, e.g. "10, 50, 100" (GB, 1..100000, at most 6)
        $rawSizes = trim(str_replace(['،', '-', '/'], ',', (string) Env::input($post['addon_sizes'] ?? '')));
        if ($rawSizes !== '') {
            $sizes = [];
            foreach (explode(',', $rawSizes) as $v) {
                $v = $numv($v);
                if ($v === '') {
                    continue;
                }
                if (!ctype_digit($v) || (int) $v < 1 || (int) $v > 100000) {
                    $sizes = null;
                    break;
                }
                $sizes[(int) $v] = (int) $v;
            }
            if ($sizes === null || !$sizes || count($sizes) > 6) {
                if ($in['addon']) {
                    $e[] = 'اندازه‌های بسته‌ی ترافیک افزوده باید ۱ تا ۶ عدد صحیح (گیگابایت) با کاما جدا باشند؛ مثلاً 10,50,100.';
                }
            } else {
                ksort($sizes);
                $in['addon_sizes'] = array_values($sizes);
            }
        }
        if ($in['group_name'] === '') {
            $e[] = 'نام گروه محصولات را وارد کنید.';
        }
        $in['overage'] = $in['billing'] === 'overage';
        $op = $numv($post['overage_price'] ?? '0');
        if ($in['billing'] !== 'cut' && (!is_numeric($op) || (float) $op < 0 || (float) $op > 1e12)) {
            $e[] = 'قیمت هر گیگابایت ترافیک اضافه باید عددی نامنفی باشد.';
        } elseif ($in['billing'] === 'prepaid' && (float) $op <= 0) {
            $e[] = 'در حالت پیش‌پرداخت، قیمت هر گیگابایت ترافیک اضافه را وارد کنید (بیشتر از صفر).';
        }
        $in['overage_price'] = is_numeric($op) ? max(0.0, (float) $op) : 0.0;
        $oa = $numv($post['overage_allow'] ?? '0');
        if (!ctype_digit($oa) || (int) $oa > 1000) {
            $e[] = 'سقف ترافیک اضافه باید عددی بین ۰ تا ۱۰۰۰ درصد باشد.';
        }
        $in['overage_allow'] = ctype_digit($oa) ? min(1000, (int) $oa) : 0;
        if ($in['servergroup'] === 'new' && !Env::serverById($in['server_id'])) {
            $e[] = 'برای ساخت گروه سرور جدید، سرور CDN را انتخاب کنید.';
        }
        if ($in['servergroup'] !== 'new' && !Capsule::table('tblservergroups')->where('id', $in['servergroup'])->exists()) {
            $e[] = 'گروه سرور انتخاب‌شده وجود ندارد.';
        }
        $any = false;
        foreach (self::PLANS as $key => $defaults) {
            $p = (array) ($post['plan'][$key] ?? []);
            $row = ['title' => $defaults['title'], 'family' => $defaults['family'], 'enabled' => !empty($p['enabled'])];
            $row['name'] = $str($p['name'] ?? '', 100);
            $row['desc'] = Env::input($p['desc'] ?? '');
            if (strlen($row['desc']) > 20000) {
                $e[] = 'توضیحات پلن ' . $defaults['title'] . ' بیش از حد طولانی است.';
            }
            $badNum = [];
            foreach (array_merge(['bw' => 0], self::NUMS) as $f => $_) {
                // tunnel limits may be absent (forms from before tunnel mode): 0
                $v = $numv($p[$f] ?? (in_array($f, ['tpaths', 'tconn', 'tmbps'], true) ? '0' : ''));
                if (!ctype_digit($v) || (int) $v > self::NUM_MAX[$f]) {
                    if ($row['enabled']) {
                        $e[] = 'مقدار «' . self::FIELD_LABELS[$f] . '» در پلن ' . $defaults['title'] . ' باید عدد صحیح بین ۰ و '
                            . View::n(self::NUM_MAX[$f]) . ' باشد.';
                    }
                    $v = '0';
                    $badNum[$f] = true;
                }
                $row[$f] = (int) $v;
            }
            if ($row['records'] < 1) {
                $row['records'] = 1;
            }
            foreach (self::FLAGS as $f => $_) {
                $row[$f] = !empty($p[$f]) ? 1 : 0;
            }
            if (!$row['lb']) {
                $row['pools'] = 0;
            }
            $row['group'] = array_key_exists((string) ($p['group'] ?? ''), self::EDGE_GROUPS) ? (string) $p['group'] : 'general';
            if (!$row['tunnel']) {
                $row['tpaths'] = $row['tconn'] = $row['tmbps'] = 0;
            } elseif ($row['enabled'] && $row['tpaths'] < 1 && empty($badNum['tpaths'])) {
                $e[] = 'پلن ' . $defaults['title'] . ' حالت تونل دارد؛ دست‌کم یک مسیر تونل مجاز کنید.';
            }
            $row['prices'] = [];
            foreach ($currencies as $c) {
                $cid = (int) $c->id;
                $priced = 0;
                foreach (self::CYCLES as $cycle => $label) {
                    $v = $numv($post['price'][$key][$cid][$cycle] ?? '');
                    if ($v === '') {
                        $row['prices'][$cid][$cycle] = '';
                        continue;
                    }
                    if (!is_numeric($v) || (float) $v < 0 || (float) $v > 1e12) {
                        if ($row['enabled']) {
                            $e[] = 'قیمت ' . $label . ' پلن ' . $defaults['title'] . ' (' . $c->code . ') نامعتبر است.';
                        }
                        $row['prices'][$cid][$cycle] = '';
                        continue;
                    }
                    $row['prices'][$cid][$cycle] = self::fmt((float) $v);
                    $priced++;
                }
                if ($row['enabled'] && $priced === 0) {
                    $e[] = 'برای پلن ' . $defaults['title'] . ' دست‌کم یک دوره پرداخت با واحد ' . $c->code . ' قیمت‌گذاری کنید.';
                }
            }
            if ($row['enabled']) {
                $any = true;
                if ($row['name'] === '') {
                    $e[] = 'نام محصول پلن ' . $defaults['title'] . ' را وارد کنید.';
                }
            }
            $in['plans'][$key] = $row;
        }
        if (!$any) {
            $e[] = 'دست‌کم یک پلن را انتخاب کنید.';
        }
        $names = [];
        foreach ($in['plans'] as $row) {
            if ($row['enabled'] && $row['name'] !== '') {
                if (isset($names[$row['name']])) {
                    $e[] = 'نام محصول «' . $row['name'] . '» تکراری است.';
                }
                $names[$row['name']] = true;
            }
        }
        if ($in['billing'] === 'overage') {
            $perMb = self::perMb($in['overage_price']);
            $max = Env::decimalMax('tblproducts', 'overagesbwprice');
            if ($perMb > $max) {
                $e[] = 'قیمت ترافیک اضافه در WHMCS به ازای هر مگابایت ذخیره می‌شود و ستون آن حداکثر ' . View::n($max, 4)
                    . ' را می‌پذیرد؛ یعنی حداکثر ' . View::n(floor($max * 1024)) . ' برای هر گیگابایت. مقدار را کمتر کنید '
                    . '(یا از واحد پول بزرگ‌تر، مثلاً تومان به جای ریال، استفاده کنید).';
            }
        }
        return [$in, array_values(array_unique($e))];
    }

    /** Billing mode saved in the addon settings (prepaid by default). */
    public static function currentBilling(): string
    {
        $m = Env::setting('billing', 'prepaid');
        return array_key_exists($m, self::BILLING) ? $m : 'prepaid';
    }

    /** WHMCS keeps overage prices per MB (4 decimals). */
    public static function perMb(float $perGb): float
    {
        return round($perGb / 1024, 4);
    }

    /**
     * Controller hard cap for a plan: included × (1 + allowance%) in overage-invoice mode;
     * plan GB in prepaid mode (bought blocks are added on top at run time) and in cut mode.
     */
    public static function hardCap(array $p, array $in): int
    {
        $bw = (int) $p['bw'];
        if ($bw <= 0 || !$in['overage']) {
            return $bw;
        }
        return (int) ceil($bw * (100 + (int) $in['overage_allow']) / 100);
    }

    /** configoption1..19 for a plan. */
    public static function configOptions(array $p, array $in): array
    {
        $o = ['configoption1' => (string) self::hardCap($p, $in)];
        foreach (self::NUMS as $f => $n) {
            $o['configoption' . $n] = (string) (int) ($p[$f] ?? 0);
        }
        foreach (self::FLAGS as $f => $n) {
            $o['configoption' . $n] = !empty($p[$f]) ? 'on' : '';
        }
        $o['configoption' . self::GROUP_OPTION] = ($p['group'] ?? 'general') === 'tunnel' ? 'tunnel' : 'general';
        ksort($o, SORT_NATURAL);
        return $o;
    }

    // ------------------------------------------------------------------ lookups

    public static function existingServerGroup()
    {
        try {
            $named = Capsule::table('tblservergroups')->where('name', self::SERVER_GROUP_NAME)->first();
            if ($named) {
                return $named;
            }
            $ids = array_map(function ($s) {
                return (int) $s->id;
            }, Env::servers());
            if (!$ids) {
                return null;
            }
            return Capsule::table('tblservergroups as g')->join('tblservergroupsrel as r', 'r.groupid', '=', 'g.id')
                ->whereIn('r.serverid', $ids)->orderBy('g.id')->first(['g.id', 'g.name']);
        } catch (\Throwable $e) {
            return null;
        }
    }

    public static function serverGroups(): array
    {
        try {
            return Capsule::table('tblservergroups')->orderBy('id')->get(['id', 'name'])->all();
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function findGroup(string $name)
    {
        return Capsule::table('tblproductgroups')->where('name', $name)->orderBy('id')->first();
    }

    /** Existing product for a plan: remembered mapping first, then by name. */
    public static function findProduct(string $key, string $name, int $gid)
    {
        $map = (array) Env::kvGet('wizard_pids', []);
        if (!empty($map[$key])) {
            $p = Capsule::table('tblproducts')->where('id', (int) $map[$key])->where('servertype', 'pasargadcdn')->first();
            if ($p) {
                return $p;
            }
        }
        $q = Capsule::table('tblproducts')->where('name', $name)->where('servertype', 'pasargadcdn');
        if ($gid > 0) {
            $p = (clone $q)->where('gid', $gid)->orderBy('id')->first();
            if ($p) {
                return $p;
            }
        }
        return $q->orderBy('id')->first();
    }

    public static function findEmail(string $name = self::EMAIL_NAME)
    {
        return Capsule::table('tblemailtemplates')->where('name', $name)->where('type', 'product')
            ->where(function ($q) {
                $q->where('language', '')->orWhereNull('language');
            })->orderBy('id')->first();
    }

    public static function originField(int $pid)
    {
        return Capsule::table('tblcustomfields')->where('type', 'product')->where('relid', $pid)
            ->where(function ($q) {
                $q->where('fieldname', 'Origin IP')->orWhere('fieldname', 'like', 'Origin IP|%');
            })->first();
    }

    // ------------------------------------------------------------------ email

    public static function nameservers(): array
    {
        try {
            $r = Env::api(8)->get('/api/v1/ping');
            $ns = array_values(array_filter((array) ($r['nameservers'] ?? []), 'is_string'));
            if ($ns) {
                return $ns;
            }
        } catch (\Throwable $e) {
            // fall back below
        }
        return Env::DEFAULT_NS;
    }

    /** name => [subject, HTML body] of the templates the wizard manages. */
    public static function templates(array $ns): array
    {
        // Branded RTL wrapper: a «پاسارگاد سی‌دی‌ان / پاسارگاد میزبان» header, the message, then a
        // footer that always names the affected service domain, and the WHMCS signature.
        $wrap = function (string $inner, string $accent = '#1d5fd6') {
            return '<div dir="rtl" style="text-align:right;font-family:Tahoma,Arial,sans-serif;line-height:1.9;font-size:14px;color:#1f2933">' . "\n"
                . '<div style="border-right:4px solid ' . $accent . ';padding:2px 12px;margin:0 0 14px">'
                . '<div style="font-size:16px;font-weight:bold;color:' . $accent . '">پاسارگاد سی‌دی‌ان</div>'
                . '<div style="font-size:12px;color:#7b8794">شبکه توزیع محتوا و امنیت وب پاسارگاد میزبان</div></div>' . "\n"
                . $inner . "\n"
                . '<p style="margin-top:16px;font-size:12px;color:#7b8794">این پیام درباره سرویس CDN دامنه '
                . '<strong dir="ltr">{$service_domain}</strong> فرستاده شده است.</p>'
                . "\n<p>{\$signature}</p>\n</div>";
        };
        // Primary call-to-action: charge the wallet. $manage links to the service (upgrade path).
        $btn = '<p style="margin:14px 0"><a href="{$whmcs_url}clientarea.php?action=addfunds" style="display:inline-block;background:#1d5fd6;'
            . 'color:#fff;padding:9px 20px;border-radius:8px;text-decoration:none;font-weight:bold">شارژ کیف پول</a></p>';
        $manage = '<p style="margin:10px 0"><a href="{$whmcs_url}clientarea.php?action=productdetails&amp;id={$service_id}" '
            . 'style="display:inline-block;background:#eef2ff;color:#1d5fd6;padding:8px 18px;border-radius:8px;text-decoration:none;font-weight:bold">'
            . 'مدیریت سرویس و ارتقای پلن</a></p>';
        return [
            self::EMAIL_NAME => [self::emailSubject(), self::emailBody($ns)],
            self::EMAIL_EXHAUSTED => ['ترافیک سرویس CDN دامنه {$service_domain} تمام شد — برای وصل شدن کیف پول را شارژ کنید', $wrap(
                "<p>{\$client_name} عزیز، سلام</p>\n"
                . "<p>ترافیک این ماه سرویس <strong>{\$service_product_name}</strong> برای دامنه <strong dir=\"ltr\">{\$service_domain}</strong> "
                . "تمام شده است (<strong>{\$cdn_used_gb} از {\$cdn_cap_gb} گیگابایت</strong>) و سایت شما دیگر از طریق CDN پاسارگاد سرو نمی‌شود.</p>\n"
                . "{if \$cdn_limit_reached}<p>سقف خرید خودکار ترافیک این ماه برای سرویس شما پر شده است. برای ادامه سرویس، پلن را ارتقا دهید یا با پشتیبانی پاسارگاد میزبان تماس بگیرید.</p>\n"
                . $manage
                . "{else}<p>ترافیک اضافه به‌صورت بسته‌های <strong>{\$cdn_block_gb} گیگابایتی</strong> (هر بسته {\$cdn_block_price}) خودکار از اعتبار کیف پول شما خریده می‌شود. "
                . "اعتبار فعلی شما {\$cdn_credit} است؛ با شارژ دست‌کم <strong>{\$cdn_needed}</strong> سرویس ظرف چند ثانیه دوباره وصل می‌شود.</p>\n"
                . $btn . "{/if}\n"
                . '<p style="font-size:13px;color:#52606d">برای ترافیک بیشتر در ماه‌های آینده می‌توانید پلن را ارتقا دهید: '
                . '<a href="{$whmcs_url}clientarea.php?action=productdetails&amp;id={$service_id}">مدیریت سرویس</a></p>', '#d64545')],
            self::EMAIL_WARNING => ['هشدار: ترافیک سرویس CDN دامنه {$service_domain} رو به اتمام است', $wrap(
                "<p>{\$client_name} عزیز، سلام</p>\n"
                . "<p>از ترافیک این ماه سرویس <strong>{\$service_product_name}</strong> برای دامنه <strong dir=\"ltr\">{\$service_domain}</strong> "
                . "<strong>{\$cdn_used_gb} از {\$cdn_cap_gb} گیگابایت</strong> مصرف شده است (بیش از ۹۰٪).</p>\n"
                . "{if \$cdn_limit_reached}<p>سقف خرید خودکار ترافیک این ماه پر شده است؛ پس از اتمام ترافیک، سرویس تا ماه بعد قطع می‌شود مگر اینکه پلن را ارتقا دهید.</p>\n"
                . $manage
                . "{else}<p>پس از اتمام، بسته‌های <strong>{\$cdn_block_gb} گیگابایتی</strong> (هر بسته {\$cdn_block_price}) خودکار از کیف پول خریده می‌شوند، "
                . "اما اعتبار فعلی شما ({\$cdn_credit}) برای یک بسته کافی نیست. برای جلوگیری از قطع سرویس، دست‌کم <strong>{\$cdn_needed}</strong> شارژ کنید.</p>\n"
                . $btn . "{/if}", '#de911d')],
            self::EMAIL_FORECAST => ['پیش‌بینی اتمام ترافیک سرویس CDN دامنه {$service_domain}', $wrap(
                "<p>{\$client_name} عزیز، سلام</p>\n"
                . "<p>طبق روند مصرف این ماه، پیش‌بینی می‌شود ترافیک پلن سرویس <strong>{\$service_product_name}</strong> برای دامنه "
                . "<strong dir=\"ltr\">{\$service_domain}</strong> حدود <strong>{\$cdn_days_left} روز دیگر</strong> تمام شود "
                . "(تاکنون <strong>{\$cdn_used_gb} از {\$cdn_plan_gb} گیگابایت</strong> مصرف شده و حدود <strong>{\$cdn_remaining_gb} گیگابایت</strong> باقی مانده است).</p>\n"
                . "<p>برای جلوگیری از قطعی، می‌توانید اعتبار کیف پول را شارژ کنید تا پس از اتمام ترافیک پلن، بسته‌های ترافیک خودکار خریده شوند، "
                . "یا برای صرفه‌جویی در بلندمدت، پلن را به یک پلن با ترافیک بیشتر ارتقا دهید.</p>\n"
                . $btn . $manage, '#1d5fd6')],
            // Wave 7 (SPEC §15.7): tunnel origin down / up (TunnelAlerts, from GET /api/v1/events?type=tunnel)
            self::EMAIL_TUNNEL_DOWN => ['قطعی سرور پشت تونل — {$service_domain}', $wrap(
                "<p>{\$client_name} عزیز، سلام</p>\n"
                . "<p>از <strong>{\$cdn_tunnel_since}</strong> نودهای CDN نمی‌توانند به سرور پشت تونل دامنه <strong dir=\"ltr\">{\$service_domain}</strong> وصل شوند "
                . "(<strong>{\$cdn_tunnel_origin_errors} از {\$cdn_tunnel_attempts}</strong> تلاش اتصال در چند دقیقه‌ی گذشته ناموفق بود). "
                . "در این مدت کاربران VPN شما احتمالاً وصل نمی‌شوند.</p>\n"
                . "{if \$cdn_tunnel_paths}<p>مسیرهای درگیر: <span dir=\"ltr\">{\$cdn_tunnel_paths}</span></p>\n{/if}"
                . "<p><strong>چه چیزهایی را بررسی کنم؟</strong></p>\n<ul>"
                . "<li>سرور خاموش نشده یا ترافیک/اعتبار آن تمام نشده باشد.</li>"
                . "<li>سرویس Xray یا sing-box روشن باشد (مثلاً <span dir=\"ltr\">systemctl status xray</span>).</li>"
                . "<li>پورت سرویس با پورت مسیر در صفحه‌ی تونل یکی باشد و فایروال سرور آی‌پی‌های CDN را نبسته باشد.</li></ul>\n"
                . '<p style="margin:14px 0"><a href="{$whmcs_url}clientarea.php?action=productdetails&amp;id={$service_id}#pcdn=tquality" style="display:inline-block;background:#1d5fd6;'
                . 'color:#fff;padding:9px 20px;border-radius:8px;text-decoration:none;font-weight:bold">مشاهده‌ی کیفیت تونل</a></p>'
                . "<p style=\"font-size:13px;color:#52606d\">وقتی اتصال دوباره برقرار شود، ایمیل دیگری برایتان می‌فرستیم.</p>", '#d64545')],
            self::EMAIL_TUNNEL_UP => ['اتصال دوباره برقرار شد — سرور پشت تونل {$service_domain}', $wrap(
                "<p>{\$client_name} عزیز، سلام</p>\n"
                . "<p>اتصال نودهای CDN به سرور پشت تونل دامنه <strong dir=\"ltr\">{\$service_domain}</strong> از <strong>{\$cdn_tunnel_since}</strong> دوباره برقرار شده است"
                . "{if \$cdn_tunnel_down_for} (مدت قطعی: حدود <strong>{\$cdn_tunnel_down_for}</strong>){/if}. کاربران VPN شما می‌توانند دوباره وصل شوند.</p>\n"
                . "<p style=\"font-size:13px;color:#52606d\">اگر قطعی تکرار می‌شود، گزارش «کیفیت تونل» در ناحیه کاربری مشکل اصلی هر مسیر و راه‌حل آن را نشان می‌دهد.</p>"
                . '<p style="margin:10px 0"><a href="{$whmcs_url}clientarea.php?action=productdetails&amp;id={$service_id}#pcdn=tquality">مشاهده‌ی کیفیت تونل</a></p>', '#13733a')],
        ];
    }

    public static function emailSubject(): string
    {
        return 'سرویس CDN دامنه {$service_domain} فعال شد';
    }

    public static function emailBody(array $ns): string
    {
        $nsHtml = '';
        foreach ($ns as $n) {
            $nsHtml .= '<div dir="ltr" style="font-family:Consolas,monospace;font-size:15px;background:#f1f5f9;padding:4px 10px;'
                . 'margin:4px 0;border-radius:6px;display:inline-block">' . htmlspecialchars($n, ENT_QUOTES, 'UTF-8') . '</div><br>';
        }
        return '<div dir="rtl" style="text-align:right;font-family:Tahoma,Arial,sans-serif;line-height:1.9;font-size:14px">'
            . "\n<p>{\$client_name} عزیز، سلام</p>"
            . "\n<p>سرویس <strong>{\$service_product_name}</strong> برای دامنه <strong dir=\"ltr\">{\$service_domain}</strong> "
            . 'روی CDN پاسارگاد ساخته شد. برای فعال شدن کامل، این سه مرحله را انجام دهید:</p>'
            . "\n<ol>"
            . "\n<li><strong>رکوردهای DNS را کامل کنید.</strong> در ناحیه کاربری، بخش «DNS»، رکوردهای فعلی دامنه "
            . '(ایمیل، زیردامنه‌ها و ...) را وارد یا با فایل زون درون‌ریزی کنید تا پس از تغییر نیم‌سرورها سرویسی قطع نشود.</li>'
            . "\n<li><strong>نیم‌سرورهای دامنه را تغییر دهید.</strong> در پنل ثبت‌کننده دامنه (مثلاً nic.ir)، "
            . 'نیم‌سرورها را فقط به این مقادیر تغییر دهید:<br>' . $nsHtml . '</li>'
            . "\n<li><strong>منتظر تأیید بمانید.</strong> تغییر نیم‌سرور معمولاً چند ساعت (برای دامنه‌های .ir گاهی تا ۲۴ ساعت) "
            . 'طول می‌کشد. پس از تأیید، گواهی SSL رایگان به‌صورت خودکار صادر می‌شود و سایت از طریق CDN سرو می‌شود.</li>'
            . "\n</ol>"
            . "\n<p>مدیریت کامل CDN (DNS، کش، فایروال، SSL و گزارش‌ها): "
            . '<a href="{$whmcs_url}clientarea.php?action=productdetails&amp;id={$service_id}">ورود به ناحیه کاربری</a></p>'
            . "\n<p>{\$signature}</p>\n</div>";
    }

    // ------------------------------------------------------------------ plan (preview) & apply

    /**
     * Read-only description of what apply() will do.
     * @return array list of ['op' => create|update|reuse|skip, 'kind' => ..., 'label' => ..., 'detail' => ...]
     */
    public static function plan(array $in, array $currencies): array
    {
        $steps = [];
        $group = self::findGroup($in['group_name']);
        $gid = $group ? (int) $group->id : 0;
        $steps[] = ['op' => $group ? 'reuse' : 'create', 'kind' => 'گروه محصولات', 'label' => $in['group_name'],
            'detail' => $group ? 'گروه موجود #' . $gid . ' استفاده می‌شود' : 'گروه جدید ساخته می‌شود'];

        if ($in['servergroup'] === 'new') {
            $sg = Capsule::table('tblservergroups')->where('name', self::SERVER_GROUP_NAME)->first();
            $srv = Env::serverById((int) $in['server_id']);
            $steps[] = ['op' => $sg ? 'reuse' : 'create', 'kind' => 'گروه سرور', 'label' => self::SERVER_GROUP_NAME,
                'detail' => ($sg ? 'گروه موجود #' . (int) $sg->id : 'گروه جدید') . ' با سرور ' . ($srv ? $srv->name . ' (#' . (int) $srv->id . ')' : '—')];
        } else {
            $sg = Capsule::table('tblservergroups')->where('id', (int) $in['servergroup'])->first();
            $steps[] = ['op' => 'reuse', 'kind' => 'گروه سرور', 'label' => $sg ? $sg->name : '#' . $in['servergroup'], 'detail' => 'گروه موجود'];
        }

        if ($in['email']) {
            $what = [self::EMAIL_NAME => 'قالب خوش‌آمدگویی فارسی با نیم‌سرورها: ' . implode('، ', self::nameservers()),
                self::EMAIL_EXHAUSTED => 'اطلاع‌رسانی قطع سرویس به‌دلیل اتمام ترافیک و کافی نبودن اعتبار (حداکثر یک بار در ماه)',
                self::EMAIL_WARNING => 'هشدار ۹۰٪ ترافیک وقتی اعتبار برای بسته بعدی کافی نیست',
                self::EMAIL_FORECAST => 'پیش‌بینی اتمام زودهنگام ترافیک پلن بر اساس روند مصرف (حداکثر یک بار در ماه)',
                self::EMAIL_TUNNEL_DOWN => '«قطعی سرور پشت تونل»: وقتی نودها به سرور تونل مشتری وصل نمی‌شوند (هر رویداد یک بار)',
                self::EMAIL_TUNNEL_UP => '«اتصال دوباره برقرار شد»: پس از رفع قطعی سرور پشت تونل'];
            foreach ($what as $name => $desc) {
                $tpl = self::findEmail($name);
                $steps[] = ['op' => $tpl ? ($in['email_update'] ? 'update' : 'skip') : 'create', 'kind' => 'قالب ایمیل',
                    'label' => $name, 'detail' => $tpl ? ($in['email_update'] ? 'متن قالب موجود بازنویسی می‌شود' : 'قالب موجود دست نمی‌خورد') : $desc];
            }
        }
        $steps[] = ['op' => $in['billing'] === self::currentBilling() ? 'skip' : 'update', 'kind' => 'روش صورتحساب ترافیک',
            'label' => self::BILLING[$in['billing']], 'detail' => $in['billing'] === 'prepaid'
                ? 'پس از اتمام ترافیک پلن، بسته‌های ' . View::n((int) Env::setting('block_gb', '10') ?: 10) . ' گیگابایتی از کیف پول مشتری خریده می‌شود؛ اعتبار ناکافی = قطع تا شارژ مجدد. Overage WHMCS برای این محصولات خاموش است.'
                : ($in['billing'] === 'overage' ? 'WHMCS در پایان ماه ترافیک مازاد را فاکتور می‌کند.' : 'سرویس در پایان ترافیک پلن قطع می‌شود؛ هزینه اضافه‌ای گرفته نمی‌شود.')];

        if (!empty($in['addon'])) {
            foreach ($in['addon_sizes'] as $gb) {
                $ex = self::findAddon($gb);
                $steps[] = ['op' => $ex ? ($in['update'] ? 'update' : 'skip') : 'create', 'kind' => 'افزونه', 'label' => self::addonName($gb),
                    'detail' => $ex ? 'افزونه‌ی موجود #' . (int) $ex->id . ($in['update'] ? ' به‌روزرسانی می‌شود' : ' دست نمی‌خورد')
                        : 'یک‌بار پرداخت، پنهان تا قیمت‌گذاری؛ پس از پرداخت فاکتور، سقف ترافیک این ماه سرویس ' . View::n($gb) . ' گیگابایت بالا می‌رود'];
            }
        }
        $perMb = self::perMb($in['overage_price']);
        $found = [];
        foreach ($in['plans'] as $key => $p) {
            if (!$p['enabled']) {
                continue;
            }
            $prod = self::findProduct($key, $p['name'], $gid);
            $found[self::familyOf($key)][] = $prod ? (int) $prod->id : 0;
            $cap = self::hardCap($p, $in);
            $detail = self::FIELD_LABELS['bw'] . ': ' . ($p['bw'] > 0 ? View::n($p['bw']) : 'نامحدود');
            if ($in['billing'] === 'prepaid' && $p['bw'] > 0) {
                $detail .= ' — پیش‌پرداخت: هر GB ' . View::n($in['overage_price'], 2) . ' از کیف پول؛ قطع در ' . View::n($cap) . ' GB + ترافیک خریداری‌شده';
            } elseif ($in['overage'] && $p['bw'] > 0) {
                $detail .= ' — ترافیک اضافه هر GB ' . View::n($in['overage_price'], 4) . ' (ذخیره: ' . View::n($perMb, 4) . ' هر MB)'
                    . ' — سقف قطع روی CDN: ' . View::n($cap) . ' GB';
            }
            if (!empty($p['tunnel'])) {
                $detail .= ' — تونل: ' . View::n($p['tpaths']) . ' مسیر، ' . ($p['tconn'] ? View::n($p['tconn']) . ' اتصال هر نود' : 'اتصال نامحدود')
                    . '، ' . ($p['tmbps'] ? View::n($p['tmbps']) . ' Mbps' : 'بدون سقف سرعت') . '، گروه نود ' . ($p['group'] ?? 'general');
            }
            $steps[] = ['op' => $prod ? ($in['update'] ? 'update' : 'skip') : 'create', 'kind' => 'محصول', 'label' => $p['name'],
                'detail' => ($prod ? 'محصول موجود #' . (int) $prod->id . ($in['update'] ? ' به‌روزرسانی می‌شود' : ' دست نمی‌خورد') . ' — ' : '') . $detail,
                'pid' => $prod ? (int) $prod->id : 0];
            $existingPricing = $prod ? Data::pricing([(int) $prod->id])[(int) $prod->id] ?? [] : [];
            foreach ($currencies as $c) {
                $has = isset($existingPricing[(int) $c->id]);
                $op = !$prod || !$has ? 'create' : ($in['update'] ? 'update' : 'skip');
                $parts = [];
                foreach (self::CYCLES as $cycle => $label) {
                    $v = $p['prices'][(int) $c->id][$cycle] ?? '';
                    $parts[] = $label . ': ' . ($v === '' ? 'غیرفعال' : View::n((float) $v, 2));
                }
                $steps[] = ['op' => $op, 'kind' => 'قیمت', 'label' => $p['name'] . ' — ' . $c->code, 'detail' => implode(' · ', $parts)];
            }
            $field = $prod ? self::originField((int) $prod->id) : null;
            $steps[] = ['op' => $field ? 'skip' : 'create', 'kind' => 'فیلد سفارشی', 'label' => 'Origin IP — ' . $p['name'],
                'detail' => $field ? 'از قبل وجود دارد' : 'فیلد متنی اختیاری با اعتبارسنجی IPv4 در فرم سفارش'];
        }
        foreach ($found as $fam => $ids) {
            $n = count($ids);
            if ($n < 2) {
                continue;
            }
            $missing = in_array(0, $ids, true) ? 1 : self::missingPaths($ids);
            $steps[] = ['op' => $missing ? 'create' : 'skip', 'kind' => 'مسیر ارتقا', 'label' => 'ارتقا/تنزل بین ' . View::n($n) . ' پلن — ' . self::FAMILIES[$fam],
                'detail' => 'مسیرهای موجود حفظ و فقط مسیرهای جاافتاده اضافه می‌شوند (' . (Env::hasTable('tblproduct_upgrade_products')
                    ? 'tblproduct_upgrade_products' : 'tblproducts.upgradepackages') . ')'];
        }
        return $steps;
    }

    /** Family of a plan key ('site' | 'tunnel'). */
    public static function familyOf(string $key): string
    {
        return self::PLANS[$key]['family'] ?? 'site';
    }

    /**
     * Runs the plan in one transaction.
     * @return array summary rows ['op', 'kind', 'label', 'link']
     */
    public static function apply(array $in, array $currencies): array
    {
        $ns = $in['email'] ? self::nameservers() : [];
        $summary = [];
        $run = function () use ($in, $currencies, $ns, &$summary) {
            $summary = self::applyInner($in, $currencies, $ns);
        };
        $conn = Capsule::connection();
        $conn->transaction($run);
        $pids = [];
        foreach ($summary as $s) {
            if (!empty($s['plan'])) {
                $pids[$s['plan']] = $s['pid'];
            }
        }
        if ($pids) {
            Env::kvSet('wizard_pids', array_merge((array) Env::kvGet('wizard_pids', []), $pids));
            // per-GB price of prepaid traffic, in the default currency (read by the prepaid engine)
            $prices = (array) Env::kvGet('gb_prices', []);
            foreach ($summary as $s) {
                if (!empty($s['plan']) && ($s['op'] !== 'skip' || !isset($prices[(string) $s['pid']]))) {
                    $prices[(string) $s['pid']] = round((float) $in['overage_price'], 2);
                }
            }
            Env::kvSet('gb_prices', $prices);
        }
        if (Env::setting('billing', '') !== $in['billing']) {
            Env::saveSetting('billing', $in['billing']);
        }
        // Wave 7: lets the cron's add-on pass (cap retries / month rollover) run only where add-ons exist
        if (!empty($in['addon']) && Env::setting('traffic_addon_on', '') !== 'on') {
            Env::saveSetting('traffic_addon_on', 'on');
        }
        return $summary;
    }

    private static function applyInner(array $in, array $currencies, array $ns): array
    {
        $now = date('Y-m-d H:i:s');
        $out = [];

        // product group
        $group = self::findGroup($in['group_name']);
        if ($group) {
            $gid = (int) $group->id;
            $out[] = ['op' => 'reuse', 'kind' => 'گروه محصولات', 'label' => $in['group_name'], 'link' => 'configproducts.php?action=editgroup&ids=' . $gid];
        } else {
            $row = ['name' => $in['group_name'], 'headline' => 'CDN و امنیت وب پاسارگاد میزبان',
                'tagline' => 'سرعت بیشتر و امنیت بالاتر برای سایت شما، با نیم‌سرورها و نودهای داخل ایران',
                'orderfrmtpl' => '', 'disabledgateways' => '', 'hidden' => 0,
                'order' => (int) Capsule::table('tblproductgroups')->max('order') + 1,
                'created_at' => $now, 'updated_at' => $now];
            if (Env::hasColumn('tblproductgroups', 'slug')) {
                $row['slug'] = self::uniqueSlug('cdn');
            }
            $gid = (int) Capsule::table('tblproductgroups')->insertGetId(Env::onlyColumns('tblproductgroups', $row));
            $out[] = ['op' => 'create', 'kind' => 'گروه محصولات', 'label' => $in['group_name'], 'link' => 'configproducts.php?action=editgroup&ids=' . $gid];
        }

        // server group
        if ($in['servergroup'] === 'new') {
            $sg = Capsule::table('tblservergroups')->where('name', self::SERVER_GROUP_NAME)->first();
            if ($sg) {
                $sgid = (int) $sg->id;
                $out[] = ['op' => 'reuse', 'kind' => 'گروه سرور', 'label' => self::SERVER_GROUP_NAME, 'link' => 'configservers.php'];
            } else {
                $sgid = (int) Capsule::table('tblservergroups')->insertGetId(Env::onlyColumns('tblservergroups',
                    ['name' => self::SERVER_GROUP_NAME, 'filltype' => 1, 'created_at' => $now, 'updated_at' => $now]));
                $out[] = ['op' => 'create', 'kind' => 'گروه سرور', 'label' => self::SERVER_GROUP_NAME, 'link' => 'configservers.php'];
            }
            $sid = (int) $in['server_id'];
            if ($sid > 0 && !Capsule::table('tblservergroupsrel')->where('groupid', $sgid)->where('serverid', $sid)->exists()) {
                Capsule::table('tblservergroupsrel')->insert(['groupid' => $sgid, 'serverid' => $sid]);
            }
        } else {
            $sgid = (int) $in['servergroup'];
        }

        // email templates (welcome + the two prepaid traffic notices)
        $emailId = 0;
        if ($in['email']) {
            foreach (self::templates($ns) as $name => [$subject, $body]) {
                $tpl = self::findEmail($name);
                $fields = ['subject' => $subject, 'message' => $body, 'updated_at' => $now];
                if ($tpl) {
                    $id = (int) $tpl->id;
                    if ($in['email_update']) {
                        Capsule::table('tblemailtemplates')->where('id', $id)->update(Env::onlyColumns('tblemailtemplates', $fields));
                    }
                    $op = $in['email_update'] ? 'update' : 'skip';
                } else {
                    $id = (int) Capsule::table('tblemailtemplates')->insertGetId(Env::onlyColumns('tblemailtemplates', $fields + [
                        'type' => 'product', 'name' => $name, 'attachments' => '', 'fromname' => '', 'fromemail' => '',
                        'disabled' => 0, 'custom' => 1, 'language' => '', 'copyto' => '', 'blind_copy_to' => '', 'plaintext' => 0,
                        'created_at' => $now,
                    ]));
                    $op = 'create';
                }
                if ($name === self::EMAIL_NAME) {
                    $emailId = $id;
                }
                $out[] = ['op' => $op, 'kind' => 'قالب ایمیل', 'label' => $name, 'link' => 'configemailtemplates.php?action=edit&id=' . $id];
            }
        }

        // products
        $pids = [];
        $order = 0;
        foreach ($in['plans'] as $key => $p) {
            $order++;
            if (!$p['enabled']) {
                continue;
            }
            $prod = self::findProduct($key, $p['name'], $gid);
            $cols = self::productColumns($p, $in, $gid, $sgid, $emailId, $order);
            if ($prod) {
                $pid = (int) $prod->id;
                if ($in['update']) {
                    // Keep where the admin placed/hid the product; only its CDN settings, text and billing change.
                    $upd = $cols;
                    unset($upd['gid'], $upd['order'], $upd['hidden']);
                    if (!$emailId) {
                        unset($upd['welcomeemail']);
                    }
                    Capsule::table('tblproducts')->where('id', $pid)->update(Env::onlyColumns('tblproducts', $upd));
                    $out[] = ['op' => 'update', 'kind' => 'محصول', 'label' => $p['name'], 'link' => 'configproducts.php?action=edit&id=' . $pid,
                        'plan' => $key, 'pid' => $pid];
                } else {
                    if ($emailId && empty($prod->welcomeemail)) {
                        Capsule::table('tblproducts')->where('id', $pid)->update(['welcomeemail' => $emailId]);
                    }
                    $out[] = ['op' => 'skip', 'kind' => 'محصول', 'label' => $p['name'], 'link' => 'configproducts.php?action=edit&id=' . $pid,
                        'plan' => $key, 'pid' => $pid];
                }
            } else {
                $pid = self::createProduct($p, $in, $cols, $gid, $sgid, $emailId, $order);
                $out[] = ['op' => 'create', 'kind' => 'محصول', 'label' => $p['name'], 'link' => 'configproducts.php?action=edit&id=' . $pid,
                    'plan' => $key, 'pid' => $pid];
            }
            $pids[$key] = $pid;

            // pricing
            foreach ($currencies as $c) {
                $cid = (int) $c->id;
                $row = ['type' => 'product', 'currency' => $cid, 'relid' => $pid];
                $vals = [];
                foreach (self::SETUP_COL as $cycle => $setup) {
                    $v = $p['prices'][$cid][$cycle] ?? '';
                    $vals[$cycle] = $v === '' ? -1.0 : (float) $v;
                    $vals[$setup] = 0.0;
                }
                $existing = Capsule::table('tblpricing')->where($row)->first();
                if (!$existing) {
                    Capsule::table('tblpricing')->insert($row + $vals);
                    $out[] = ['op' => 'create', 'kind' => 'قیمت', 'label' => $p['name'] . ' — ' . $c->code, 'link' => ''];
                } elseif ($in['update']) {
                    Capsule::table('tblpricing')->where('id', $existing->id)->update($vals);
                    $out[] = ['op' => 'update', 'kind' => 'قیمت', 'label' => $p['name'] . ' — ' . $c->code, 'link' => ''];
                } else {
                    $out[] = ['op' => 'skip', 'kind' => 'قیمت', 'label' => $p['name'] . ' — ' . $c->code, 'link' => ''];
                }
            }

            // custom field
            if (!self::originField($pid)) {
                Capsule::table('tblcustomfields')->insert(Env::onlyColumns('tblcustomfields', [
                    'type' => 'product', 'relid' => $pid, 'fieldname' => self::ORIGIN_FIELD, 'fieldtype' => 'text',
                    'description' => 'اختیاری — IP عمومی سرور فعلی سایت (IPv4). اگر وارد کنید، رکوردهای @ و www به‌صورت خودکار ساخته و از طریق CDN پروکسی می‌شوند.',
                    'fieldoptions' => '', 'regexpr' => self::ORIGIN_REGEX, 'adminonly' => '', 'required' => '', 'showorder' => 'on',
                    'showinvoice' => '', 'sortorder' => 0, 'created_at' => $now, 'updated_at' => $now,
                ]));
                $out[] = ['op' => 'create', 'kind' => 'فیلد سفارشی', 'label' => 'Origin IP — ' . $p['name'], 'link' => ''];
            } else {
                $out[] = ['op' => 'skip', 'kind' => 'فیلد سفارشی', 'label' => 'Origin IP — ' . $p['name'], 'link' => ''];
            }
        }

        // upgrade / downgrade paths between the wizard products of the same family (site plans, tunnel plans)
        $byFamily = [];
        foreach ($pids as $key => $pid) {
            $byFamily[self::familyOf($key)][] = $pid;
        }
        foreach ($byFamily as $fam => $ids) {
            if (count($ids) > 1) {
                $added = self::upgradePaths($ids);
                $out[] = ['op' => $added ? 'create' : 'skip', 'kind' => 'مسیر ارتقا', 'label' => View::n($added) . ' مسیر جدید — ' . self::FAMILIES[$fam], 'link' => ''];
            }
        }
        if (!empty($in['addon'])) {
            foreach (self::applyAddons($in, $now) as $row) {
                $out[] = $row;
            }
        }
        return $out;
    }

    // ------------------------------------------------------------------ Wave 7: add-on traffic (SPEC §15.7)

    public static function addonName(int $gb): string
    {
        return self::ADDON_NAME . ' — ' . View::n($gb) . ' گیگابایت';
    }

    /** The wizard's add-on of this size: through the remembered id → GB map first, then by its name. */
    public static function findAddon(int $gb)
    {
        if (!Env::hasTable('tbladdons')) {
            return null;
        }
        foreach ((array) Env::kvGet('traffic_addons', []) as $id => $size) {
            if ((int) $size === $gb) {
                $row = Capsule::table('tbladdons')->where('id', (int) $id)->first();
                if ($row) {
                    return $row;
                }
            }
        }
        return Capsule::table('tbladdons')->where('name', self::addonName($gb))->first();
    }

    /**
     * Creates (or, in update mode, refreshes) one «بسته‌ی ترافیک افزوده» add-on per size: one-time,
     * linked to every CDN product, hidden from the order form until the admin prices it (no pricing
     * rows are written: prices are the admin's). Remembers id → GB in mod_pasargadcdn_settings.
     */
    private static function applyAddons(array $in, string $now): array
    {
        if (!Env::hasTable('tbladdons')) {
            return [['op' => 'skip', 'kind' => 'افزونه', 'label' => self::ADDON_NAME, 'link' => '']];
        }
        $out = [];
        $map = (array) Env::kvGet('traffic_addons', []);
        $packages = implode(',', array_map('intval', Capsule::table('tblproducts')->where('servertype', 'pasargadcdn')->orderBy('id')->pluck('id')->all()));
        foreach ($in['addon_sizes'] as $gb) {
            $gb = (int) $gb;
            $cols = ['packages' => $packages, 'name' => self::addonName($gb),
                'description' => View::n($gb) . ' گیگابایت ترافیک اضافه برای همین ماه سرویس CDN / تونل؛ بلافاصله پس از پرداخت به سقف ترافیک این ماه اضافه می‌شود و به ماه بعد منتقل نمی‌شود.',
                'billingcycle' => 'onetime', 'allowqty' => 0, 'tax' => 1, 'autoactivate' => 'on', 'suspendproduct' => 0,
                'welcomeemail' => 0, 'type' => '', 'module' => '', 'weight' => 0, 'updated_at' => $now];
            $ex = self::findAddon($gb);
            if ($ex) {
                $id = (int) $ex->id;
                if ($in['update']) {
                    Capsule::table('tbladdons')->where('id', $id)->update(Env::onlyColumns('tbladdons', ['packages' => $packages, 'description' => $cols['description'], 'updated_at' => $now]));
                }
                $op = $in['update'] ? 'update' : 'skip';
            } else {
                $id = (int) Capsule::table('tbladdons')->insertGetId(Env::onlyColumns('tbladdons', $cols + ['showorder' => 0, 'hidden' => 1, 'retired' => 0,
                    'downloads' => '', 'autolinkby' => '', 'server_group_id' => 0, 'created_at' => $now]));
                $op = 'create';
            }
            $map[(string) $id] = $gb;
            $out[] = ['op' => $op, 'kind' => 'افزونه', 'label' => self::addonName($gb), 'link' => 'configaddons.php?action=manage&id=' . $id];
        }
        Env::kvSet('traffic_addons', $map);
        return $out;
    }

    public static function productColumns(array $p, array $in, int $gid, int $sgid, int $emailId, int $order): array
    {
        $overage = $in['overage'] && $p['bw'] > 0;
        $cols = [
            'type' => 'other', 'gid' => $gid, 'name' => $p['name'], 'description' => $p['desc'],
            'hidden' => $in['hidden'] ? 1 : 0, 'showdomainoptions' => 1, 'paytype' => 'recurring',
            'autosetup' => $in['autosetup'], 'servertype' => 'pasargadcdn', 'servergroup' => $sgid,
            'welcomeemail' => $emailId, 'order' => $order,
            // "1,diskunit,bwunit": units MB, so limits are MB and prices are per MB (WHMCS convention).
            'overagesenabled' => $overage ? '1,MB,MB' : '',
            'overagesdisklimit' => 0, 'overagesdiskprice' => 0,
            'overagesbwlimit' => $overage ? $p['bw'] * 1024 : 0,
            'overagesbwprice' => $overage ? self::perMb($in['overage_price']) : 0,
            'updated_at' => date('Y-m-d H:i:s'),
        ];
        return $cols + self::configOptions($p, $in);
    }

    private static function createProduct(array $p, array $in, array $cols, int $gid, int $sgid, int $emailId, int $order): int
    {
        $pid = 0;
        if (function_exists('localAPI')) {
            $args = [
                'type' => 'other', 'gid' => $gid, 'name' => $p['name'], 'description' => $p['desc'],
                'hidden' => $in['hidden'], 'showdomainoptions' => true, 'paytype' => 'recurring',
                'autosetup' => $in['autosetup'], 'module' => 'pasargadcdn', 'servergroupid' => $sgid,
                'welcomeemail' => $emailId, 'order' => $order,
            ] + self::configOptions($p, $in);
            $r = Env::localApi('AddProduct', $args);
            if (($r['result'] ?? '') === 'success' && (int) ($r['pid'] ?? 0) > 0) {
                $pid = (int) $r['pid'];
            } else {
                throw new \RuntimeException('ساخت محصول «' . $p['name'] . '» با AddProduct ناموفق بود: ' . ($r['message'] ?? 'خطای نامشخص'));
            }
        } else {
            $pid = (int) Capsule::table('tblproducts')->insertGetId(Env::onlyColumns('tblproducts',
                $cols + ['created_at' => date('Y-m-d H:i:s')]));
        }
        // AddProduct does not cover every column (overage, all config options) — set them all explicitly.
        Capsule::table('tblproducts')->where('id', $pid)->update(Env::onlyColumns('tblproducts', $cols));
        return $pid;
    }

    /** Number of missing upgrade pairs between existing products (read-only). */
    public static function missingPaths(array $pids): int
    {
        $missing = 0;
        if (!Env::hasTable('tblproduct_upgrade_products')) {
            return count($pids) * (count($pids) - 1);
        }
        foreach ($pids as $a) {
            foreach ($pids as $b) {
                if ($a !== $b && !Capsule::table('tblproduct_upgrade_products')->where(['product_id' => $a, 'upgrade_product_id' => $b])->exists()) {
                    $missing++;
                }
            }
        }
        return $missing;
    }

    /** Adds missing upgrade paths between all $pids (both directions). Returns the number added. */
    public static function upgradePaths(array $pids): int
    {
        $pids = array_values(array_unique(array_map('intval', $pids)));
        if (count($pids) < 2) {
            return 0;
        }
        $added = 0;
        if (Env::hasTable('tblproduct_upgrade_products')) {
            foreach ($pids as $a) {
                foreach ($pids as $b) {
                    if ($a === $b) {
                        continue;
                    }
                    $row = ['product_id' => $a, 'upgrade_product_id' => $b];
                    if (!Capsule::table('tblproduct_upgrade_products')->where($row)->exists()) {
                        Capsule::table('tblproduct_upgrade_products')->insert($row);
                        $added++;
                    }
                }
            }
        } elseif (Env::hasColumn('tblproducts', 'upgradepackages')) {
            foreach ($pids as $a) {
                $cur = Capsule::table('tblproducts')->where('id', $a)->value('upgradepackages');
                $list = $cur ? @unserialize((string) $cur, ['allowed_classes' => false]) : [];
                $list = is_array($list) ? array_map('intval', $list) : [];
                $new = $list;
                foreach ($pids as $b) {
                    if ($b !== $a && !in_array($b, $new, true)) {
                        $new[] = $b;
                        $added++;
                    }
                }
                if ($new !== $list) {
                    Capsule::table('tblproducts')->where('id', $a)->update(['upgradepackages' => serialize($new)]);
                }
            }
        }
        return $added;
    }

    private static function uniqueSlug(string $base): string
    {
        $slug = $base;
        $i = 2;
        while (Capsule::table('tblproductgroups')->where('slug', $slug)->exists()) {
            $slug = $base . '-' . $i++;
        }
        return $slug;
    }
}
