<?php

namespace PasargadCdn\Admin;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\CartValidator', false)) {
    return;
}

/**
 * Checkout rules for Pasargad CDN products in the WHMCS cart.
 *
 * Cost model: an empty cart costs nothing; a cart without CDN products costs
 * exactly one query (the memoised list of CDN product ids) and no HTTP call.
 * Only carts that contain CDN products run the domain/custom-field queries,
 * and only when every local rule passes is the controller asked (≤ 5 s,
 * fail-open with a logged warning).
 */
final class CartValidator
{
    const CONTROLLER_TIMEOUT = 5;

    /** ShoppingCartValidateCheckout */
    public static function checkout(array $cart, array $vars = []): array
    {
        $items = self::cdnItems($cart);
        if (!$items) {
            return [];
        }
        // Growth: free trial — one per order, per client, per e-mail address and per domain, ever.
        $trialErrors = self::trialErrors($items, $vars);
        if ($trialErrors) {
            return $trialErrors;
        }
        $errors = [];
        $seen = [];
        $fields = self::originFieldIds(array_unique(array_column($items, 'pid')));
        $taken = self::existingServices(array_filter(array_map(function ($it) {
            return self::normalize((string) $it['domain']);
        }, $items)));
        $toCheck = [];
        foreach ($items as $it) {
            $label = self::label($it, count($items));
            $d = self::normalize((string) $it['domain']);
            $err = self::domainError($d, (string) $it['domain'], $label);
            if ($err === null && isset($seen[$d])) {
                $err = 'دامنه ' . $d . ' دو بار در سبد خرید برای CDN انتخاب شده است. هر دامنه فقط یک سرویس CDN لازم دارد.';
            }
            if ($err === null && isset($taken[$d])) {
                $err = 'برای دامنه ' . $d . ' از قبل سرویس CDN ثبت شده است (' . self::statusFa($taken[$d]) . '). '
                    . 'برای تغییر پلن از بخش ارتقای سرویس فعلی استفاده کنید یا با پشتیبانی تماس بگیرید.';
            }
            if ($err === null) {
                $err = self::nestedError($d, self::visitor($vars));
            }
            if ($err !== null) {
                $errors[] = $err;
            } else {
                $seen[$d] = true;
                $toCheck[] = $d;
            }
            $ipErr = self::originError($it, $fields, $label);
            if ($ipErr !== null) {
                $errors[] = $ipErr;
            }
        }
        if (!$errors && $toCheck && Env::enabled('cartcheck', true)) {
            $errors = self::controllerCheck($toCheck);
        }
        return array_values(array_unique($errors));
    }

    /**
     * ShoppingCartValidateProductUpdate: early feedback for one cart item
     * (local rules only — no controller call).
     */
    public static function productUpdate(array $cart, int $index, array $postedFields): array
    {
        $item = $cart['products'][$index] ?? null;
        if (!is_array($item) || !Env::isCdnProduct((int) ($item['pid'] ?? 0))) {
            return [];
        }
        $item['index'] = $index;
        $item['pid'] = (int) $item['pid'];
        if ($postedFields) {
            $item['customfields'] = $postedFields + (array) ($item['customfields'] ?? []);
        }
        $errors = [];
        $label = self::label($item);
        $raw = (string) ($item['domain'] ?? '');
        if ($raw !== '') {
            $d = self::normalize($raw);
            $err = self::domainError($d, $raw, $label);
            if ($err === null) {
                $taken = self::existingServices([$d]);
                if (isset($taken[$d])) {
                    $err = 'برای دامنه ' . $d . ' از قبل سرویس CDN ثبت شده است (' . self::statusFa($taken[$d]) . ').';
                } else {
                    $err = self::nestedError($d, self::visitor([]));
                }
            }
            if ($err !== null) {
                $errors[] = $err;
            }
        }
        $ipErr = self::originError($item, self::originFieldIds([$item['pid']]), $label);
        if ($ipErr !== null) {
            $errors[] = $ipErr;
        }
        return $errors;
    }

    // ------------------------------------------------------------------ rules

    /** Cart items whose product uses the pasargadcdn module. */
    public static function cdnItems(array $cart): array
    {
        $products = $cart['products'] ?? [];
        if (!is_array($products) || !$products) {
            return [];
        }
        $out = [];
        foreach ($products as $i => $p) {
            if (!is_array($p) || (int) ($p['pid'] ?? 0) <= 0) {
                continue;
            }
            if (!Env::isCdnProduct((int) $p['pid'])) {
                continue;
            }
            $out[] = ['index' => $i, 'pid' => (int) $p['pid'], 'domain' => (string) ($p['domain'] ?? ''),
                'customfields' => is_array($p['customfields'] ?? null) ? $p['customfields'] : []];
        }
        return $out;
    }

    public static function normalize(string $raw): string
    {
        $d = Env::domain($raw);
        if ($d !== '' && preg_match('/[^\x20-\x7e]/', $d) && function_exists('idn_to_ascii')) {
            $a = defined('INTL_IDNA_VARIANT_UTS46') ? idn_to_ascii($d, 0, INTL_IDNA_VARIANT_UTS46) : idn_to_ascii($d);
            if (is_string($a) && $a !== '') {
                $d = strtolower($a);
            }
        }
        return $d;
    }

    /** null when the (normalised) domain is acceptable. */
    public static function domainError(string $d, string $raw, string $label): ?string
    {
        if (trim($raw) === '' || $d === '') {
            return 'برای ' . $label . ' نام دامنه را وارد کنید (مثلاً example.com).';
        }
        if (filter_var(trim($d, '[]'), FILTER_VALIDATE_IP)) {
            return 'برای ' . $label . ' باید نام دامنه وارد شود، نه آدرس IP.';
        }
        if (!Env::validHostname($d) || strpos($d, '.') === false) {
            // The raw input is not echoed back (cart templates may print errors unescaped).
            return 'دامنه واردشده برای ' . $label . ' معتبر نیست. نام دامنه را بدون http و مسیر وارد کنید (مثلاً example.com).';
        }
        if (self::publicSuffix($d)) {
            return self::tr('«%s» یک پسوند عمومی دامنه است و نمی‌توان آن را به‌عنوان سایت روی CDN ثبت کرد؛ نام کامل دامنه خود را وارد کنید (مثلاً example.ir).', $d);
        }
        foreach (Env::reservedDomains() as $r) {
            if ($d === $r || substr($d, -strlen('.' . $r)) === '.' . $r) {
                return 'دامنه ' . $d . ' متعلق به زیرساخت پاسارگاد میزبان است و نمی‌توان آن را روی CDN ثبت کرد.';
            }
        }
        return null;
    }

    /** Origin IP custom field: optional, but a public IPv4 when given. */
    private static function originError(array $item, array $fields, string $label): ?string
    {
        $fid = $fields[$item['pid']] ?? 0;
        if ($fid <= 0) {
            return null;
        }
        $v = $item['customfields'][$fid] ?? '';
        $v = is_string($v) ? trim(html_entity_decode($v, ENT_QUOTES, 'UTF-8')) : '';
        if ($v === '') {
            return null;
        }
        if (!filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return 'IP سرور اصلی برای ' . $label . ' باید یک آدرس IPv4 معتبر باشد (مثلاً 185.10.20.30).';
        }
        if (!filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return 'IP سرور اصلی برای ' . $label . ' باید یک IP عمومی باشد؛ IP خصوصی یا رزروشده (مثل 192.168.x.x یا 127.0.0.1) قابل استفاده نیست.';
        }
        return null;
    }

    /** pid => custom field id of "Origin IP" (fieldname "Origin IP" or "Origin IP|label"). */
    private static function originFieldIds(array $pids): array
    {
        $pids = array_values(array_filter(array_map('intval', $pids)));
        if (!$pids) {
            return [];
        }
        $out = [];
        try {
            $rows = Capsule::table('tblcustomfields')->where('type', 'product')->whereIn('relid', $pids)
                ->where(function ($q) {
                    $q->where('fieldname', 'Origin IP')->orWhere('fieldname', 'like', 'Origin IP|%');
                })->get(['id', 'relid']);
            foreach ($rows as $r) {
                $out[(int) $r->relid] = (int) $r->id;
            }
        } catch (\Throwable $e) {
            return [];
        }
        return $out;
    }

    /** domain => WHMCS status of live CDN services for these domains (one query). */
    public static function existingServices(array $domains): array
    {
        $domains = array_values(array_unique(array_filter($domains)));
        $pids = Env::cdnProductIds();
        if (!$domains || !$pids) {
            return [];
        }
        $variants = [];
        $ps = self::rulesLoaded();
        foreach ($domains as $d) {
            // C1: the same query also returns the parents / children of each domain (nestedError)
            foreach (array_merge([$d], $ps ? \PasargadCdn\DomainRules::parents($d) : []) as $x) {
                $variants[] = $x;
                $variants[] = 'www.' . $x;
            }
        }
        $out = [];
        self::$related = [];
        try {
            $rows = Capsule::table('tblhosting')->whereIn('packageid', $pids)
                ->where(function ($q) use ($variants, $domains, $ps) {
                    $q->whereIn('domain', $variants);
                    if ($ps) {
                        foreach ($domains as $d) {
                            $q->orWhere('domain', 'like', '%.' . $d . '%');
                        }
                    }
                })
                ->whereNotIn('domainstatus', Env::DEAD_STATUSES)->get(['domain', 'domainstatus', 'userid']);
            foreach ($rows as $r) {
                $n = Env::domain((string) $r->domain);
                if (in_array($n, $domains, true)) {
                    $out[$n] = (string) $r->domainstatus;
                }
                foreach ($domains as $d) {
                    if ($ps && \PasargadCdn\DomainRules::nested($n, $d)) {
                        self::$related[$d][] = ['domain' => $n, 'userid' => (int) ($r->userid ?? 0), 'status' => (string) $r->domainstatus, 'kind' => 'service'];
                    }
                }
            }
        } catch (\Throwable $e) {
            return [];
        }
        return $out;
    }

    /** @var array domain => parent/child rows found by the last existingServices() */
    private static $related = [];

    private static function rulesLoaded(): bool
    {
        return Env::loadServerModule() && class_exists('\\PasargadCdn\\DomainRules');
    }

    private static function publicSuffix(string $d): bool
    {
        return self::rulesLoaded() && \PasargadCdn\DomainRules::isPublicSuffix($d);
    }

    /** Logged-in client of the checkout (0 for a new sign-up). */
    private static function visitor(array $vars): int
    {
        return (int) ($vars['userid'] ?? ($_SESSION['uid'] ?? 0));
    }

    /** C1: a parent / child of another client's live CDN domain (from the existingServices() rows). */
    private static function nestedError(string $d, int $uid): ?string
    {
        if (!self::rulesLoaded()) {
            return null;
        }
        $other = \PasargadCdn\DomainRules::foreignNested($d, $uid, self::$related[$d] ?? []);
        if ($other === null) {
            return null;
        }
        Env::log('checkout: CDN domain ' . $d . ' refused — nested with another client\'s ' . $other, $uid);
        return self::tr('دامنه %s زیردامنه یا دامنه اصلی سایتی است که متعلق به مشتری دیگری روی CDN است و قابل ثبت نیست. اگر مالک دامنه هستید با پشتیبانی تماس بگیرید.', $d);
    }

    /** A checkout message in the visitor's language (lib/I18n.php). */
    private static function tr(string $fa, ...$args): string
    {
        if (!Env::loadServerModule() || !class_exists('\\PasargadCdn\\I18n')) {
            return $args ? vsprintf($fa, $args) : $fa;
        }
        $prev = \PasargadCdn\I18n::$current;
        \PasargadCdn\I18n::$current = \PasargadCdn\I18n::lang();
        $out = \PasargadCdn\I18n::tr($fa, ...$args);
        \PasargadCdn\I18n::$current = $prev;
        return $out;
    }

    /** Asks the controller whether the domains already exist. Fail-open. */
    public static function controllerCheck(array $domains): array
    {
        try {
            Env::loadServerModule();
            $api = Env::api(self::CONTROLLER_TIMEOUT);
        } catch (\Throwable $e) {
            Env::log('checkout check skipped (' . $e->getMessage() . ')');
            return [];
        }
        $paths = [];
        foreach ($domains as $d) {
            $paths[$d] = \PasargadCdn\ApiClient::site($d);
        }
        $res = $api->getMany(array_values($paths));
        $errors = [];
        foreach ($paths as $d => $path) {
            $r = $res[$path] ?? ['code' => 0, 'error' => 'no response'];
            if ($r['code'] === 200) {
                $errors[] = 'دامنه ' . $d . ' از قبل روی CDN پاسارگاد ثبت شده است. اگر مالک این دامنه هستید با پشتیبانی تماس بگیرید.';
            } elseif ($r['code'] !== 404) {
                Env::log('checkout controller check for ' . $d . ' failed (' . ($r['error'] ?: 'HTTP ' . $r['code'])
                    . ') — order allowed (fail-open)');
            }
        }
        return $errors;
    }

    // ------------------------------------------------------------------ growth: free trial

    /**
     * Trial rules for the CDN items of a cart. The client is the logged-in one ($_SESSION['uid'] / $vars['userid']);
     * a new sign-up is identified by the e-mail of the checkout form ($vars['email'] / $_POST['email']).
     * Messages follow the visitor's language (lib/I18n.php). Fail-open on any database error (Trial::hadTrial).
     */
    public static function trialErrors(array $items, array $vars = []): array
    {
        // the wizard mirrors the trial product id into the (memoised) addon settings: no trial → no extra query
        if ((int) Env::setting('trial_pid', '0') <= 0 || !Env::loadServerModule() || !class_exists('\\PasargadCdn\\Trial')) {
            return [];
        }
        $pid = \PasargadCdn\Trial::pid();
        if ($pid <= 0) {
            return [];
        }
        $trials = array_values(array_filter($items, function ($it) use ($pid) {
            return (int) $it['pid'] === $pid;
        }));
        if (!$trials) {
            return [];
        }
        $prev = \PasargadCdn\I18n::$current;
        \PasargadCdn\I18n::$current = \PasargadCdn\I18n::lang();
        $tr = function (string $fa, ...$a) {
            return \PasargadCdn\I18n::tr($fa, ...$a);
        };
        $errors = [];
        if (count($trials) > 1) {
            $errors[] = $tr('در هر سفارش فقط یک سرویس آزمایشی CDN مجاز است.');
        }
        $uid = (int) ($vars['userid'] ?? ($_SESSION['uid'] ?? 0));
        $email = '';
        foreach ([$vars['email'] ?? null, $_POST['email'] ?? null] as $e) {
            if (is_string($e) && trim($e) !== '') {
                $email = Env::input($e);
                break;
            }
        }
        if ($email === '' && $uid > 0) {
            try {
                $email = (string) Capsule::table('tblclients')->where('id', $uid)->value('email');
            } catch (\Throwable $e) {
                $email = '';
            }
        }
        $why = null;
        foreach ($trials as $it) {
            $why = \PasargadCdn\Trial::hadTrial($uid, $email, self::normalize((string) $it['domain']));
            if ($why !== null) {
                break;
            }
        }
        if ($why === 'domain') {
            $errors[] = $tr('برای این دامنه قبلاً از دوره آزمایشی CDN استفاده شده است. برای ادامه یکی از پلن‌های CDN را سفارش دهید.');
        } elseif ($why !== null) {
            $errors[] = $tr('هر مشتری فقط یک بار می‌تواند از دوره آزمایشی رایگان CDN استفاده کند. برای ادامه یکی از پلن‌های CDN را سفارش دهید.');
        }
        \PasargadCdn\I18n::$current = $prev;
        if ($errors) {
            Env::log('checkout: free CDN trial refused (' . ($why ?? 'several in one order') . ')', $uid);
        }
        return $errors;
    }

    // ------------------------------------------------------------------ helpers

    private static function label(array $it, int $count = 1): string
    {
        return 'سرویس CDN' . ($count > 1 ? ' (آیتم ' . ((int) $it['index'] + 1) . ' سبد خرید)' : '');
    }

    private static function statusFa(string $s): string
    {
        $m = ['Active' => 'فعال', 'Suspended' => 'معلق', 'Pending' => 'در انتظار پرداخت/راه‌اندازی', 'Completed' => 'تکمیل‌شده'];
        return $m[$s] ?? $s;
    }

}
