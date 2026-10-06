<?php

namespace PasargadCdn\Admin;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Referrals', false)) {
    return;
}

/**
 * Wave 10 (SPEC §18.5) — referral programme on WHMCS's own credit (no separate wallet). Off by default
 * (addon setting «برنامهٔ معرفی»); every entry point returns at once while it is off.
 *
 *  1. capture (ClientAreaPage hook): `?ref=<code>` on any client-area page (cart.php?ref=…) is kept in the
 *     session and a 30-day cookie `pcdn_ref`;
 *  2. attach (AfterShoppingCartCheckout hook): the new client's FIRST CDN order gets one ledger row
 *     (mod_pasargadcdn_referrals, unique per referred client) — `pending`, or `cancelled` with the
 *     anti-abuse reason: self-referral, same e-mail domain (unless a public mail provider), same signup IP;
 *  3. qualify (InvoicePaid hook): the referred client's first paid invoice with a CDN service line →
 *     `qualified` (qualified_at = now);
 *  4. payout (AfterCronJob, once a day): `qualified` rows older than «X days» (default 7) whose invoice is
 *     still Paid and not refunded → AddCredit (localAPI) to both clients in their own currency →
 *     `paid`; at most «N» rewards per referrer per calendar month (the rest wait for next month);
 *  5. refunds / cancelled invoices before the payout (InvoiceRefunded / InvoiceCancelled hooks and the cron's
 *     re-check) → `cancelled`; the admin can cancel pending / qualified rows by hand.
 * Every state change is a conditional UPDATE (status = old), so parallel crons / hooks never pay twice; the
 * credited_* flags make a retried payout skip the side already credited.
 */
final class Referrals
{
    const COOKIE = 'pcdn_ref';
    const COOKIE_DAYS = 30;
    const CODE_RE = '/^([0-9a-z]{1,8})-([0-9a-f]{8})$/D';
    const BATCH = 200;
    const PUBLIC_DOMAINS = 'gmail.com, googlemail.com, yahoo.com, ymail.com, outlook.com, hotmail.com, live.com, msn.com, icloud.com, me.com, '
        . 'aol.com, mail.com, gmx.com, yandex.com, yandex.ru, protonmail.com, proton.me, zoho.com, chmail.ir, mail.ir';
    const STATUSES = ['pending' => ['در انتظار پرداخت فاکتور', 'warn'], 'qualified' => ['پرداخت‌شده، در انتظار مهلت', 'brand'],
        'paying' => ['در حال پرداخت', 'brand'], 'paid' => ['پاداش داده شد', 'ok'], 'cancelled' => ['لغوشده', 'muted']];
    const REASONS = ['self' => 'معرفی خود', 'same_domain' => 'دامنهٔ ایمیل یکسان', 'same_ip' => 'آی‌پی ثبت‌نام یکسان',
        'refunded' => 'بازپرداخت فاکتور', 'invoice_cancelled' => 'لغو فاکتور', 'invoice_unpaid' => 'فاکتور دیگر پرداخت‌شده نیست',
        'referrer_inactive' => 'حساب معرف غیرفعال', 'referred_inactive' => 'حساب معرفی‌شده غیرفعال', 'admin' => 'لغو توسط مدیر',
        'existing_client' => 'مشتری از قبل سرویس CDN داشت'];

    /** @var int|null tests: fixed clock */
    public static $now = null;
    /** @var array report of the last payout run (tests / admin) */
    public static $report = [];

    public static function now(): int
    {
        return self::$now ?? time();
    }

    // ------------------------------------------------------------------ settings

    /**
     * The cheap gate of every hook: the «برنامهٔ معرفی» setting from the server module's memoised addon settings
     * (the same read the prepaid engine makes, so the cron pays nothing extra while the programme is off).
     */
    public static function on(): bool
    {
        if (!Env::loadServerModule() || !function_exists('pasargadcdn_addon_settings')) {
            return Env::enabled('referral_enabled', false);
        }
        $v = strtolower(trim((string) (\pasargadcdn_addon_settings()['referral_enabled'] ?? '')));
        return in_array($v, ['on', '1', 'yes', 'true'], true);
    }

    public static function enabled(): bool
    {
        return self::on() && Env::hasTable(Env::REFERRALS);
    }

    /** Reward amounts in the settings currency (0 = that side gets nothing). */
    public static function amounts(): array
    {
        $num = function (string $k) {
            $v = str_replace([',', '٬', ' '], '', Env::setting($k, '0'));
            return is_numeric($v) && (float) $v > 0 ? round((float) $v, 2) : 0.0;
        };
        return ['referrer' => $num('referral_reward_referrer'), 'referred' => $num('referral_reward_referred')];
    }

    public static function delayDays(): int
    {
        $v = trim(Env::setting('referral_delay_days', '7'));
        return ctype_digit($v) ? min(365, (int) $v) : 7;
    }

    /** Rewards per referrer per calendar month (0 = unlimited). */
    public static function monthlyCap(): int
    {
        $v = trim(Env::setting('referral_monthly_cap', '5'));
        return ctype_digit($v) ? min(10000, (int) $v) : 5;
    }

    public static function publicDomains(): array
    {
        $raw = Env::setting('referral_public_domains', '');
        $raw = trim($raw) === '' ? self::PUBLIC_DOMAINS : $raw;
        $out = [];
        foreach (preg_split('/[\s,،]+/u', strtolower($raw)) ?: [] as $d) {
            $d = trim($d, " .\t@");
            if ($d !== '' && preg_match('/^[a-z0-9.-]+$/', $d)) {
                $out[$d] = true;
            }
        }
        return $out;
    }

    /** The settings currency row (code from «ارز پاداش», else WHMCS's default currency). */
    public static function currency()
    {
        $code = strtoupper(trim(Env::setting('referral_currency', '')));
        $q = Capsule::table('tblcurrencies');
        $c = $code !== '' ? (clone $q)->where('code', $code)->first() : null;
        return $c ?: Capsule::table('tblcurrencies')->where('default', 1)->first() ?: Capsule::table('tblcurrencies')->orderBy('id')->first();
    }

    /** $amount in the settings currency → the client's currency (WHMCS rates are relative to the default currency). */
    public static function convert(float $amount, int $clientId): float
    {
        if ($amount <= 0) {
            return 0.0;
        }
        $from = self::currency();
        $cid = (int) Capsule::table('tblclients')->where('id', $clientId)->value('currency');
        $to = $cid > 0 ? Capsule::table('tblcurrencies')->where('id', $cid)->first() : null;
        if (!$from || !$to || (int) $from->id === (int) $to->id) {
            return round($amount, 2);
        }
        $rf = (float) $from->rate > 0 ? (float) $from->rate : 1.0;
        $rt = (float) $to->rate > 0 ? (float) $to->rate : 1.0;
        return round($amount / $rf * $rt, 2);
    }

    // ------------------------------------------------------------------ codes

    private static function secret(): string
    {
        $s = Env::kvGet('referral_secret');
        if (!is_string($s) || strlen($s) < 32) {
            $s = bin2hex(random_bytes(24));
            Env::kvSet('referral_secret', $s);
        }
        return $s;
    }

    /** The client's referral code: base36 id + 8 hex of an HMAC (not guessable from the id). */
    public static function code(int $clientId): string
    {
        return base_convert((string) $clientId, 10, 36) . '-' . substr(hash_hmac('sha256', 'ref|' . $clientId, self::secret()), 0, 8);
    }

    /** Client id of a well-formed, genuine code, else 0. */
    public static function parse($code): int
    {
        if (!is_string($code) || !preg_match(self::CODE_RE, strtolower(trim($code)), $m)) {
            return 0;
        }
        $id = (int) base_convert($m[1], 36, 10);
        return $id > 0 && hash_equals(self::code($id), $m[1] . '-' . $m[2]) ? $id : 0;
    }

    /** Public link of a code: <SystemURL>/cart.php?ref=<code> (relative when SystemURL is unknown). */
    public static function link(string $code): string
    {
        $base = '';
        try {
            $base = rtrim((string) Capsule::table('tblconfiguration')->where('setting', 'SystemURL')->value('value'), '/');
        } catch (\Throwable $e) {
            $base = '';
        }
        return ($base !== '' ? $base . '/' : '') . 'cart.php?ref=' . rawurlencode($code);
    }

    // ------------------------------------------------------------------ 1. capture

    /**
     * ClientAreaPage hook: remembers a genuine `ref` (session + 30-day cookie). $setCookie is injectable for
     * tests. Returns the referrer id kept (0 = nothing).
     */
    public static function capture(array $get, ?callable $setCookie = null): int
    {
        if (!isset($get['ref']) || !self::enabled()) {
            return 0;
        }
        $code = strtolower(trim((string) $get['ref']));
        $id = self::parse($code);
        if ($id <= 0) {
            return 0;
        }
        $_SESSION['pcdn_ref'] = $code;
        $set = $setCookie ?: function (string $name, string $value, int $exp) {
            if (!headers_sent()) {
                setcookie($name, $value, ['expires' => $exp, 'path' => '/', 'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
                    'httponly' => true, 'samesite' => 'Lax']);
            }
        };
        $set(self::COOKIE, $code, self::now() + self::COOKIE_DAYS * 86400);
        return $id;
    }

    /** The remembered code (session first, then cookie) or ''. */
    public static function remembered(): string
    {
        foreach ([$_SESSION['pcdn_ref'] ?? null, $_COOKIE[self::COOKIE] ?? null] as $c) {
            if (is_string($c) && self::parse($c) > 0) {
                return strtolower(trim($c));
            }
        }
        return '';
    }

    // ------------------------------------------------------------------ 2. attach to the first CDN order

    /**
     * AfterShoppingCartCheckout hook: one ledger row for the new client's first CDN order. Returns the row
     * status written ('pending' | 'cancelled') or '' when nothing was recorded.
     */
    public static function attach(int $orderId, int $invoiceId, string $code = '', string $ip = ''): string
    {
        if ($orderId <= 0 || !self::enabled()) {
            return '';
        }
        $code = $code !== '' ? $code : self::remembered();
        $referrer = self::parse($code);
        if ($referrer <= 0) {
            return '';
        }
        $order = Capsule::table('tblorders')->where('id', $orderId)->first();
        if (!$order) {
            return '';
        }
        $client = (int) $order->userid;
        $pids = Env::cdnProductIds();
        if (!$pids || !Capsule::table('tblhosting')->where('orderid', $orderId)->where('userid', $client)->whereIn('packageid', $pids)->exists()) {
            return '';   // not a CDN order: the ref stays for a later CDN order
        }
        if (Capsule::table(Env::REFERRALS)->where('referred_id', $client)->exists()) {
            return '';   // once per referred client
        }
        $reason = self::abuse($referrer, $client, $ip !== '' ? $ip : (string) ($order->ipaddress ?? ''));
        if ($reason === '' && Capsule::table('tblhosting')->where('userid', $client)->whereIn('packageid', $pids)->where('orderid', '<>', $orderId)->exists()) {
            $reason = 'existing_client';
        }
        $now = date('Y-m-d H:i:s', self::now());
        $status = $reason === '' ? 'pending' : 'cancelled';
        try {
            Capsule::table(Env::REFERRALS)->insert(['referrer_id' => $referrer, 'referred_id' => $client, 'code' => $code,
                'status' => $status, 'reason' => $reason === '' ? null : $reason, 'order_id' => $orderId, 'invoice_id' => max(0, $invoiceId),
                'signup_ip' => substr(self::clientIp($client) ?: $ip, 0, 45), 'created_at' => $now, 'updated_at' => $now]);
        } catch (\Throwable $e) {
            return '';   // a parallel checkout of the same client won the unique key
        }
        unset($_SESSION['pcdn_ref']);
        Env::log('referral: client #' . $client . ' (order #' . $orderId . ') referred by client #' . $referrer
            . ($reason === '' ? ' — pending until the first CDN invoice is paid' : ' — not rewarded: ' . $reason), $client);
        return $status;
    }

    private static function clientIp(int $client): string
    {
        return Env::hasColumn('tblclients', 'ip') ? (string) Capsule::table('tblclients')->where('id', $client)->value('ip') : '';
    }

    private static function domainOf(string $email): string
    {
        $p = strrpos($email, '@');
        return $p === false ? '' : strtolower(trim(substr($email, $p + 1)));
    }

    /** Anti-abuse reason ('' = fine): same client, same e-mail domain (non-public), same signup IP. */
    public static function abuse(int $referrer, int $client, string $orderIp = ''): string
    {
        if ($referrer === $client) {
            return 'self';
        }
        $r = Capsule::table('tblclients')->where('id', $referrer)->first();
        $c = Capsule::table('tblclients')->where('id', $client)->first();
        if (!$r || !$c) {
            return 'self';
        }
        $dr = self::domainOf((string) $r->email);
        $dc = self::domainOf((string) $c->email);
        if ($dr !== '' && $dr === $dc && !isset(self::publicDomains()[$dr])) {
            return 'same_domain';
        }
        $ipR = self::clientIp($referrer);
        foreach ([self::clientIp($client), $orderIp] as $ip) {
            if ($ipR !== '' && $ip !== '' && $ipR === $ip) {
                return 'same_ip';
            }
        }
        return '';
    }

    // ------------------------------------------------------------------ 3. qualify on the first paid CDN invoice

    /**
     * InvoicePaid (through Prepaid::onInvoicePaid, which already read the invoice lines — $items): a pending row of
     * the invoice's client + a CDN service line on it → qualified. Invoices without a Hosting line cost nothing.
     */
    public static function onInvoicePaid(int $invoiceId, ?array $items = null): bool
    {
        if ($invoiceId <= 0) {
            return false;
        }
        if ($items !== null) {
            $items = array_values(array_filter($items, function ($i) {
                return (string) $i->type === 'Hosting';
            }));
            if (!$items) {
                return false;
            }
        }
        if (!self::enabled()) {
            return false;
        }
        $inv = Capsule::table('tblinvoices')->where('id', $invoiceId)->first(['id', 'userid', 'status']);
        if (!$inv) {
            return false;
        }
        $row = Capsule::table(Env::REFERRALS)->where('referred_id', (int) $inv->userid)->where('status', 'pending')->first();
        if (!$row) {
            return false;
        }
        $pids = Env::cdnProductIds();
        $hosting = $items !== null ? array_map(function ($i) {
            return (int) $i->relid;
        }, $items) : Capsule::table('tblinvoiceitems')->where('invoiceid', $invoiceId)->where('type', 'Hosting')->pluck('relid')->all();
        $cdn = $hosting && $pids ? Capsule::table('tblhosting')->whereIn('id', array_map('intval', $hosting))->where('userid', (int) $inv->userid)
            ->whereIn('packageid', $pids)->exists() : false;
        if (!$cdn) {
            return false;
        }
        $now = date('Y-m-d H:i:s', self::now());
        $n = Capsule::table(Env::REFERRALS)->where('id', (int) $row->id)->where('status', 'pending')
            ->update(['status' => 'qualified', 'invoice_id' => $invoiceId, 'qualified_at' => $now, 'updated_at' => $now]);
        if ($n) {
            Env::log('referral #' . (int) $row->id . ': first CDN invoice #' . $invoiceId . ' paid; reward due after '
                . self::delayDays() . ' days', (int) $inv->userid);
        }
        return (bool) $n;
    }

    // ------------------------------------------------------------------ 5. refunds / cancellations

    /** InvoiceRefunded / InvoiceCancelled hooks: an unpaid-out row on that invoice is cancelled. */
    public static function onInvoiceReversed(int $invoiceId, string $reason = 'refunded'): int
    {
        if ($invoiceId <= 0 || !Env::hasTable(Env::REFERRALS)) {
            return 0;
        }
        $n = Capsule::table(Env::REFERRALS)->where('invoice_id', $invoiceId)->whereIn('status', ['pending', 'qualified'])
            ->update(['status' => 'cancelled', 'reason' => $reason, 'updated_at' => date('Y-m-d H:i:s', self::now())]);
        if ($n) {
            Env::log('referral: reward on invoice #' . $invoiceId . ' cancelled (' . $reason . ')');
        }
        return $n;
    }

    /** Admin «لغو»: pending / qualified rows only. */
    public static function cancel(int $id, int $admin): bool
    {
        $n = Capsule::table(Env::REFERRALS)->where('id', $id)->whereIn('status', ['pending', 'qualified'])
            ->update(['status' => 'cancelled', 'reason' => 'admin', 'cancelled_by' => $admin, 'updated_at' => date('Y-m-d H:i:s', self::now())]);
        if ($n) {
            Env::log('referral #' . $id . ' cancelled by admin #' . $admin);
        }
        return (bool) $n;
    }

    /** Why a qualified row's invoice no longer allows a payout ('' = still fine). */
    private static function invoiceProblem(int $invoiceId): string
    {
        $inv = Capsule::table('tblinvoices')->where('id', $invoiceId)->first(['status']);
        if (!$inv) {
            return 'invoice_unpaid';
        }
        $st = (string) $inv->status;
        if ($st === 'Refunded') {
            return 'refunded';
        }
        if ($st === 'Cancelled') {
            return 'invoice_cancelled';
        }
        if ($st !== 'Paid') {
            return 'invoice_unpaid';
        }
        // a partial refund keeps the invoice Paid but books money out on tblaccounts
        if (Env::hasColumn('tblaccounts', 'amountout')
            && Capsule::table('tblaccounts')->where('invoiceid', $invoiceId)->where('amountout', '>', 0)->exists()) {
            return 'refunded';
        }
        return '';
    }

    // ------------------------------------------------------------------ 4. daily payout

    /** AfterCronJob: at most once per day (KV `referral_cron_day`). Errors are logged, never thrown. */
    public static function onCron(): void
    {
        try {
            if (!self::enabled()) {
                return;
            }
            $day = date('Y-m-d', self::now());
            if (Env::kvGet('referral_cron_day') === $day) {
                return;
            }
            Env::kvSet('referral_cron_day', $day);
            self::run();
        } catch (\Throwable $e) {
            Env::log('referral payout error: ' . $e->getMessage());
        }
    }

    /** One payout pass. @return array ['paid' => [ids], 'cancelled' => [id => reason], 'deferred' => [ids], 'failed' => [id => msg]] */
    public static function run(): array
    {
        $r = ['paid' => [], 'cancelled' => [], 'deferred' => [], 'failed' => []];
        self::$report = $r;
        if (!self::enabled()) {
            return $r;
        }
        $now = self::now();
        $due = date('Y-m-d H:i:s', $now - self::delayDays() * 86400);
        $stale = date('Y-m-d H:i:s', $now - 3600);
        $rows = Capsule::table(Env::REFERRALS)
            ->where(function ($q) use ($due, $stale) {
                $q->where(function ($q2) use ($due) {
                    $q2->where('status', 'qualified')->where('qualified_at', '<=', $due);
                })->orWhere(function ($q2) use ($stale) {
                    $q2->where('status', 'paying')->where('updated_at', '<=', $stale);   // a crashed run: credited_* make it idempotent
                });
            })->orderBy('qualified_at')->orderBy('id')->limit(self::BATCH)->get()->all();
        $amounts = self::amounts();
        $cap = self::monthlyCap();
        $monthStart = date('Y-m-01 00:00:00', $now);
        $stamp = date('Y-m-d H:i:s', $now);
        foreach ($rows as $row) {
            $id = (int) $row->id;
            $why = self::invoiceProblem((int) $row->invoice_id);
            if ($why === '') {
                $ref = Capsule::table('tblclients')->where('id', (int) $row->referrer_id)->first(['status']);
                $cli = Capsule::table('tblclients')->where('id', (int) $row->referred_id)->first(['status']);
                $why = !$ref || in_array((string) $ref->status, ['Closed', 'Fraud'], true) ? 'referrer_inactive'
                    : (!$cli || in_array((string) $cli->status, ['Closed', 'Fraud'], true) ? 'referred_inactive' : '');
            }
            if ($why !== '') {
                if (Capsule::table(Env::REFERRALS)->where('id', $id)->whereIn('status', ['qualified', 'paying'])->where('credited_referrer', 0)->where('credited_referred', 0)
                    ->update(['status' => 'cancelled', 'reason' => $why, 'updated_at' => $stamp])) {
                    $r['cancelled'][$id] = $why;
                    Env::log('referral #' . $id . ' cancelled before payout: ' . $why);
                }
                continue;
            }
            if ($row->status === 'qualified' && $cap > 0 && Capsule::table(Env::REFERRALS)->where('referrer_id', (int) $row->referrer_id)
                    ->where('status', 'paid')->where('paid_at', '>=', $monthStart)->count() >= $cap) {
                $r['deferred'][] = $id;   // monthly cap reached: paid in a later month
                continue;
            }
            // claim (a parallel cron loses here)
            if ($row->status === 'qualified' && !Capsule::table(Env::REFERRALS)->where('id', $id)->where('status', 'qualified')
                    ->update(['status' => 'paying', 'updated_at' => $stamp])) {
                continue;
            }
            $err = '';
            $set = [];
            foreach (['referrer' => (int) $row->referrer_id, 'referred' => (int) $row->referred_id] as $side => $client) {
                if (!empty($row->{'credited_' . $side})) {
                    continue;
                }
                $amt = self::convert($amounts[$side], $client);
                if ($amt > 0) {
                    $res = Env::localApi('AddCredit', ['clientid' => $client, 'amount' => $amt,
                        'description' => $side === 'referrer' ? 'Pasargad CDN referral reward (client #' . (int) $row->referred_id . ')'
                            : 'Pasargad CDN welcome credit (referred by a friend)']);
                    if (($res['result'] ?? '') !== 'success') {
                        $err = (string) ($res['message'] ?? 'AddCredit failed');
                        break;
                    }
                }
                $set['credited_' . $side] = 1;
                $set['amount_' . $side] = $amt;
                // persisted immediately: a retry never credits this side again
                Capsule::table(Env::REFERRALS)->where('id', $id)->update(['credited_' . $side => 1, 'amount_' . $side => $amt, 'updated_at' => $stamp]);
            }
            if ($err !== '') {
                Capsule::table(Env::REFERRALS)->where('id', $id)->update(['status' => 'qualified', 'reason' => substr('credit_failed: ' . $err, 0, 191), 'updated_at' => $stamp]);
                $r['failed'][$id] = $err;
                Env::log('referral #' . $id . ' payout failed (retried tomorrow): ' . $err);
                continue;
            }
            Capsule::table(Env::REFERRALS)->where('id', $id)->update(['status' => 'paid', 'reason' => null, 'paid_at' => $stamp, 'updated_at' => $stamp]);
            $r['paid'][] = $id;
            Env::log('referral #' . $id . ' paid: client #' . (int) $row->referrer_id . ' and client #' . (int) $row->referred_id . ' credited', (int) $row->referrer_id);
        }
        self::$report = $r;
        return $r;
    }

    // ------------------------------------------------------------------ client card / page

    /** Facts of the client's card: code, link, counts by status, credit earned (paid, referrer side). */
    public static function summary(int $clientId): array
    {
        $code = self::code($clientId);
        $counts = ['pending' => 0, 'qualified' => 0, 'paid' => 0, 'cancelled' => 0];
        $earned = 0.0;
        foreach (Capsule::table(Env::REFERRALS)->where('referrer_id', $clientId)->get(['status', 'amount_referrer']) as $row) {
            $st = $row->status === 'paying' ? 'qualified' : (string) $row->status;
            if (isset($counts[$st])) {
                $counts[$st]++;
            }
            if ($row->status === 'paid') {
                $earned += (float) $row->amount_referrer;
            }
        }
        $cur = null;
        $cid = (int) Capsule::table('tblclients')->where('id', $clientId)->value('currency');
        if ($cid > 0) {
            $cur = Capsule::table('tblcurrencies')->where('id', $cid)->first(['code', 'prefix', 'suffix']);
        }
        $amounts = self::amounts();
        return ['code' => $code, 'link' => self::link($code), 'counts' => $counts, 'earned' => round($earned, 2),
            'currency' => $cur ? trim((string) $cur->suffix) ?: (string) $cur->code : '',
            'reward_referrer' => self::convert($amounts['referrer'], $clientId), 'reward_referred' => self::convert($amounts['referred'], $clientId),
            'delay_days' => self::delayDays()];
    }

    const T = [
        'title' => ['معرفی به دوستان', 'Refer a friend'],
        'intro' => ['لینک زیر را برای دوستانتان بفرستید. وقتی اولین فاکتور CDN آن‌ها پرداخت شود و %s روز بگذرد، %s اعتبار به حساب شما و %s به حساب دوستتان اضافه می‌شود.',
            'Share the link below. When your friend\'s first CDN invoice is paid and %s days pass, you get %s credit and your friend gets %s.'],
        'link' => ['لینک معرفی شما', 'Your referral link'],
        'copy' => ['کپی', 'Copy'],
        'pending' => ['در انتظار', 'Pending'],
        'qualified' => ['در انتظار مهلت', 'Waiting period'],
        'paid' => ['پاداش گرفته', 'Rewarded'],
        'earned' => ['اعتبار دریافتی', 'Credit earned'],
        'more' => ['جزئیات', 'Details'],
        'rules' => ['قوانین: معرفی خود، حساب‌های هم‌دامنه یا هم‌آی‌پی پاداش ندارند؛ بازپرداخت فاکتور پیش از پرداخت پاداش آن را لغو می‌کند؛ پاداش به اعتبار حساب شما اضافه می‌شود.',
            'Rules: self-referrals and accounts sharing an e-mail domain or signup IP are not rewarded; a refund before the payout cancels it; rewards are added to your account credit balance.'],
        'off' => ['برنامهٔ معرفی در حال حاضر فعال نیست.', 'The referral programme is not active right now.'],
    ];

    public static function tx(string $k, string $lang): string
    {
        return self::T[$k][$lang === 'en' ? 1 : 0] ?? $k;
    }

    private static function money(float $v, string $cur, string $lang): string
    {
        $s = number_format($v, abs($v - round($v)) < 0.005 ? 0 : 2, '.', ',');
        return ($lang === 'en' ? $s : View::digits($s)) . ($cur !== '' ? ' ' . $cur : '');
    }

    /** Body of the client-area home panel / page (escaped HTML). */
    public static function cardHtml(int $clientId, string $lang = 'fa', bool $full = false): string
    {
        $s = self::summary($clientId);
        $e = function ($v) {
            return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        };
        $n = function ($v) use ($lang) {
            return $lang === 'en' ? (string) $v : View::digits((string) $v);
        };
        $dir = $lang === 'en' ? 'ltr' : 'rtl';
        $h = '<div class="pcdn-ref" dir="' . $dir . '" data-ref-code="' . $e($s['code']) . '">'
            . '<p>' . $e(sprintf(self::tx('intro', $lang), $n($s['delay_days']), self::money($s['reward_referrer'], $s['currency'], $lang),
                self::money($s['reward_referred'], $s['currency'], $lang))) . '</p>'
            . '<label style="display:block;font-weight:600;margin:6px 0 4px">' . $e(self::tx('link', $lang)) . '</label>'
            . '<div style="display:flex;gap:6px;flex-wrap:wrap"><input type="text" readonly dir="ltr" class="form-control pcdn-ref-link" style="flex:1 1 220px;min-width:0" value="'
            . $e($s['link']) . '" onclick="this.select()" aria-label="' . $e(self::tx('link', $lang)) . '"></div>'
            . '<ul class="pcdn-ref-counts" style="display:flex;flex-wrap:wrap;gap:12px;list-style:none;padding:0;margin:10px 0 0">';
        foreach (['pending', 'qualified', 'paid'] as $k) {
            $h .= '<li data-count="' . $k . '"><strong>' . $e($n($s['counts'][$k])) . '</strong> ' . $e(self::tx($k, $lang)) . '</li>';
        }
        $h .= '<li data-earned="1"><strong>' . $e(self::money($s['earned'], $s['currency'], $lang)) . '</strong> ' . $e(self::tx('earned', $lang)) . '</li></ul>';
        if ($full) {
            $h .= '<p style="margin-top:12px;color:#666;font-size:.9em">' . $e(self::tx('rules', $lang)) . '</p>';
        }
        return $h . '</div>';
    }

    // ------------------------------------------------------------------ admin page

    /** «معرفی‌ها»: ledger with status filter, totals and manual cancel. */
    public static function adminPage(array $get): string
    {
        if (!Env::hasTable(Env::REFERRALS)) {
            return View::alert('warn', 'جدول <code>' . View::e(Env::REFERRALS) . '</code> هنوز ساخته نشده است؛ ماژول را یک بار غیرفعال و دوباره فعال کنید یا صفحه را پس از ارتقا دوباره باز کنید.');
        }
        $status = is_string($get['status'] ?? null) && isset(self::STATUSES[$get['status']]) ? $get['status'] : '';
        $amounts = self::amounts();
        $cur = self::currency();
        $code = $cur ? (string) $cur->code : '';
        $settings = (self::enabled() ? View::badge('فعال', 'ok') : View::badge('غیرفعال', 'muted'))
            . ' پاداش معرف: ' . View::e(View::n($amounts['referrer'], 2) . ' ' . $code) . ' · پاداش مشتری جدید: ' . View::e(View::n($amounts['referred'], 2) . ' ' . $code)
            . ' · مهلت: ' . View::e(View::n(self::delayDays())) . ' روز · سقف ماهانهٔ هر معرف: ' . View::e(self::monthlyCap() ? View::n(self::monthlyCap()) : 'نامحدود')
            . ' — <a href="configaddonmods.php#pasargadcdn_admin">تنظیمات ماژول</a>';
        $counts = [];
        foreach (Capsule::table(Env::REFERRALS)->select('status', Capsule::raw('COUNT(*) as n'))->groupBy('status')->get() as $c) {
            $counts[(string) $c->status] = (int) $c->n;
        }
        $kpis = '<div class="pcdna-kpis">';
        foreach (['pending' => 'clock', 'qualified' => 'history', 'paid' => 'check', 'cancelled' => 'x'] as $st => $ic) {
            [$label, $tone] = self::STATUSES[$st];
            $kpis .= View::kpi($ic === 'clock' ? 'history' : $ic, $tone, $label, View::n($counts[$st] ?? 0));
        }
        $kpis .= '</div>';
        $opts = ['' => 'همه'];
        foreach (self::STATUSES as $k => [$label]) {
            $opts[$k] = $label;
        }
        $filter = '<form method="get" action="addonmodules.php" class="pcdna-filters"><input type="hidden" name="module" value="' . View::e(Env::MODULE) . '">'
            . '<input type="hidden" name="page" value="referrals">' . View::select('status', $opts, $status, ' aria-label="وضعیت"')
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary"><span>اعمال</span></button></form>';
        $q = Capsule::table(Env::REFERRALS)->orderBy('id', 'desc')->limit(500);
        if ($status !== '') {
            $q->where('status', $status);
        }
        $rows = $q->get()->all();
        $ids = [];
        foreach ($rows as $r) {
            $ids[(int) $r->referrer_id] = true;
            $ids[(int) $r->referred_id] = true;
        }
        $names = [];
        if ($ids) {
            foreach (Capsule::table('tblclients')->whereIn('id', array_keys($ids))->get(['id', 'firstname', 'lastname', 'companyname']) as $c) {
                $names[(int) $c->id] = trim($c->firstname . ' ' . $c->lastname) . ($c->companyname !== '' ? ' (' . $c->companyname . ')' : '');
            }
        }
        $client = function (int $id) use ($names) {
            return '<a href="clientssummary.php?userid=' . $id . '">#' . View::n($id) . '</a> ' . View::e($names[$id] ?? '—');
        };
        if (!$rows) {
            $table = View::emptyState('معرفی‌ای ثبت نشده است', self::enabled() ? 'پس از اولین سفارش CDN با لینک معرفی، اینجا نمایش داده می‌شود.'
                : 'برنامهٔ معرفی خاموش است؛ از تنظیمات ماژول آن را روشن کنید.', 'users');
        } else {
            $table = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-referrals"><thead><tr><th>#</th><th>معرف</th><th>مشتری جدید</th><th>وضعیت</th>'
                . '<th>سفارش / فاکتور</th><th>پرداخت فاکتور</th><th>پاداش</th><th></th></tr></thead><tbody>';
            foreach ($rows as $r) {
                [$label, $tone] = self::STATUSES[(string) $r->status] ?? [(string) $r->status, 'muted'];
                $reason = (string) ($r->reason ?? '');
                $why = $reason !== '' ? '<div class="pcdna-muted">' . View::e(self::REASONS[$reason] ?? $reason) . '</div>' : '';
                $act = in_array($r->status, ['pending', 'qualified'], true)
                    ? View::postButton(['page' => 'referrals'] + ($status !== '' ? ['status' => $status] : []), 'referral_cancel', ['id' => (int) $r->id], 'لغو', 'pcdna-btn pcdna-btn-sm',
                        'پاداش این معرفی لغو شود؟ این کار برگشت‌پذیر نیست.', 'x') : '';
                $table .= '<tr data-referral="' . (int) $r->id . '" data-status="' . View::e($r->status) . '"><td>' . View::n((int) $r->id) . '</td>'
                    . '<td>' . $client((int) $r->referrer_id) . '</td><td>' . $client((int) $r->referred_id) . '</td>'
                    . '<td>' . View::badge($label, $tone) . $why . '</td>'
                    . '<td>' . ((int) $r->order_id ? '<a href="orders.php?action=view&amp;id=' . (int) $r->order_id . '">#' . View::n((int) $r->order_id) . '</a>' : '—')
                    . ' / ' . ((int) $r->invoice_id ? '<a href="invoices.php?action=edit&amp;id=' . (int) $r->invoice_id . '">#' . View::n((int) $r->invoice_id) . '</a>' : '—') . '</td>'
                    . '<td>' . View::e(View::date($r->qualified_at)) . '</td>'
                    . '<td>' . ($r->status === 'paid' ? View::e(View::n((float) $r->amount_referrer, 2) . ' + ' . View::n((float) $r->amount_referred, 2)) . '<div class="pcdna-muted">'
                        . View::e(View::date($r->paid_at)) . '</div>' : '—') . '</td>'
                    . '<td>' . $act . '</td></tr>';
            }
            $table .= '</tbody></table></div>';
        }
        $run = View::postButton(['page' => 'referrals'], 'referral_run', [], 'اجرای پرداخت‌های سررسیده', 'pcdna-btn pcdna-btn-sm', '', 'refresh');
        return View::alert('info', $settings) . $kpis . $filter . View::card('معرفی‌ها (' . View::n(count($rows)) . ')', $table, $run, 'pcdna-flush', 'users');
    }
}
