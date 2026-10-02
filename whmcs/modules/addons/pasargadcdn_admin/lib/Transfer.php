<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use PasargadCdn\Transfers;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Transfer', false)) {
    return;
}

/**
 * SPEC §19.2 — «انتقال دامنه»: a complete move of a domain to another owner, reachable from the operator list, the
 * Sites page and the admin service page (module AdminServicesTabFields button). Directions:
 *
 *  - client → client: controller transfer first (customer API keys revoked, integrations paused), then in ONE DB
 *    transaction: tblhosting.userid, the service's tblhostingaddons, the client-keyed module rows of the service
 *    (prepaid top-ups, storage charges, trial registry; the e-mail report opt-in is switched off), the chosen invoices
 *    (unpaid single-service invoices — default on; paid ones — default off), the optional credit transfer
 *    (AddCredit on the new client, AddCredit with a negative amount — or the equivalent tblcredit / tblclients.credit
 *    write when WHMCS refuses a negative amount — on the old one) and the ledger row (new-owner notice). Invoices that
 *    mix other items are never moved; they are listed.
 *  - operator → client: in one DB transaction: AddOrder (product + cycle, payment method, invoice per the option,
 *    no e-mails) → AcceptOrder (autosetup = false, so the module's Create never runs) → UpdateClientProduct (Active,
 *    domain, server, next due date) → controller transfer with reset_billing_anchor (the client never pays for the
 *    operator's traffic) → commit. Rows a WHMCS API call committed on its own are deleted on failure.
 *  - client → operator: controller transfer first, then the ledger row with guard = 1 (the module's Terminate /
 *    Suspend / ChangePackage never touch the site again), UpdateClientProduct status Cancelled, the trial registry
 *    closed and the optional credit to the old client.
 *
 * Every run starts with a preview (controller dry_run + the WHMCS changes) and needs an explicit confirmation; when the
 * WHMCS side fails after the controller step, the DB transaction is rolled back and the site is transferred back.
 * Every step is logged (logActivity with the admin's name; the controller audits site.transfer itself).
 */
final class Transfer
{
    // ------------------------------------------------------------------ controller contract (SPEC §19.2), in one place
    /** POST /api/v1/sites/{d}/transfer {to, reset_billing_anchor, revoke_credentials, pause_integrations, include_related, dry_run}
     *  → {domain, from, to, related: [...], revoked_keys, paused: [...], billing_since, dry_run}; 422 / 409 with a Persian detail */
    const PATH = '/transfer';

    const EMAIL_OLD = 'انتقال دامنه — مبدأ';
    const EMAIL_NEW = 'انتقال دامنه — مقصد';

    const LIVE = ['Active', 'Suspended'];
    const UNPAID = ['Unpaid', 'Draft', 'Payment Pending'];
    /** invoice item types that belong to a service / its add-ons (relid = service id / hosting add-on id) */
    const SVC_TYPES = ['Hosting', 'PromoHosting'];
    const ADDON_TYPES = ['Addon', 'PromoAddon'];
    /** tblpricing column => [AddOrder billingcycle, tblhosting billingcycle, label, months] */
    const CYCLES = [
        'monthly' => ['monthly', 'Monthly', 'ماهانه', 1], 'quarterly' => ['quarterly', 'Quarterly', 'سه‌ماهه', 3],
        'semiannually' => ['semiannually', 'Semi-Annually', 'شش‌ماهه', 6], 'annually' => ['annually', 'Annually', 'سالانه', 12],
        'biennially' => ['biennially', 'Biennially', 'دوساله', 24], 'triennially' => ['triennially', 'Triennially', 'سه‌ساله', 36],
    ];
    /** client-keyed module rows of a service: table => extra columns set from the new client */
    const MODULE_ROWS = ['mod_pasargadcdn_topups' => [], 'mod_pasargadcdn_storage_bills' => [], 'mod_pasargadcdn_trials' => ['email' => 'email']];

    const DIR_LABEL = ['client_client' => 'مشتری ← مشتری', 'operator_client' => 'اپراتور ← مشتری', 'client_operator' => 'مشتری ← اپراتور'];

    /** @var bool AddOrder of an operator → client transfer in progress (the referral checkout hook skips it) */
    public static $creating = false;
    /** @var string|null tests: 'whmcs' (fail inside the WHMCS transaction) | 'after_controller' (op → client) */
    public static $failpoint = null;
    /** @var array tests: the last run's steps */
    public static $steps = [];

    // ------------------------------------------------------------------ source / destination

    /** ['kind' => client|operator, 'domain', 'svc'?, 'site'?, 'client'?] or an error string. */
    public static function source(array $in)
    {
        $sid = (int) ($in['service'] ?? 0);
        if ($sid > 0) {
            $svc = Data::serviceQuery()->where('h.id', $sid)->first(['h.id', 'h.userid', 'h.packageid', 'h.server', 'h.domain', 'h.domainstatus',
                'h.nextduedate', 'h.billingcycle', 'h.amount', 'p.name as product', 'c.firstname', 'c.lastname', 'c.companyname', 'c.email', 'c.currency', 'c.credit']);
            if (!$svc) {
                return 'سرویس CDN #' . $sid . ' پیدا نشد.';
            }
            if (Transfers::guarded($sid)) {
                return 'دامنهٔ سرویس #' . $sid . ' قبلاً به اپراتور منتقل شده است؛ آن را از «دامنه‌های اپراتور» منتقل کنید.';
            }
            $domain = Env::domain((string) $svc->domain);
            if (!Env::validHostname($domain)) {
                return 'دامنهٔ سرویس #' . $sid . ' معتبر نیست.';
            }
            if (!in_array((string) $svc->domainstatus, self::LIVE, true)) {
                return 'فقط سرویس فعال یا معلق قابل انتقال است (وضعیت فعلی: ' . (string) $svc->domainstatus . ').';
            }
            return ['kind' => 'client', 'domain' => $domain, 'svc' => $svc, 'client' => (int) $svc->userid];
        }
        $domain = Env::domain((string) ($in['domain'] ?? ''));
        if ($domain === '') {
            return 'مبدأ انتقال مشخص نیست؛ از «سایت‌ها» یا «دامنه‌های اپراتور» وارد شوید.';
        }
        $site = Operator::site($domain);
        return is_string($site) ? $site : ['kind' => 'operator', 'domain' => strtolower((string) $site['domain']), 'site' => $site, 'client' => 0];
    }

    private static function client(int $id)
    {
        return $id > 0 ? Capsule::table('tblclients')->where('id', $id)->first(['id', 'firstname', 'lastname', 'companyname', 'email', 'currency', 'credit']) : null;
    }

    private static function clientName($c): string
    {
        return $c ? trim(Data::clientName($c)) . ' (#' . (int) $c->id . ')' : '—';
    }

    /** direction for a source + destination ('operator' | client id), or an error string. */
    public static function direction(array $src, string $to)
    {
        if ($to === 'operator') {
            return $src['kind'] === 'client' ? 'client_operator' : 'این دامنه همین حالا متعلق به اپراتور است.';
        }
        $cid = ctype_digit($to) ? (int) $to : 0;
        $c = self::client($cid);
        if (!$c) {
            return 'مشتری مقصد پیدا نشد.';
        }
        if ($src['kind'] === 'client' && $cid === (int) $src['client']) {
            return 'مشتری مقصد همان مالک فعلی است.';
        }
        return $src['kind'] === 'client' ? 'client_client' : 'operator_client';
    }

    // ------------------------------------------------------------------ options

    public static function defaults(string $dir, array $src): array
    {
        return ['move_unpaid' => true, 'move_paid' => false, 'credit' => '0', 'include_related' => false, 'email_old' => true, 'email_new' => true,
            'pid' => 0, 'cycle' => 'monthly', 'nextdue' => date('Y-m-d', strtotime('+1 month')), 'invoice' => true, 'gateway' => '',
            'note' => ''];
    }

    /** Options of a POST, validated for $dir. [opts, errors] */
    public static function options(string $dir, array $post, array $src, int $to): array
    {
        $b = function ($k) use ($post) {
            return in_array((string) ($post[$k] ?? ''), ['1', 'on', 'yes'], true);
        };
        $o = ['move_unpaid' => $b('move_unpaid'), 'move_paid' => $b('move_paid'), 'include_related' => $b('include_related'),
            'email_old' => $b('email_old'), 'email_new' => $b('email_new'), 'invoice' => $b('invoice'),
            'credit' => trim(str_replace([',', '٬', ' '], '', strtr(Env::input($post['credit'] ?? '0'), ['۰' => '0', '۱' => '1', '۲' => '2', '۳' => '3', '۴' => '4',
                '۵' => '5', '۶' => '6', '۷' => '7', '۸' => '8', '۹' => '9', '٫' => '.']))),
            'pid' => (int) ($post['pid'] ?? 0), 'cycle' => Env::input($post['cycle'] ?? 'monthly'), 'nextdue' => trim(Env::input($post['nextdue'] ?? '')),
            'gateway' => Env::input($post['gateway'] ?? ''), 'note' => Env::input($post['note'] ?? '')];
        $e = [];
        if ($o['credit'] === '') {
            $o['credit'] = '0';
        }
        if ($dir !== 'operator_client') {
            if (!preg_match('/^\d{1,12}(\.\d{1,2})?$/D', $o['credit'])) {
                $e[] = 'مبلغ اعتبار باید عدد نامنفی با حداکثر دو رقم اعشار باشد.';
            } elseif ($dir === 'client_client' && (float) $o['credit'] > (float) ($src['svc']->credit ?? 0) + 0.0001) {
                $e[] = 'مبلغ اعتبار بیش از موجودی اعتبار مشتری فعلی (' . View::n((float) ($src['svc']->credit ?? 0), 2) . ') است.';
            }
        } else {
            $o['credit'] = '0';
            if (!Env::isCdnProduct($o['pid'])) {
                $e[] = 'یک محصول CDN برای سرویس جدید انتخاب کنید.';
            }
            if (!isset(self::CYCLES[$o['cycle']])) {
                $e[] = 'دورهٔ پرداخت نامعتبر است.';
            } elseif ($o['pid'] > 0 && !in_array($o['cycle'], array_keys(self::cycles($o['pid'], $to)), true)) {
                $e[] = 'این دورهٔ پرداخت برای محصول انتخاب‌شده قیمت ندارد.';
            }
            $d = \DateTime::createFromFormat('!Y-m-d', $o['nextdue']);
            if (!$d || $d->format('Y-m-d') !== $o['nextdue'] || $o['nextdue'] < date('Y-m-d')) {
                $e[] = 'تاریخ سررسید بعدی باید یک تاریخ معتبر (YYYY-MM-DD) از امروز به بعد باشد.';
            }
            $gws = self::gateways();
            if ($gws && !isset($gws[$o['gateway']])) {
                $e[] = 'روش پرداخت نامعتبر است.';
            }
        }
        if ($dir === 'client_operator') {
            $len = function_exists('mb_strlen') ? mb_strlen($o['note'], 'UTF-8') : strlen($o['note']);
            if ($len > Operator::NOTE_MAX) {
                $e[] = 'یادداشت حداکثر ' . View::n(Operator::NOTE_MAX) . ' نویسه باشد.';
            }
        }
        return [$o, $e];
    }

    /** cycle key => price of product $pid in client $cid's currency (tblpricing; −1 = off). All cycles when unpriced. */
    public static function cycles(int $pid, int $cid): array
    {
        $c = self::client($cid);
        $row = Capsule::table('tblpricing')->where('type', 'product')->where('relid', $pid)
            ->where('currency', $c ? (int) $c->currency : 1)->first();
        if (!$row) {
            return array_map(function () {
                return null;
            }, self::CYCLES);
        }
        $out = [];
        foreach (array_keys(self::CYCLES) as $k) {
            $v = isset($row->$k) ? (float) $row->$k : -1;
            if ($v >= 0) {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    /** Active payment gateways: system name => display name ([] when none are configured). */
    public static function gateways(): array
    {
        try {
            if (!Env::hasTable('tblpaymentgateways')) {
                return [];
            }
            $out = [];
            foreach (Capsule::table('tblpaymentgateways')->where('setting', 'name')->orderBy('order')->get(['gateway', 'value']) as $g) {
                $out[(string) $g->gateway] = (string) $g->value;
            }
            return $out;
        } catch (\Throwable $e) {
            return [];
        }
    }

    // ------------------------------------------------------------------ invoices (client sources)

    /**
     * Invoices of service $sid that belong to client $uid: single-service ones (every line is this service, one of its
     * add-ons, or a line of this service's prepaid / storage ledger) split by status, and mixed ones (also other items).
     * @return array ['unpaid' => [], 'paid' => [], 'other' => [], 'mixed' => []] of invoice rows (+ ->items_total)
     */
    public static function invoices(int $sid, int $uid): array
    {
        $out = ['unpaid' => [], 'paid' => [], 'other' => [], 'mixed' => []];
        $addons = Capsule::table('tblhostingaddons')->where('hostingid', $sid)->pluck('id')->map(function ($v) {
            return (int) $v;
        })->all();
        $ledger = [];
        foreach (['mod_pasargadcdn_topups', 'mod_pasargadcdn_storage_bills'] as $t) {
            if (Env::hasTable($t)) {
                foreach (Capsule::table($t)->where('service_id', $sid)->whereNotNull('invoice_id')->pluck('invoice_id') as $i) {
                    if ((int) $i > 0) {
                        $ledger[(int) $i] = true;
                    }
                }
            }
        }
        $ids = Capsule::table('tblinvoiceitems')->where(function ($w) use ($sid, $addons) {
            $w->where(function ($x) use ($sid) {
                $x->whereIn('type', self::SVC_TYPES)->where('relid', $sid);
            });
            if ($addons) {
                $w->orWhere(function ($x) use ($addons) {
                    $x->whereIn('type', self::ADDON_TYPES)->whereIn('relid', $addons);
                });
            }
        })->distinct()->pluck('invoiceid')->map(function ($v) {
            return (int) $v;
        })->all();
        $ids = array_values(array_unique(array_merge($ids, array_keys($ledger))));
        if (!$ids) {
            return $out;
        }
        $items = [];
        foreach (Capsule::table('tblinvoiceitems')->whereIn('invoiceid', $ids)->get(['invoiceid', 'type', 'relid', 'amount']) as $it) {
            $items[(int) $it->invoiceid][] = $it;
        }
        foreach (Capsule::table('tblinvoices')->whereIn('id', $ids)->where('userid', $uid)->orderBy('id')->get(['id', 'invoicenum', 'date', 'duedate', 'total', 'status']) as $inv) {
            $single = true;
            foreach ($items[(int) $inv->id] ?? [] as $it) {
                $type = (string) $it->type;
                $mine = (in_array($type, self::SVC_TYPES, true) && (int) $it->relid === $sid)
                    || (in_array($type, self::ADDON_TYPES, true) && in_array((int) $it->relid, $addons, true))
                    || (isset($ledger[(int) $inv->id]) && $type === '');
                if (!$mine) {
                    $single = false;
                }
            }
            $st = (string) $inv->status;
            $out[!$single ? 'mixed' : (in_array($st, self::UNPAID, true) ? 'unpaid' : ($st === 'Paid' ? 'paid' : 'other'))][] = $inv;
        }
        return $out;
    }

    // ------------------------------------------------------------------ controller

    private static function server(array $src)
    {
        if ($src['kind'] === 'client') {
            $s = Capsule::table('tblservers')->where('id', (int) $src['svc']->server)->first();
            if ($s && ($s->type ?? '') === 'pasargadcdn') {
                return $s;
            }
        }
        return Env::server();
    }

    private static function ctlTransfer(array $src, array $to, bool $reset, bool $related, bool $dry): array
    {
        return Env::api(20, self::server($src))->post(ApiClient::site($src['domain']) . self::PATH, ['to' => $to, 'reset_billing_anchor' => $reset,
            'revoke_credentials' => true, 'pause_integrations' => true, 'include_related' => $related, 'dry_run' => $dry]);
    }

    /** `to` of the contract: client {client_id, external_id = the WHMCS service id} | operator {operator_note?}. */
    private static function to(string $dir, int $cid, int $sid, string $note = ''): array
    {
        if ($dir === 'client_operator') {
            return ['kind' => 'operator'] + (trim($note) !== '' ? [Operator::NOTE_FIELD => trim($note)] : []);
        }
        return ['kind' => 'client', 'client_id' => $cid, 'external_id' => (string) $sid];
    }

    /** paused [{domain, type: logs|webhook, id, url}] (or plain strings) as text. */
    public static function pausedText($paused): array
    {
        $out = [];
        foreach ((array) $paused as $p) {
            if (is_array($p)) {
                $out[] = (string) ($p['domain'] ?? '') . ' ' . ((string) ($p['type'] ?? '') === 'webhook' ? 'webhook' : 'logs')
                    . (isset($p['id']) && is_scalar($p['id']) ? ' ' . $p['id'] : '') . (isset($p['url']) && is_string($p['url']) ? ' (' . $p['url'] . ')' : '');
            } elseif (is_scalar($p)) {
                $out[] = (string) $p;
            }
        }
        return $out;
    }

    /** rotated {image_key: bool, tsig: [...], buckets: {done, pending}} (contract addition) as text lines. */
    public static function rotatedText($r): array
    {
        if (!is_array($r)) {
            return [];
        }
        $out = [];
        if (!empty($r['image_key'])) {
            $out[] = 'image transform key';
        }
        if (!empty($r['tsig']) && is_array($r['tsig'])) {
            // [{domain, name, dns_error: str|null}] (dns_error absent on dry_run)
            $out[] = 'TSIG: ' . implode(', ', array_filter(array_map(function ($x) {
                if (!is_array($x)) {
                    return is_scalar($x) ? (string) $x : '';
                }
                return trim((string) ($x['name'] ?? '') . ' @ ' . (string) ($x['domain'] ?? ''), ' @')
                    . (isset($x['dns_error']) && is_string($x['dns_error']) && $x['dns_error'] !== '' ? ' (DNS: ' . $x['dns_error'] . ')' : '');
            }, $r['tsig'])));
        }
        $b = is_array($r['buckets'] ?? null) ? $r['buckets'] : [];
        foreach (['done' => 'buckets rotated', 'pending' => 'buckets pending'] as $k => $label) {
            if (!empty($b[$k]) && is_array($b[$k])) {
                $out[] = $label . ': ' . implode(', ', array_filter(array_map(function ($x) {
                    return is_scalar($x) ? (string) $x : (is_array($x) ? (string) ($x['name'] ?? '') : '');
                }, $b[$k])));
            }
        }
        return $out;
    }

    private static function domainsText($list): string
    {
        return implode(', ', array_filter(array_map(function ($x) {
            return is_scalar($x) ? (string) $x : (is_array($x) ? (string) ($x['domain'] ?? '') : '');
        }, (array) $list)));
    }

    // ------------------------------------------------------------------ actions

    /** @return array [flash, state] */
    public static function action(string $action, array $post, int $admin): array
    {
        if (!Env::adminHasAccess()) {
            return [[['bad', 'نقش مدیریتی شما به این ماژول دسترسی ندارد.']], []];
        }
        $src = self::source($post);
        if (is_string($src)) {
            return [[['bad', View::e($src)]], []];
        }
        $toRaw = Env::input($post['to'] ?? '');
        $dir = self::direction($src, $toRaw);
        if (!in_array($dir, Transfers::DIRECTIONS, true)) {
            return [[['bad', View::e($dir)]], []];
        }
        $cid = $dir === 'client_operator' ? 0 : (int) $toRaw;
        [$o, $errs] = self::options($dir, $post, $src, $cid);
        if ($errs) {
            return [array_map(function ($m) {
                return ['bad', View::e($m)];
            }, $errs), ['opts' => $o]];
        }
        if ($action === 'transfer_preview') {
            return self::preview($dir, $src, $cid, $o);
        }
        if (!in_array((string) ($post['confirm'] ?? ''), ['1', 'on'], true)) {
            return [[['bad', 'برای اجرای انتقال، تأیید نهایی را علامت بزنید.']], self::preview($dir, $src, $cid, $o)[1]];
        }
        return self::execute($dir, $src, $cid, $o, $admin);
    }

    /** The WHMCS changes of a run, as text lines (preview) — computed from the database, never from the request. */
    public static function changes(string $dir, array $src, int $cid, array $o): array
    {
        $l = [];
        $new = self::client($cid);
        if ($dir === 'client_client' || $dir === 'client_operator') {
            $sid = (int) $src['svc']->id;
            $inv = self::invoices($sid, (int) $src['client']);
            if ($dir === 'client_client') {
                $l[] = ['ok', 'سرویس #' . View::n($sid) . ' (' . View::e($src['svc']->product) . ') با همان محصول، دورهٔ پرداخت، سررسید، گزینه‌های سفارشی، دفتر پیش‌پرداخت و مصرف این ماه به ' . View::e(self::clientName($new)) . ' منتقل می‌شود (tblhosting.userid).'];
                $na = Capsule::table('tblhostingaddons')->where('hostingid', $sid)->count();
                $l[] = ['ok', View::n($na) . ' افزونهٔ سرویس (tblhostingaddons) همراه سرویس منتقل می‌شود.'];
                $rows = [];
                foreach (self::MODULE_ROWS as $t => $x) {
                    if (Env::hasTable($t)) {
                        $n = Capsule::table($t)->where('service_id', $sid)->count();
                        if ($n) {
                            $rows[] = $t . ' × ' . $n;
                        }
                    }
                }
                $l[] = ['ok', 'ردیف‌های ماژول این سرویس: ' . ($rows ? View::e(implode('، ', $rows)) : 'ندارد') . '؛ گزارش ایمیلی زمان‌بندی‌شده خاموش می‌شود تا مالک جدید خودش آن را فعال کند.'];
                $l[] = [$o['move_unpaid'] && $inv['unpaid'] ? 'ok' : 'muted', 'صورت‌حساب‌های پرداخت‌نشدهٔ تک‌سرویسی: ' . self::invList($inv['unpaid']) . ($o['move_unpaid'] ? ' — منتقل می‌شوند' : ' — نزد مشتری فعلی می‌مانند')];
                $l[] = [$o['move_paid'] && $inv['paid'] ? 'warn' : 'muted', 'صورت‌حساب‌های پرداخت‌شدهٔ تک‌سرویسی: ' . self::invList($inv['paid'])
                    . ($o['move_paid'] ? ' — منتقل می‌شوند (سابقهٔ حسابداری مشتری فعلی تغییر می‌کند)' : ' — نزد مشتری فعلی می‌مانند')];
            } else {
                $l[] = ['ok', 'سرویس #' . View::n($sid) . ' در WHMCS «لغوشده» (Cancelled) می‌شود — نه حذف؛ ماژول دیگر هرگز سایت را روی کنترلر حذف یا معلق نمی‌کند (نشانهٔ انتقال).'];
                if ($inv['unpaid']) {
                    $l[] = ['warn', 'صورت‌حساب‌های پرداخت‌نشدهٔ این سرویس نزد مشتری می‌مانند؛ در صورت نیاز دستی لغو کنید: ' . self::invList($inv['unpaid'])];
                }
            }
            if ($inv['mixed']) {
                $l[] = ['warn', 'صورت‌حساب‌های ترکیبی (شامل اقلام دیگر) هرگز منتقل نمی‌شوند: ' . self::invList($inv['mixed'])];
            }
            if ((float) $o['credit'] > 0) {
                $l[] = ['ok', $dir === 'client_client'
                    ? 'انتقال ' . View::n((float) $o['credit'], 2) . ' اعتبار: کسر از ' . View::e(self::clientName(self::client((int) $src['client']))) . ' و افزودن به ' . View::e(self::clientName($new)) . ' (با توضیح در هر دو حساب).'
                    : 'افزودن ' . View::n((float) $o['credit'], 2) . ' اعتبار (سهم باقی‌مانده) به ' . View::e(self::clientName(self::client((int) $src['client']))) . '.'];
            }
        } else {
            $prod = Capsule::table('tblproducts')->where('id', $o['pid'])->first(['name']);
            $l[] = ['ok', 'سرویس جدید برای ' . View::e(self::clientName($new)) . ' روی محصول «' . View::e($prod->name ?? '') . '»، دورهٔ ' . View::e(self::CYCLES[$o['cycle']][2] ?? '')
                . '، سررسید بعدی ' . View::e($o['nextdue']) . ' ساخته می‌شود (AddOrder → AcceptOrder بدون راه‌اندازی خودکار؛ Create ماژول اجرا نمی‌شود) و فعال می‌شود.'];
            $l[] = [$o['invoice'] ? 'ok' : 'muted', $o['invoice'] ? 'اولین صورت‌حساب سرویس صادر می‌شود (بدون ارسال ایمیل سفارش).' : 'صورت‌حسابی صادر نمی‌شود.'];
            $l[] = ['ok', 'شروع شمارش مصرف (billing anchor) از همین لحظه: ترافیک دورهٔ اپراتور برای مشتری حساب نمی‌شود.'];
        }
        if ($o['email_old'] && $src['kind'] === 'client') {
            $l[] = ['ok', 'ایمیل «' . self::EMAIL_OLD . '» به مالک قبلی ارسال می‌شود.'];
        }
        if ($o['email_new'] && $dir !== 'client_operator') {
            $l[] = ['ok', 'ایمیل «' . self::EMAIL_NEW . '» به مالک جدید ارسال می‌شود.'];
        }
        return $l;
    }

    private static function invList(array $rows): string
    {
        if (!$rows) {
            return 'ندارد';
        }
        return implode('، ', array_map(function ($i) {
            return '<a href="invoices.php?action=edit&amp;id=' . (int) $i->id . '">#' . View::n((int) $i->id) . '</a> (' . View::e((string) $i->status) . '، ' . View::n((float) $i->total, 2) . ')';
        }, $rows));
    }

    private static function preview(string $dir, array $src, int $cid, array $o): array
    {
        try {
            // operator → client: the new service id does not exist yet — the dry run carries no external_id
            $to = $dir === 'operator_client' ? ['kind' => 'client', 'client_id' => $cid] : self::to($dir, $cid, (int) $src['svc']->id, $o['note']);
            $dry = self::ctlTransfer($src, $to, $dir === 'operator_client', $o['include_related'], true);
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            // 422 for a parent/child of the same owner (names them): offer «انتقال همراه زیردامنه‌ها» (include_related)
            $hint = !$o['include_related'] && $e instanceof ApiException && $e->getCode() === 422 && strpos($msg, 'include_related') === false
                && (strpos($msg, 'زیردامنه') !== false || strpos($msg, 'والد') !== false || strpos($msg, 'مرتبط') !== false)
                ? ' اگر این سایت‌ها هم باید منتقل شوند، گزینهٔ «انتقال همراه زیردامنه‌ها» را علامت بزنید.' : '';
            return [[['bad', View::e('کنترلر انتقال را نمی‌پذیرد: ' . $msg . $hint)]], ['opts' => $o, 'related_hint' => $hint !== '']];
        }
        return [[], ['preview' => ['dir' => $dir, 'dry' => $dry, 'changes' => self::changes($dir, $src, $cid, $o), 'cid' => $cid], 'opts' => $o]];
    }

    // ------------------------------------------------------------------ execute

    private static function step(array &$steps, string $tone, string $text, string $domain, int $uid = 0): void
    {
        $steps[] = [$tone, $text];
        Env::log('domain transfer ' . $domain . ': ' . $text . ' — ' . Env::adminLabel(), $uid);
    }

    private static function execute(string $dir, array $src, int $cid, array $o, int $admin): array
    {
        $steps = [];
        $domain = $src['domain'];
        $db = Capsule::connection();
        $new = self::client($cid);
        $old = $src['kind'] === 'client' ? self::client((int) $src['client']) : null;
        $sid = $src['kind'] === 'client' ? (int) $src['svc']->id : 0;
        $ctlDone = null;
        $created = null;
        self::step($steps, 'ok', 'start ' . $dir . ' (' . ($old ? 'client #' . (int) $old->id : 'operator') . ' → ' . ($new ? 'client #' . $cid : 'operator') . ')', $domain);

        if ($dir !== 'operator_client') {
            // client sources: the controller first (keys revoked, integrations paused before anything else)
            try {
                $ctlDone = self::ctlTransfer($src, self::to($dir, $cid, $sid, $o['note']), false, $o['include_related'], false);
            } catch (\Throwable $e) {
                self::step($steps, 'bad', 'controller transfer refused: ' . $e->getMessage(), $domain, (int) $src['client']);
                self::$steps = $steps;
                return [[['bad', View::e('انتقال روی کنترلر انجام نشد و هیچ تغییری ذخیره نشد: ' . $e->getMessage())]], ['opts' => $o, 'done' => $steps]];
            }
            self::step($steps, 'ok', 'controller transfer done (' . self::ctlSummary($ctlDone) . ')', $domain, (int) $src['client']);
        }
        Transfers::ensure();
        $db->beginTransaction();
        try {
            if ($dir === 'client_client') {
                $detail = self::whmcsClientToClient($src, $cid, $o, $steps);
            } elseif ($dir === 'client_operator') {
                $detail = self::whmcsClientToOperator($src, $o, $steps);
            } else {
                [$created, $detail] = self::whmcsOperatorToClient($src, $cid, $o, $steps);
                $sid = $created['service'];
                $ctlDone = self::ctlTransfer($src, self::to($dir, $cid, $sid), true, $o['include_related'], false);
                self::step($steps, 'ok', 'controller transfer done with reset_billing_anchor (' . self::ctlSummary($ctlDone) . ')', $domain, $cid);
                if (self::$failpoint === 'after_controller') {
                    throw new \RuntimeException('test failpoint after the controller transfer');
                }
            }
            Capsule::table(Transfers::TABLE)->insert(['domain' => $domain, 'service_id' => $sid, 'direction' => $dir,
                'from_client' => $src['kind'] === 'client' ? (int) $src['client'] : 0, 'to_client' => $cid, 'admin_id' => $admin, 'status' => 'done',
                'guard' => $dir === 'client_operator' ? 1 : 0, 'banner' => $dir === 'client_operator' ? 0 : 1,
                'detail' => json_encode(['controller' => $ctlDone, 'whmcs' => $detail], JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR),
                'created_at' => date('Y-m-d H:i:s'), 'updated_at' => date('Y-m-d H:i:s')]);
            if ($dir !== 'client_operator') {
                // an older notice of this service (an earlier transfer) is superseded
                Capsule::table(Transfers::TABLE)->where('service_id', $sid)->where('to_client', '<>', $cid)->update(['banner' => 0]);
            }
            if (self::$failpoint === 'whmcs') {
                throw new \RuntimeException('test failpoint in the WHMCS transaction');
            }
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollBack();
            self::step($steps, 'bad', 'WHMCS step failed, database rolled back: ' . $e->getMessage(), $domain, $cid);
            if ($created) {
                self::cleanupCreated($created, $steps, $domain);
            }
            $back = '';
            if ($ctlDone !== null) {
                // put the site back with its previous owner
                $backTo = $dir === 'operator_client' ? ['kind' => 'operator'] : ['kind' => 'client', 'client_id' => (int) $src['client'], 'external_id' => (string) $src['svc']->id];
                try {
                    self::ctlTransfer($src, $backTo, false, $o['include_related'], false);
                    self::step($steps, 'warn', 'site transferred back to its previous owner on the controller (revoked API keys stay revoked; integrations stay paused)', $domain);
                    $back = ' سایت روی کنترلر به مالک قبلی برگردانده شد (کلیدهای API باطل‌شده برنمی‌گردند و یکپارچه‌سازی‌ها متوقف مانده‌اند).';
                } catch (\Throwable $e2) {
                    self::step($steps, 'bad', 'transferring the site back FAILED: ' . $e2->getMessage() . ' — fix the owner on the controller by hand', $domain);
                    $back = ' برگرداندن سایت روی کنترلر هم ناموفق بود (' . $e2->getMessage() . ')؛ مالک سایت را دستی اصلاح کنید.';
                }
            }
            try {
                Capsule::table(Transfers::TABLE)->insert(['domain' => $domain, 'service_id' => $sid, 'direction' => $dir,
                    'from_client' => $src['kind'] === 'client' ? (int) $src['client'] : 0, 'to_client' => $cid, 'admin_id' => $admin,
                    'status' => $ctlDone !== null ? 'rolled_back' : 'failed', 'guard' => 0, 'banner' => 0,
                    'detail' => json_encode(['error' => $e->getMessage()], JSON_UNESCAPED_UNICODE), 'created_at' => date('Y-m-d H:i:s'), 'updated_at' => date('Y-m-d H:i:s')]);
            } catch (\Throwable $e3) {
                // the ledger is informational here
            }
            self::$steps = $steps;
            Pages::reset();
            return [[['bad', View::e('انتقال انجام نشد و تغییرات WHMCS برگردانده شد: ' . $e->getMessage() . '.' . $back)]], ['opts' => $o, 'done' => $steps]];
        }
        self::step($steps, 'ok', 'WHMCS changes committed', $domain, $cid);
        // after the commit: best-effort extras
        if ($dir === 'client_operator') {
            Operator::remember($domain, null, $admin);
        }
        $flash = [];
        $rot = is_array($ctlDone['rotated'] ?? null) ? $ctlDone['rotated'] : [];
        if (!empty($rot['tsig'])) {
            $flash[] = ['warn', 'کلید TSIG این دامنه عوض شد: اگر DNS ثانویهٔ سمت مشتری با این کلید زون را می‌گیرد، رمز جدید باید در آن تنظیم شود (از صفحهٔ «DNS ثانویه»).'];
            self::step($steps, 'warn', 'TSIG key rotated: ' . implode('; ', self::rotatedText(['tsig' => $rot['tsig']])), $domain);
        }
        if (!empty($rot['buckets']['pending'])) {
            $flash[] = ['info', 'چرخش کلید باکت‌های ' . View::ltr(implode(', ', array_map('strval', array_filter((array) $rot['buckets']['pending'], 'is_scalar'))))
                . ' هنوز در جریان است و خودکار تمام می‌شود. مالک جدید کلیدهای ذخیره‌سازی خودش را با «کلید جدید» در صفحهٔ فضای ذخیره‌سازی می‌گیرد.'];
        } elseif (!empty($rot['buckets']['done'])) {
            $flash[] = ['info', 'کلیدهای دسترسی باکت‌ها عوض شد؛ مالک جدید کلیدهای ذخیره‌سازی خودش را با «کلید جدید» در صفحهٔ فضای ذخیره‌سازی می‌گیرد.'];
        }
        self::emails($dir, $domain, $old, $new, $sid, $o, $steps);
        Env::reset();
        Pages::reset();
        self::$steps = $steps;
        $msg = 'انتقال ' . View::ltr($domain) . ' (' . self::DIR_LABEL[$dir] . ') انجام شد.';
        if ($dir === 'operator_client') {
            $msg .= ' سرویس جدید: <a href="' . View::e(Data::serviceUrl($cid, $sid)) . '">#' . View::n($sid) . '</a>.';
        }
        return [array_merge([['ok', $msg]], $flash), ['done' => $steps, 'service' => $sid]];
    }

    private static function ctlSummary($r): string
    {
        $r = is_array($r) ? $r : [];
        $rot = self::rotatedText($r['rotated'] ?? null);
        return 'related: ' . (self::domainsText($r['related'] ?? []) ?: 'none') . ', revoked keys: ' . (is_array($r['revoked_keys'] ?? null) ? count($r['revoked_keys']) : (int) ($r['revoked_keys'] ?? 0))
            . ', paused: ' . (implode('; ', self::pausedText($r['paused'] ?? [])) ?: 'none')
            . (!empty($r['access_rotated']) ? ', access secret rotated: ' . self::domainsText($r['access_rotated']) : '')
            . ($rot ? ', rotated: ' . implode('; ', $rot) : '')
            . (isset($r['billing_since']) && is_string($r['billing_since']) && $r['billing_since'] !== '' ? ', billing since ' . $r['billing_since'] : '');
    }

    /** client → client WHMCS side (inside the transaction). */
    private static function whmcsClientToClient(array $src, int $cid, array $o, array &$steps): array
    {
        $sid = (int) $src['svc']->id;
        $from = (int) $src['client'];
        $domain = $src['domain'];
        $n = Capsule::table('tblhosting')->where('id', $sid)->where('userid', $from)->update(['userid' => $cid]);
        if ($n !== 1) {
            throw new \RuntimeException('service #' . $sid . ' is no longer owned by client #' . $from);
        }
        self::step($steps, 'ok', 'tblhosting #' . $sid . ' userid ' . $from . ' → ' . $cid, $domain, $cid);
        $na = Capsule::table('tblhostingaddons')->where('hostingid', $sid)->update(['userid' => $cid]);
        self::step($steps, 'ok', 'tblhostingaddons of service #' . $sid . ': ' . $na . ' moved', $domain, $cid);
        $new = self::client($cid);
        foreach (self::MODULE_ROWS as $t => $extra) {
            if (!Env::hasTable($t)) {
                continue;
            }
            $set = ['userid' => $cid];
            foreach ($extra as $col => $from_) {
                $set[$col] = (string) ($new->$from_ ?? '');
            }
            $m = Capsule::table($t)->where('service_id', $sid)->update($set);
            if ($m) {
                self::step($steps, 'ok', $t . ': ' . $m . ' row(s) moved', $domain, $cid);
            }
        }
        if (Env::hasTable('mod_pasargadcdn_service_state')) {
            Capsule::table('mod_pasargadcdn_service_state')->where('service_id', $sid)->update(['report_freq' => '']);
        }
        $inv = self::invoices($sid, $from);
        $move = array_merge($o['move_unpaid'] ? $inv['unpaid'] : [], $o['move_paid'] ? $inv['paid'] : []);
        $ids = array_map(function ($i) {
            return (int) $i->id;
        }, $move);
        if ($ids) {
            Capsule::table('tblinvoices')->whereIn('id', $ids)->where('userid', $from)->update(['userid' => $cid]);
            Capsule::table('tblinvoiceitems')->whereIn('invoiceid', $ids)->update(['userid' => $cid]);
            if (Env::hasTable('tblaccounts')) {
                Capsule::table('tblaccounts')->whereIn('invoiceid', $ids)->update(['userid' => $cid]);
            }
            self::step($steps, 'ok', 'invoices moved: #' . implode(', #', $ids), $domain, $cid);
        }
        if ($inv['mixed']) {
            self::step($steps, 'warn', 'mixed invoices left with client #' . $from . ': #' . implode(', #', array_map(function ($i) {
                return (int) $i->id;
            }, $inv['mixed'])), $domain, $from);
        }
        $credit = round((float) $o['credit'], 2);
        if ($credit > 0) {
            $cur = (float) Capsule::table('tblclients')->where('id', $from)->value('credit');
            if ($credit > $cur + 0.0001) {
                throw new \RuntimeException('client #' . $from . ' has only ' . $cur . ' credit');
            }
            self::removeCredit($from, $credit, 'انتقال اعتبار به مشتری #' . $cid . ' همراه با انتقال دامنه ' . $domain . ' (سرویس #' . $sid . ')');
            $r = Env::localApi('AddCredit', ['clientid' => $cid, 'amount' => $credit,
                'description' => 'انتقال اعتبار از مشتری #' . $from . ' همراه با انتقال دامنه ' . $domain . ' (سرویس #' . $sid . ')']);
            if (($r['result'] ?? '') !== 'success') {
                throw new \RuntimeException('AddCredit failed: ' . ($r['message'] ?? ''));
            }
            self::step($steps, 'ok', 'credit ' . $credit . ' moved from client #' . $from . ' to client #' . $cid, $domain, $cid);
        }
        return ['service' => $sid, 'addons' => $na, 'invoices' => $ids, 'mixed' => count($inv['mixed']), 'credit' => $credit];
    }

    /**
     * Takes $amount of credit from a client: WHMCS AddCredit with a negative amount; when WHMCS refuses it, the same
     * effect written directly (tblcredit row with the negative amount + tblclients.credit), inside the transaction.
     */
    private static function removeCredit(int $uid, float $amount, string $desc): void
    {
        $r = Env::localApi('AddCredit', ['clientid' => $uid, 'amount' => -$amount, 'description' => $desc]);
        if (($r['result'] ?? '') === 'success') {
            return;
        }
        Capsule::table('tblclients')->where('id', $uid)->update(['credit' => Capsule::raw('credit - ' . number_format($amount, 2, '.', ''))]);
        Capsule::table('tblcredit')->insert(Env::onlyColumns('tblcredit', ['clientid' => $uid, 'date' => date('Y-m-d'), 'description' => $desc,
            'amount' => -$amount, 'relid' => 0]));
    }

    /** client → operator WHMCS side (inside the transaction). */
    private static function whmcsClientToOperator(array $src, array $o, array &$steps): array
    {
        $sid = (int) $src['svc']->id;
        $uid = (int) $src['client'];
        $r = Env::localApi('UpdateClientProduct', ['serviceid' => $sid, 'status' => 'Cancelled']);
        if (($r['result'] ?? '') !== 'success') {
            throw new \RuntimeException('UpdateClientProduct (Cancelled) failed: ' . ($r['message'] ?? ''));
        }
        self::step($steps, 'ok', 'service #' . $sid . ' set to Cancelled (no module Terminate; guard set)', $src['domain'], $uid);
        if (Env::hasTable('mod_pasargadcdn_trials')) {
            Capsule::table('mod_pasargadcdn_trials')->where('service_id', $sid)->update(['status' => 'closed', 'updated_at' => date('Y-m-d H:i:s')]);
        }
        if (Env::hasTable('mod_pasargadcdn_service_state')) {
            Capsule::table('mod_pasargadcdn_service_state')->where('service_id', $sid)->update(['report_freq' => '']);
        }
        $credit = round((float) $o['credit'], 2);
        if ($credit > 0) {
            $r = Env::localApi('AddCredit', ['clientid' => $uid, 'amount' => $credit,
                'description' => 'بازپرداخت سهم باقی‌ماندهٔ سرویس #' . $sid . ' (انتقال دامنه ' . $src['domain'] . ' به اپراتور)']);
            if (($r['result'] ?? '') !== 'success') {
                throw new \RuntimeException('AddCredit failed: ' . ($r['message'] ?? ''));
            }
            self::step($steps, 'ok', 'credit ' . $credit . ' added to client #' . $uid, $src['domain'], $uid);
        }
        return ['service' => $sid, 'credit' => $credit];
    }

    /** operator → client WHMCS side (inside the transaction): [created ids, detail]. */
    private static function whmcsOperatorToClient(array $src, int $cid, array $o, array &$steps): array
    {
        $domain = $src['domain'];
        $server = Env::server();
        if (!$server) {
            throw new \RuntimeException('no Pasargad CDN server configured');
        }
        $gw = $o['gateway'];
        if ($gw === '') {
            $gw = (string) (Env::hasColumn('tblclients', 'defaultgateway') ? Capsule::table('tblclients')->where('id', $cid)->value('defaultgateway') : '');
        }
        if ($gw === '') {
            $gw = (string) (array_keys(self::gateways())[0] ?? '');
        }
        self::$creating = true;
        try {
            $r = Env::localApi('AddOrder', ['clientid' => $cid, 'pid' => [$o['pid']], 'domain' => [$domain], 'billingcycle' => [self::CYCLES[$o['cycle']][0]],
                'paymentmethod' => $gw, 'noinvoice' => !$o['invoice'], 'noinvoiceemail' => true, 'noemail' => true]);
        } finally {
            self::$creating = false;
        }
        if (($r['result'] ?? '') !== 'success') {
            throw new \RuntimeException('AddOrder failed: ' . ($r['message'] ?? ''));
        }
        $orderId = (int) ($r['orderid'] ?? 0);
        $sid = (int) explode(',', (string) ($r['serviceids'] ?? $r['productids'] ?? ''))[0];
        $created = ['order' => $orderId, 'service' => $sid, 'invoice' => (int) ($r['invoiceid'] ?? 0)];
        if ($orderId <= 0 || $sid <= 0) {
            throw new \RuntimeException('AddOrder returned no order / service id');
        }
        self::step($steps, 'ok', 'AddOrder #' . $orderId . ' → service #' . $sid . ($created['invoice'] ? ', invoice #' . $created['invoice'] : ', no invoice'), $domain, $cid);
        $r = Env::localApi('AcceptOrder', ['orderid' => $orderId, 'autosetup' => false, 'sendemail' => false]);
        if (($r['result'] ?? '') !== 'success') {
            throw new \RuntimeException('AcceptOrder failed: ' . ($r['message'] ?? ''));
        }
        self::step($steps, 'ok', 'AcceptOrder #' . $orderId . ' (autosetup off — module Create not run)', $domain, $cid);
        $r = Env::localApi('UpdateClientProduct', ['serviceid' => $sid, 'status' => 'Active', 'serverid' => (int) $server->id,
            'nextduedate' => $o['nextdue'], 'domain' => $domain]);
        if (($r['result'] ?? '') !== 'success') {
            throw new \RuntimeException('UpdateClientProduct failed: ' . ($r['message'] ?? ''));
        }
        if (Env::hasColumn('tblhosting', 'nextinvoicedate')) {
            Capsule::table('tblhosting')->where('id', $sid)->update(['nextinvoicedate' => $o['nextdue']]);
        }
        self::step($steps, 'ok', 'service #' . $sid . ' Active on server #' . (int) $server->id . ', next due ' . $o['nextdue'], $domain, $cid);
        return [$created, $created];
    }

    /** Rows a WHMCS API call may have committed on its own (outside our transaction) are removed after a failure. */
    private static function cleanupCreated(array $c, array &$steps, string $domain): void
    {
        try {
            $left = [];
            if ($c['service'] > 0 && Capsule::table('tblhosting')->where('id', $c['service'])->exists()) {
                Capsule::table('tblhosting')->where('id', $c['service'])->delete();
                $left[] = 'service #' . $c['service'];
            }
            if ($c['invoice'] > 0 && Capsule::table('tblinvoices')->where('id', $c['invoice'])->exists()) {
                Capsule::table('tblinvoiceitems')->where('invoiceid', $c['invoice'])->delete();
                Capsule::table('tblinvoices')->where('id', $c['invoice'])->delete();
                $left[] = 'invoice #' . $c['invoice'];
            }
            if ($c['order'] > 0 && Env::hasTable('tblorders') && Capsule::table('tblorders')->where('id', $c['order'])->exists()) {
                Capsule::table('tblorders')->where('id', $c['order'])->delete();
                $left[] = 'order #' . $c['order'];
            }
            if ($left) {
                self::step($steps, 'warn', 'removed rows committed outside the transaction: ' . implode(', ', $left), $domain);
            }
        } catch (\Throwable $e) {
            self::step($steps, 'bad', 'cleanup failed: ' . $e->getMessage(), $domain);
        }
    }

    // ------------------------------------------------------------------ e-mails

    /** name => [fa subject, fa body, en subject, en body] (general templates, sent with the client id). */
    public static function templates(): array
    {
        $fa = function (string $inner) {
            return '<div dir="rtl" style="text-align:right;font-family:Tahoma,Arial,sans-serif;line-height:1.9;font-size:14px;color:#1f2933">'
                . '<div style="border-right:4px solid #1d5fd6;padding:2px 12px;margin:0 0 14px"><div style="font-size:16px;font-weight:bold;color:#1d5fd6">پاسارگاد سی‌دی‌ان</div></div>'
                . '<p>{$client_name} گرامی،</p>' . $inner . '<p>{$signature}</p></div>';
        };
        $en = function (string $inner) {
            return '<div dir="ltr" style="text-align:left;font-family:Arial,sans-serif;line-height:1.7;font-size:14px;color:#1f2933">'
                . '<div style="border-left:4px solid #1d5fd6;padding:2px 12px;margin:0 0 14px"><div style="font-size:16px;font-weight:bold;color:#1d5fd6">Pasargad CDN</div></div>'
                . '<p>Dear {$client_name},</p>' . $inner . '<p>{$signature}</p></div>';
        };
        return [
            self::EMAIL_OLD => ['انتقال دامنه {$transfer_domain} از حساب شما',
                $fa('<p>دامنهٔ <strong dir="ltr">{$transfer_domain}</strong> در تاریخ {$transfer_date} از حساب CDN شما منتقل شد و دیگر در ناحیهٔ کاربری شما نمایش داده نمی‌شود. کلیدهای API این سایت باطل و وب‌هوک‌ها و ارسال لاگ آن متوقف شده‌اند.</p>'
                    . '<p>اگر این انتقال را درخواست نکرده‌اید، لطفاً فوراً با پشتیبانی تماس بگیرید.</p>'),
                'Domain {$transfer_domain} was transferred out of your account',
                $en('<p>The domain <strong>{$transfer_domain}</strong> was transferred out of your CDN account on {$transfer_date} and no longer appears in your client area. The site\'s API keys were revoked and its webhooks and log shipping were paused.</p>'
                    . '<p>If you did not request this transfer, please contact support right away.</p>')],
            self::EMAIL_NEW => ['دامنه {$transfer_domain} به حساب شما منتقل شد',
                $fa('<p>دامنهٔ <strong dir="ltr">{$transfer_domain}</strong> در تاریخ {$transfer_date} به حساب CDN شما منتقل شد. تنظیمات، رکوردهای DNS، SSL و آمار سایت بدون تغییر منتقل شده‌اند.</p>'
                    . '<p>کلیدهای API مالک قبلی باطل شده‌اند و وب‌هوک‌ها و ارسال لاگ متوقف هستند؛ از ناحیهٔ کاربری، کلید API، وب‌هوک‌ها و ارسال لاگ را با اطلاعات خودتان دوباره تنظیم کنید.</p>'),
                'Domain {$transfer_domain} was transferred to your account',
                $en('<p>The domain <strong>{$transfer_domain}</strong> was transferred to your CDN account on {$transfer_date}. Its settings, DNS records, SSL and statistics moved unchanged.</p>'
                    . '<p>The previous owner\'s API keys were revoked and webhooks and log shipping are paused; set up API keys, webhooks and log shipping again with your own details from the client area.</p>')],
        ];
    }

    /** Creates the two templates (fa + english) when missing; never overwrites an edited one. */
    public static function ensureTemplates(): void
    {
        $now = date('Y-m-d H:i:s');
        foreach (self::templates() as $name => [$faSub, $faBody, $enSub, $enBody]) {
            foreach (['' => [$faSub, $faBody], 'english' => [$enSub, $enBody]] as $lang => [$sub, $body]) {
                if (Capsule::table('tblemailtemplates')->where('type', 'general')->where('name', $name)->where('language', $lang)->exists()) {
                    continue;
                }
                Capsule::table('tblemailtemplates')->insert(Env::onlyColumns('tblemailtemplates', ['type' => 'general', 'name' => $name, 'subject' => $sub,
                    'message' => $body, 'attachments' => '', 'fromname' => '', 'fromemail' => '', 'disabled' => 0, 'custom' => 1, 'language' => $lang,
                    'copyto' => '', 'blind_copy_to' => '', 'plaintext' => 0, 'created_at' => $now, 'updated_at' => $now]));
            }
        }
    }

    private static function emails(string $dir, string $domain, $old, $new, int $sid, array $o, array &$steps): void
    {
        $send = [];
        if ($o['email_old'] && $old) {
            $send[] = [self::EMAIL_OLD, (int) $old->id];
        }
        if ($o['email_new'] && $new && $dir !== 'client_operator') {
            $send[] = [self::EMAIL_NEW, (int) $new->id];
        }
        if (!$send) {
            return;
        }
        try {
            self::ensureTemplates();
        } catch (\Throwable $e) {
            self::step($steps, 'warn', 'e-mail templates could not be created: ' . $e->getMessage(), $domain);
            return;
        }
        foreach ($send as [$tpl, $uid]) {
            $r = Env::localApi('SendEmail', ['messagename' => $tpl, 'id' => $uid,
                'customvars' => base64_encode(serialize(['transfer_domain' => $domain, 'transfer_date' => date('Y-m-d'), 'transfer_service' => $sid]))]);
            self::step($steps, ($r['result'] ?? '') === 'success' ? 'ok' : 'warn', 'e-mail «' . $tpl . '» to client #' . $uid . ': '
                . (($r['result'] ?? '') === 'success' ? 'sent' : 'failed — ' . ($r['message'] ?? '')), $domain, $uid);
        }
    }

    // ------------------------------------------------------------------ page

    public static function page(array $get, array $state): string
    {
        $in = ['service' => (int) ($get['service'] ?? 0), 'domain' => Env::input($get['domain'] ?? '')];
        $back = '<p class="pcdna-back"><a href="' . View::url(['page' => $in['service'] > 0 ? 'sites' : 'operator']) . '">→ بازگشت</a></p>';
        if (!Env::adminHasAccess()) {
            return $back . View::alert('bad', 'نقش مدیریتی شما به این ماژول دسترسی ندارد.');
        }
        if (!empty($state['done'])) {
            return $back . self::doneCard($state['done'], (int) ($state['service'] ?? 0));
        }
        $ping = Pages::ping();
        if (!$ping['ok']) {
            return $back . Pages::ctlError($ping);
        }
        $src = self::source($in);
        if (is_string($src)) {
            return $back . View::alert('bad', View::e($src));
        }
        $h = $back . self::sourceCard($src);
        $q = $in['service'] > 0 ? ['page' => 'transfer', 'service' => $in['service']] : ['page' => 'transfer', 'domain' => $src['domain']];
        $to = Env::input($get['to'] ?? ($state['preview']['cid'] ?? ''));
        if (!empty($state['preview'])) {
            $to = $state['preview']['dir'] === 'client_operator' ? 'operator' : (string) $state['preview']['cid'];
        }
        $dir = $to !== '' ? self::direction($src, $to) : null;
        if ($dir === null || !in_array($dir, Transfers::DIRECTIONS, true)) {
            if (is_string($dir)) {
                $h .= View::alert('bad', View::e($dir));
            }
            return $h . self::destCard($src, $q, Env::input($get['q'] ?? ''));
        }
        $cid = $dir === 'client_operator' ? 0 : (int) $to;
        $o = (array) ($state['opts'] ?? []) + self::defaults($dir, $src);
        if (!empty($state['preview'])) {
            return $h . self::previewCard($state['preview'], $src, $q, $to, $o);
        }
        return $h . self::optionsCard($dir, $src, $cid, $q, $to, $o);
    }

    private static function sourceCard(array $src): string
    {
        if ($src['kind'] === 'client') {
            $s = $src['svc'];
            $b = '<dl class="pcdna-dl pcdna-dl-3"><div><dt>دامنه</dt><dd>' . View::ltr($src['domain']) . '</dd></div>'
                . '<div><dt>سرویس</dt><dd><a href="' . View::e(Data::serviceUrl((int) $s->userid, (int) $s->id)) . '">#' . View::n((int) $s->id) . '</a> · ' . View::e($s->product)
                . ' · ' . Pages::whmcsBadge((string) $s->domainstatus) . '</dd></div>'
                . '<div><dt>مالک فعلی</dt><dd><a href="' . View::e(Data::clientUrl((int) $s->userid)) . '">' . View::e(self::clientName($s)) . '</a></dd></div></dl>';
        } else {
            $b = '<dl class="pcdna-dl pcdna-dl-3"><div><dt>دامنه</dt><dd>' . View::ltr($src['domain']) . '</dd></div>'
                . '<div><dt>مالک فعلی</dt><dd>' . View::badge('اپراتور', 'violet') . '</dd></div>'
                . '<div><dt>یادداشت</dt><dd>' . View::e((string) ($src['site'][Operator::NOTE_FIELD] ?? '') ?: '—') . '</dd></div></dl>';
        }
        $b .= '<p class="pcdna-muted pcdna-small">انتقال کامل است: رکوردهای DNS، همهٔ تنظیمات، SSL، قوانین، WAF، توابع، باکت‌ها و آمار با سایت می‌مانند؛ '
            . 'کلیدهای API مشتری باطل و وب‌هوک‌ها و ارسال لاگ (با پاک‌شدن رمزهایشان) متوقف می‌شوند و نشست‌های دسترسی محافظت‌شده پایان می‌یابند. '
            . 'زیرسایت‌های نمایندگی فقط از ابزار نمایندگی منتقل می‌شوند.</p>';
        return View::card('انتقال دامنه — مبدأ', $b, '', '', 'users');
    }

    private static function destCard(array $src, array $q, string $term): string
    {
        $f = '<form method="get" action="' . View::e((string) (parse_url(View::$link, PHP_URL_PATH) ?: 'addonmodules.php')) . '" class="pcdna-filters" role="search" data-transfer-search="1">'
            . '<input type="hidden" name="module" value="' . View::e(Env::MODULE) . '">';
        foreach ($q as $k => $v) {
            $f .= '<input type="hidden" name="' . View::e($k) . '" value="' . View::e($v) . '">';
        }
        $f .= '<label class="pcdna-search">' . View::icon('search') . '<input type="search" name="q" class="pcdna-input" value="' . View::e($term)
            . '" placeholder="جستجوی مشتری مقصد: #شناسه، ایمیل، نام یا شرکت" aria-label="جستجوی مشتری"></label>'
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('search') . '<span>جستجو</span></button></form>';
        if ($term !== '') {
            $rows = Data::clients($term);
            if (!$rows) {
                $f .= '<p class="pcdna-muted">مشتری‌ای پیدا نشد.</p>';
            } else {
                $f .= '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-xfer-clients"><thead><tr><th>مشتری</th><th>ایمیل</th><th>اعتبار</th><th></th></tr></thead><tbody>';
                foreach ($rows as $c) {
                    $self = $src['kind'] === 'client' && (int) $c->id === (int) $src['client'];
                    $f .= '<tr data-client="' . (int) $c->id . '"><td>' . View::e(self::clientName($c)) . '</td><td>' . View::ltr((string) $c->email) . '</td>'
                        . '<td class="pcdna-num">' . View::n((float) $c->credit, 2) . '</td><td class="pcdna-actions">'
                        . ($self ? View::badge('مالک فعلی', 'muted') : '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-primary" href="' . View::url($q + ['to' => (int) $c->id]) . '">انتخاب</a>')
                        . '</td></tr>';
                }
                $f .= '</tbody></table></div>';
            }
        }
        if ($src['kind'] === 'client') {
            $f .= '<div class="pcdna-xfer-op"><a class="pcdna-btn" data-to-operator="1" href="' . View::url($q + ['to' => 'operator']) . '">' . View::icon('zap')
                . '<span>انتقال به «اپراتور» (دامنهٔ خود پلتفرم، بدون صورت‌حساب)</span></a></div>';
        }
        return View::card('۱. مقصد انتقال', $f, '', '', 'search');
    }

    private static function hiddenSrc(array $q, string $to): string
    {
        $h = View::csrf();
        foreach (['service', 'domain'] as $k) {
            if (isset($q[$k])) {
                $h .= '<input type="hidden" name="' . $k . '" value="' . View::e($q[$k]) . '">';
            }
        }
        return $h . '<input type="hidden" name="to" value="' . View::e($to) . '">';
    }

    private static function optionsCard(string $dir, array $src, int $cid, array $q, string $to, array $o): string
    {
        $c = self::client($cid);
        $h = '<p>جهت: ' . View::badge(self::DIR_LABEL[$dir], 'brand') . ' — مقصد: <strong>' . ($dir === 'client_operator' ? 'اپراتور' : View::e(self::clientName($c))) . '</strong> · '
            . '<a href="' . View::url($q) . '">تغییر مقصد</a></p>';
        $f = '<form method="post" action="' . View::url($q + ['to' => $to]) . '" class="pcdna-form" data-transfer-options="' . View::e($dir) . '">' . self::hiddenSrc($q, $to)
            . '<input type="hidden" name="a" value="transfer_preview"><div class="pcdna-form-grid">';
        if ($dir === 'client_client') {
            $f .= '<div class="pcdna-col-2">' . Pages::check('move_unpaid', $o['move_unpaid'], 'انتقال صورت‌حساب‌های پرداخت‌نشده‌ای که فقط اقلام همین سرویس را دارند') . '</div>'
                . '<div class="pcdna-col-2">' . Pages::check('move_paid', $o['move_paid'], 'انتقال صورت‌حساب‌های پرداخت‌شدهٔ همین سرویس')
                . '<small class="pcdna-err">هشدار: سابقهٔ حسابداری مشتری فعلی تغییر می‌کند؛ فقط وقتی لازم است که کل سابقهٔ سرویس باید نزد مالک جدید باشد.</small></div>'
                . '<label><span>انتقال اعتبار از مشتری فعلی به مقصد</span><input class="pcdna-input pcdna-input-num" name="credit" dir="ltr" inputmode="decimal" value="' . View::e($o['credit']) . '">'
                . '<small>موجودی فعلی: ' . View::n((float) $src['svc']->credit, 2) . ' — ۰ یعنی بدون انتقال.</small></label>';
        } elseif ($dir === 'client_operator') {
            $hint = self::proRata($src['svc']);
            $f .= '<label><span>اعتبار برگشتی به مشتری (سهم باقی‌مانده)</span><input class="pcdna-input pcdna-input-num" name="credit" dir="ltr" inputmode="decimal" value="' . View::e($o['credit']) . '">'
                . '<small>' . ($hint !== null ? 'پیشنهاد سهم باقی‌مانده تا سررسید: ' . View::n($hint, 2) . ' — ' : '') . '۰ یعنی بدون اعتبار.</small></label>'
                . '<label><span>یادداشت دامنهٔ اپراتور (اختیاری)</span><input class="pcdna-input" name="note" maxlength="' . Operator::NOTE_MAX . '" value="' . View::e($o['note']) . '"></label>';
        } else {
            $prods = [];
            foreach (Data::products() as $p) {
                $prods[(int) $p->id] = $p->name;
            }
            $pid = $o['pid'] ?: (int) (array_keys($prods)[0] ?? 0);
            $cyc = [];
            foreach (self::cycles($pid, $cid) as $k => $price) {
                $cyc[$k] = self::CYCLES[$k][2] . ($price !== null ? ' — ' . View::n($price) : '');
            }
            $gws = self::gateways();
            $f .= '<label><span>محصول سرویس جدید</span>' . View::select('pid', $prods, $pid) . '</label>'
                . '<label><span>دورهٔ پرداخت</span>' . View::select('cycle', $cyc ?: ['monthly' => 'ماهانه'], $o['cycle']) . '<small>قیمت‌ها به ارز مشتری؛ پس از تغییر محصول، پیش‌نمایش دوره را دوباره بررسی می‌کند.</small></label>'
                . '<label><span>سررسید بعدی</span><input class="pcdna-input" type="date" name="nextdue" dir="ltr" value="' . View::e($o['nextdue']) . '" required></label>'
                . ($gws ? '<label><span>روش پرداخت</span>' . View::select('gateway', $gws, $o['gateway']) . '</label>' : '')
                . '<div class="pcdna-col-2">' . Pages::check('invoice', $o['invoice'], 'صدور اولین صورت‌حساب سرویس') . '</div>';
        }
        $f .= '<div class="pcdna-col-2">' . Pages::check('include_related', $o['include_related'], 'انتقال همراه زیردامنه‌ها (سایت‌های مرتبطِ همین مالک: زیردامنه / دامنهٔ والد)')
            . '<small>بدون این گزینه، اگر زیردامنه یا دامنهٔ والدِ همین مالک روی CDN باشد کنترلر انتقال را رد می‌کند. سرویس‌های WHMCS سایت‌های مرتبط جابه‌جا نمی‌شوند.</small></div>';
        if ($src['kind'] === 'client') {
            $f .= '<div>' . Pages::check('email_old', $o['email_old'], 'ایمیل «' . self::EMAIL_OLD . '» به مالک فعلی') . '</div>';
        }
        if ($dir !== 'client_operator') {
            $f .= '<div>' . Pages::check('email_new', $o['email_new'], 'ایمیل «' . self::EMAIL_NEW . '» به مالک جدید') . '</div>';
        }
        $f .= '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('search') . '<span>پیش‌نمایش انتقال</span></button></div></form>';
        return View::card('۲. گزینه‌های انتقال', $h . $f, '', '', 'sliders');
    }

    /** Pro-rata of the service's recurring amount until its next due date (a hint only). */
    private static function proRata($svc): ?float
    {
        $months = 0;
        foreach (self::CYCLES as [, $whmcs, , $m]) {
            if (strcasecmp($whmcs, (string) $svc->billingcycle) === 0) {
                $months = $m;
            }
        }
        $due = strtotime((string) $svc->nextduedate);
        $amount = (float) ($svc->amount ?? 0);
        if ($months <= 0 || !$due || $amount <= 0 || $due <= time()) {
            return null;
        }
        return round($amount * min(1.0, ($due - time()) / ($months * 30.44 * 86400)), 2);
    }

    private static function previewCard(array $pv, array $src, array $q, string $to, array $o): string
    {
        $dry = (array) $pv['dry'];
        $dir = $pv['dir'];
        $rel = self::domainsText($dry['related'] ?? []);
        $keys = $dry['revoked_keys'] ?? 0;
        $nKeys = is_array($keys) ? count($keys) : (int) $keys;
        $b = '<p>جهت: ' . View::badge(self::DIR_LABEL[$dir], 'brand') . '</p><h4>روی کنترلر (dry run)</h4><ul class="pcdna-bullets" data-dry-run="1">'
            . '<li>مالک: ' . View::e(self::ownerText($dry['from'] ?? null)) . ' ← ' . View::e(self::ownerText($dry['to'] ?? null)) . '</li>'
            . '<li>سایت‌های مرتبطی که همراه منتقل می‌شوند: ' . ($rel !== '' ? View::ltr($rel) : 'ندارد') . '</li>'
            . '<li>کلیدهای API مشتری که باطل می‌شوند: ' . View::n($nKeys) . '</li>'
            . '<li>یکپارچه‌سازی‌هایی که متوقف می‌شوند (رمزها پاک می‌شوند): ' . (($p = self::pausedText($dry['paused'] ?? [])) ? View::ltr(implode('; ', $p)) : 'ندارد') . '</li>'
            . (!empty($dry['access_rotated']) ? '<li>رمز دسترسی محافظت‌شده عوض می‌شود (نشست‌ها پایان می‌یابد): ' . View::ltr(self::domainsText($dry['access_rotated'])) . '</li>' : '')
            . (($rot = self::rotatedText($dry['rotated'] ?? null)) ? '<li data-rotated="1">این اعتبارنامه‌ها عوض می‌شوند: ' . View::ltr(implode('; ', $rot)) . '</li>' : '')
            . ($dir === 'operator_client' ? '<li>شروع شمارش مصرف مشتری: از لحظهٔ اجرا</li>' : '') . '</ul>';
        $b .= '<h4>در WHMCS</h4><ul class="pcdna-warnlist" data-whmcs-changes="1">';
        foreach ($pv['changes'] as [$tone, $html]) {
            $b .= '<li class="pcdna-w-' . ($tone === 'warn' ? 'warn' : ($tone === 'bad' ? 'bad' : 'ok')) . '">' . View::icon($tone === 'warn' ? 'warn' : ($tone === 'muted' ? 'info' : 'check')) . '<span>' . $html . '</span></li>';
        }
        $b .= '</ul>';
        $f = '<form method="post" action="' . View::url($q + ['to' => $to]) . '" class="pcdna-form" data-transfer-execute="1">' . self::hiddenSrc($q, $to)
            . '<input type="hidden" name="a" value="transfer_execute">';
        foreach (['move_unpaid', 'move_paid', 'include_related', 'email_old', 'email_new', 'invoice'] as $k) {
            if (!empty($o[$k])) {
                $f .= '<input type="hidden" name="' . $k . '" value="1">';
            }
        }
        foreach (['credit', 'pid', 'cycle', 'nextdue', 'gateway', 'note'] as $k) {
            $f .= '<input type="hidden" name="' . $k . '" value="' . View::e((string) $o[$k]) . '">';
        }
        $f .= '<div>' . Pages::check('confirm', false, 'تغییرات بالا را بررسی کردم؛ انتقال ' . $src['domain'] . ' انجام شود.') . '</div>'
            . '<div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-danger">' . View::icon('users') . '<span>اجرای انتقال</span></button>'
            . '<a class="pcdna-btn pcdna-btn-ghost" href="' . View::url($q + ['to' => $to]) . '">ویرایش گزینه‌ها</a></div></form>';
        return View::card('۳. پیش‌نمایش و تأیید', $b . $f, '', '', 'warn');
    }

    private static function ownerText($x): string
    {
        if (!is_array($x)) {
            return is_string($x) ? $x : '—';
        }
        if (($x['kind'] ?? '') === 'operator') {
            return 'اپراتور';
        }
        if (($x['kind'] ?? '') === 'reseller') {
            return 'نماینده #' . (int) ($x['reseller_client_id'] ?? $x['client_id'] ?? 0);
        }
        return 'مشتری #' . (int) ($x['client_id'] ?? 0) . (isset($x['external_id']) && $x['external_id'] !== null && $x['external_id'] !== '' ? ' (سرویس #' . $x['external_id'] . ')' : '');
    }

    private static function doneCard(array $steps, int $sid): string
    {
        $b = '<ol class="pcdna-timeline pcdna-xfer-steps" data-transfer-steps="1">';
        foreach ($steps as [$tone, $text]) {
            $b .= '<li class="pcdna-w-' . View::e($tone === 'ok' ? 'ok' : $tone) . '"><span dir="ltr">' . View::e($text) . '</span></li>';
        }
        return View::card('مراحل انتقال (در گزارش فعالیت WHMCS هم ثبت شد)', $b . '</ol>', '', '', 'history');
    }
}
