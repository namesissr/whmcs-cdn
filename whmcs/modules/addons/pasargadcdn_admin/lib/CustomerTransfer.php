<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use PasargadCdn\Shares;
use PasargadCdn\Transfers;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\CustomerTransfer', false)) {
    return;
}

/**
 * SPEC §19.3 — customer-initiated domain transfer.
 *
 *  - owner side (client app page «انتقال دامنه», api.php local op `xfer`, ownership / Active / team rights checked by
 *    ClientApi::localOp): GET state + summary; POST preview {email} (recipient check + controller dry run); POST create
 *    {email, message, confirm}; POST cancel {id}. One open request per service, ≤ 5 requests per owner per day.
 *  - recipient side (client area `index.php?m=pasargadcdn_admin&page=transfer[&token=…]`): the incoming requests with the
 *    same summary and Accept / Decline (client session + module CSRF; the request's recipient id AND primary e-mail must
 *    match). Token: 32 random bytes, only its SHA-256 stored, 7 days, single use, never logged.
 *  - accept → (setting «تأیید مدیر لازم است») waits in the admin «انتقال دامنه» tab for approve / reject, else runs at once:
 *    Transfer::runCustomer() — the SAME §19.2 client → client execute() path with the customer defaults.
 *  - every read re-validates an open request: the service must still be Active, owned by the requester, on the same domain
 *    and not handed to the operator; otherwise the request is cancelled (the module also cancels on Suspend / Terminate and
 *    the §19.2 execute() cancels it on any transfer). A daily cron expires requests older than 7 days.
 *  - e-mails: request to the recipient, result to the owner, notice to the admins; logActivity on both clients; the ledger
 *    row of the executed transfer carries initiated_by = client + request_id.
 *
 * Table mod_pasargadcdn_transfer_requests: id, service_id, domain, from_client, to_client, email, message, token_hash, status
 * pending|awaiting|done|declined|cancelled|expired|rejected|failed, reason, expires_at, created_by, created_at, accepted_at,
 * decided_at, admin_id, detail.
 */
final class CustomerTransfer
{
    const TABLE = Transfers::REQUESTS;
    const OPEN = Transfers::OPEN;
    const TTL = 604800;
    const DAILY = 5;
    const MSG_MAX = 300;
    const ROUTE = 'index.php?m=pasargadcdn_admin&page=transfer';
    const TOKEN_RE = '/^[0-9a-f]{64}$/D';
    const EMAIL_REQUEST = 'درخواست انتقال دامنه';
    const EMAIL_RESULT = 'نتیجهٔ درخواست انتقال دامنه';
    /** sha1 of earlier shipped bodies that may be upgraded in place (none yet — same mechanism as Shares::LEGACY_BODIES) */
    const LEGACY_BODIES = [];
    const CRON_KEY = 'xfer_expire_next';
    const STATUS = ['pending' => ['در انتظار پذیرش', 'Waiting for acceptance', 'warn'], 'awaiting' => ['در انتظار تأیید مدیر', 'Waiting for admin approval', 'brand'],
        'done' => ['انجام شد', 'Completed', 'ok'], 'declined' => ['رد شد', 'Declined', 'muted'], 'cancelled' => ['لغو شد', 'Cancelled', 'muted'],
        'expired' => ['منقضی شد', 'Expired', 'muted'], 'rejected' => ['رد توسط مدیر', 'Rejected by the administrator', 'bad'], 'failed' => ['ناموفق', 'Failed', 'bad']];

    /** @var callable|null tests: fn(): int */
    public static $clock = null;
    private static $ready = null;
    private static $memo = [];

    public static function now(): int
    {
        return self::$clock ? (int) (self::$clock)() : time();
    }

    private static function ts(?int $t = null): string
    {
        return date('Y-m-d H:i:s', $t ?? self::now());
    }

    public static function reset(): void
    {
        self::$ready = null;
        self::$memo = [];
    }

    public static function ensure(): bool
    {
        if (self::$ready === true) {
            return true;
        }
        try {
            $schema = Capsule::schema();
            if (!$schema->hasTable(self::TABLE)) {
                $schema->create(self::TABLE, function ($t) {
                    $t->increments('id');
                    $t->integer('service_id');
                    $t->string('domain', 253);
                    $t->integer('from_client');
                    $t->integer('to_client');
                    $t->string('email', 191);
                    $t->text('message')->nullable();
                    $t->char('token_hash', 64)->nullable();
                    $t->string('status', 16)->default('pending');
                    $t->string('reason', 64)->nullable();
                    $t->dateTime('expires_at')->nullable();
                    $t->string('created_by', 32)->default('');
                    $t->dateTime('created_at')->nullable();
                    $t->dateTime('accepted_at')->nullable();
                    $t->dateTime('decided_at')->nullable();
                    $t->integer('admin_id')->default(0);
                    $t->text('detail')->nullable();
                    $t->index(['service_id', 'status'], 'mod_pcdn_xreq_service');
                    $t->index(['to_client', 'status'], 'mod_pcdn_xreq_to');
                    $t->index(['from_client', 'created_at'], 'mod_pcdn_xreq_from');
                    $t->index('token_hash', 'mod_pcdn_xreq_token');
                });
            }
            Transfers::ensure();
            return self::$ready = true;
        } catch (\Throwable $e) {
            self::$ready = false;
            return false;
        }
    }

    // ------------------------------------------------------------------ settings / language

    public static function enabled(): bool
    {
        $s = function_exists('pasargadcdn_addon_settings') ? \pasargadcdn_addon_settings() : [];
        // off while the addon is not active; on by default (a 1.5.0 install upgraded in place has no row yet)
        return $s !== [] && (!array_key_exists('transfer_customer', $s) || in_array(strtolower(trim((string) $s['transfer_customer'])), ['on', '1', 'yes', 'true'], true));
    }

    public static function approval(): bool
    {
        $s = function_exists('pasargadcdn_addon_settings') ? \pasargadcdn_addon_settings() : [];
        return in_array(strtolower(trim((string) ($s['transfer_approval'] ?? ''))), ['on', '1', 'yes', 'true'], true);
    }

    private static function lang(): string
    {
        return function_exists('pasargadcdn_lang') ? \pasargadcdn_lang([]) : 'fa';
    }

    private static function tx(string $fa, string $en, ?string $lang = null): string
    {
        return ($lang ?? self::lang()) === 'en' ? $en : $fa;
    }

    private static function e($v): string
    {
        return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    private static function q()
    {
        return Capsule::table(self::TABLE);
    }

    private static function client(int $id)
    {
        return $id > 0 ? Capsule::table('tblclients')->where('id', $id)->first() : null;
    }

    /** Display name for the other party: company, else first name — never e-mail or contact data. */
    public static function displayName(int $id): string
    {
        $c = self::client($id);
        $n = $c ? trim((string) (($c->companyname ?? '') ?: ($c->firstname ?? ''))) : '';
        return $n !== '' ? $n : '—';
    }

    private static function log(string $msg, int $uid): void
    {
        Env::log('customer transfer ' . $msg, $uid);
    }

    // ------------------------------------------------------------------ summary (what moves / what is revoked)

    /** What moves with the service (live numbers; the same summary for owner, recipient and e-mail). */
    public static function summary($svc, string $lang = 'fa'): array
    {
        $cur = Capsule::table('tblcurrencies')->where('id', (int) (self::client((int) $svc->userid)->currency ?? 0))->first();
        $code = $cur ? trim((string) ($cur->suffix ?: $cur->code)) : '';
        $cyc = (string) ($svc->billingcycle ?? '');
        foreach (Transfer::CYCLES as [, $whmcs, $fa]) {
            if (strcasecmp($whmcs, $cyc) === 0 && $lang !== 'en') {
                $cyc = $fa;
            }
        }
        $inv = Transfer::invoices((int) $svc->id, (int) $svc->userid);
        $prod = Capsule::table('tblproducts')->where('id', (int) ($svc->packageid ?? 0))->value('name');
        return ['service_id' => (int) $svc->id, 'domain' => Env::domain((string) $svc->domain), 'product' => (string) $prod, 'cycle' => $cyc,
            'nextdue' => (string) ($svc->nextduedate ?? ''), 'amount' => round((float) ($svc->amount ?? 0), 2), 'currency' => ltrim($code),
            'unpaid' => ['count' => count($inv['unpaid']), 'total' => round(array_sum(array_map(function ($i) { return (float) $i->total; }, $inv['unpaid'])), 2)],
            'shares' => Transfer::liveShares(Env::domain((string) $svc->domain))];
    }

    /** What the controller revokes / rotates (dry run). [array|null, error string|null] */
    private static function dryRun($svc, int $toClient): array
    {
        try {
            $server = Capsule::table('tblservers')->where('id', (int) $svc->server)->first();
            $api = Env::api(15, $server && ($server->type ?? '') === 'pasargadcdn' ? $server : null);
            $r = $api->post(ApiClient::site(Env::domain((string) $svc->domain)) . Transfer::PATH, ['to' => ['kind' => 'client', 'client_id' => $toClient,
                'external_id' => (string) $svc->id], 'reset_billing_anchor' => false, 'revoke_credentials' => true, 'pause_integrations' => true,
                'include_related' => false, 'dry_run' => true]);
        } catch (\Throwable $e) {
            return [null, $e->getMessage()];
        }
        $rot = is_array($r['rotated'] ?? null) ? $r['rotated'] : [];
        return [['revoked_keys' => is_array($r['revoked_keys'] ?? null) ? count($r['revoked_keys']) : (int) ($r['revoked_keys'] ?? 0),
            'paused' => count((array) ($r['paused'] ?? [])), 'access' => !empty($r['access_rotated']),
            'storage' => count((array) ($rot['buckets']['pending'] ?? [])) + count((array) ($rot['buckets']['done'] ?? [])),
            'tsig' => count((array) ($rot['tsig'] ?? [])), 'image_key' => !empty($rot['image_key'])], null];
    }

    // ------------------------------------------------------------------ validation

    /**
     * Why an open request can no longer run ('' = fine): the service changed status / owner / domain or was handed to the
     * operator, the recipient's primary e-mail changed, or it expired.
     */
    public static function problem($r): string
    {
        $svc = Capsule::table('tblhosting')->where('id', (int) $r->service_id)->first(['id', 'userid', 'domain', 'domainstatus', 'packageid']);
        if (!$svc || (int) $svc->userid !== (int) $r->from_client || Env::domain((string) $svc->domain) !== (string) $r->domain) {
            return 'transferred';
        }
        if (!Env::isCdnProduct((int) $svc->packageid) || Transfers::guarded((int) $svc->id)) {
            return 'transferred';
        }
        if ((string) $svc->domainstatus !== 'Active') {
            return strtolower((string) $svc->domainstatus) ?: 'inactive';
        }
        $c = self::client((int) $r->to_client);
        if (!$c || strtolower(trim((string) $c->email)) !== (string) $r->email) {
            return 'recipient_changed';
        }
        if ($r->status === 'pending' && strtotime((string) $r->expires_at) <= self::now()) {
            return 'expired';
        }
        return '';
    }

    /** Re-validates an open row; ends it when it can no longer run. Returns the (fresh) row. */
    private static function settle($r)
    {
        if (!$r || !in_array((string) $r->status, self::OPEN, true)) {
            return $r;
        }
        $why = self::problem($r);
        if ($why === '') {
            return $r;
        }
        $st = $why === 'expired' ? 'expired' : 'cancelled';
        $n = self::q()->where('id', (int) $r->id)->whereIn('status', self::OPEN)->update(['status' => $st, 'reason' => $why, 'token_hash' => null, 'decided_at' => self::ts()]);
        if ($n) {
            self::log('#' . (int) $r->id . ' (' . $r->domain . ') ' . $st . ': ' . $why, (int) $r->from_client);
            self::log('#' . (int) $r->id . ' (' . $r->domain . ') ' . $st . ': ' . $why, (int) $r->to_client);
            if ($st === 'expired') {
                self::mailResult($r, 'expired');
            }
        }
        return self::q()->where('id', (int) $r->id)->first();
    }

    /** The open request of a service (validated), or null. */
    public static function openFor(int $sid)
    {
        if (!self::ensure()) {
            return null;
        }
        $r = self::q()->where('service_id', $sid)->whereIn('status', self::OPEN)->orderBy('id', 'desc')->first();
        $r = self::settle($r);
        return $r && in_array((string) $r->status, self::OPEN, true) ? $r : null;
    }

    // ------------------------------------------------------------------ owner side (api.php local op `xfer`)

    private static function view($r, string $lang): array
    {
        [$fa, $en] = self::STATUS[(string) $r->status] ?? [(string) $r->status, (string) $r->status];
        return ['id' => (int) $r->id, 'email' => (string) $r->email, 'recipient' => self::displayName((int) $r->to_client), 'message' => (string) ($r->message ?? ''),
            'status' => (string) $r->status, 'status_label' => $lang === 'en' ? $en : $fa, 'reason' => (string) ($r->reason ?? ''),
            'created_at' => (string) $r->created_at, 'expires_at' => (string) $r->expires_at, 'decided_at' => $r->decided_at ? (string) $r->decided_at : null];
    }

    /** Recipient by e-mail for owner $ownerId: [client row, null] or [null, error (fa, en)]. */
    private static function recipient(string $email, int $ownerId): array
    {
        $email = strtolower(trim($email));
        if (!Shares::validEmail($email)) {
            return [null, ['ایمیل نامعتبر است.', 'Invalid e-mail address.']];
        }
        $c = Capsule::table('tblclients')->whereRaw('LOWER(email) = ?', [$email])->first();
        if (!$c) {
            return [null, ['حساب مشتری با این ایمیل وجود ندارد؛ گیرنده باید ابتدا با همین ایمیل ثبت‌نام کند.', 'No client account uses this e-mail; the recipient must register with it first.']];
        }
        if ((int) $c->id === $ownerId) {
            return [null, ['نمی‌توانید دامنه را به حساب خودتان منتقل کنید.', 'You cannot transfer the domain to your own account.']];
        }
        if (strtolower((string) ($c->status ?? 'Active')) === 'closed') {
            return [null, ['حساب گیرنده بسته شده است.', 'The recipient\'s account is closed.']];
        }
        return [$c, null];
    }

    /** [status, data] of the owner's local op (service ownership, CSRF and Active-for-writes already checked by ClientApi). */
    public static function ownerOp(string $method, $svc, array $req): array
    {
        $lang = ($req['lang'] ?? '') === 'en' ? 'en' : 'fa';
        $fail = function (int $code, string $fa, string $en) use ($lang) {
            return [$code, ['detail' => $lang === 'en' ? $en : $fa]];
        };
        if (!self::enabled()) {
            return $fail(404, 'انتقال دامنه توسط مشتری فعال نیست.', 'Customer domain transfers are not enabled.');
        }
        if (!empty($req['readonly'])) {
            return $fail(403, 'دسترسی شما به این سرویس فقط‌خواندنی است.', 'Your access to this service is read-only.');
        }
        if (!self::ensure()) {
            return $fail(503, 'ذخیره در WHMCS ممکن نشد؛ دوباره تلاش کنید.', 'Could not save in WHMCS; please try again.');
        }
        $svc = Capsule::table('tblhosting')->where('id', (int) $svc->id)->first();
        $sid = (int) $svc->id;
        $owner = (int) $svc->userid;
        if (Transfers::guarded($sid)) {
            return $fail(403, 'این سرویس دیگر دامنه‌ای روی CDN ندارد.', 'This service no longer has a domain on the CDN.');
        }
        $state = function () use ($svc, $sid, $owner, $lang) {
            $open = self::openFor($sid);
            $recent = self::q()->where('service_id', $sid)->where('from_client', $owner)->orderBy('id', 'desc')->limit(5)->get()->all();
            return ['enabled' => true, 'approval' => self::approval(), 'active' => (string) $svc->domainstatus === 'Active',
                'request' => $open ? self::view($open, $lang) : null, 'summary' => self::summary($svc, $lang),
                'recent' => array_map(function ($r) use ($lang) { return self::view($r, $lang); }, $recent)];
        };
        if ($method === 'GET') {
            return [200, $state()];
        }
        $raw = (string) ($req['body'] ?? '');
        $data = $raw === '' ? [] : json_decode($raw, true, 8);
        $action = is_array($data) && is_string($data['action'] ?? null) ? $data['action'] : '';
        if (!in_array($action, ['preview', 'create', 'cancel'], true)) {
            return $fail(400, 'پارامتر نامعتبر است.', 'Invalid parameter.');
        }
        $who = 'client #' . (int) ($req['client_id'] ?? 0);
        if ($action === 'cancel') {
            $id = (int) ($data['id'] ?? 0);
            // until accepted: an accepted request waiting for the admin is decided by the admin
            $n = self::q()->where('id', $id)->where('service_id', $sid)->where('from_client', $owner)->where('status', 'pending')
                ->update(['status' => 'cancelled', 'reason' => 'owner', 'token_hash' => null, 'decided_at' => self::ts()]);
            if (!$n) {
                return $fail(404, 'درخواست در انتظار پذیرشی پیدا نشد.', 'No request waiting for acceptance found.');
            }
            $r = self::q()->where('id', $id)->first();
            self::log('#' . $id . ' (' . $r->domain . ' → client #' . (int) $r->to_client . ') cancelled by the owner (' . $who . ')', $owner);
            self::log('#' . $id . ' (' . $r->domain . ' from client #' . $owner . ') cancelled by the owner', (int) $r->to_client);
            return [200, $state()];
        }
        if ((string) $svc->domainstatus !== 'Active') {
            return $fail(403, 'این سرویس فعال نیست.', 'This service is not active.');
        }
        if (self::openFor($sid)) {
            return $fail(409, 'برای این سرویس یک درخواست انتقال باز هست؛ ابتدا آن را لغو کنید.', 'This service already has an open transfer request; cancel it first.');
        }
        [$c, $err] = self::recipient(is_string($data['email'] ?? null) ? $data['email'] : '', $owner);
        if (!$c) {
            return $fail(400, $err[0], $err[1]);
        }
        [$dry, $dryErr] = self::dryRun($svc, (int) $c->id);
        if ($dry === null) {
            return $fail(422, 'سرور CDN این انتقال را نمی‌پذیرد: ' . $dryErr, 'The CDN server refuses this transfer: ' . $dryErr);
        }
        if ($action === 'preview') {
            return [200, ['recipient' => self::displayName((int) $c->id), 'summary' => self::summary($svc, $lang), 'revoke' => $dry]];
        }
        $msg = is_string($data['message'] ?? null) ? trim($data['message']) : '';
        $len = function_exists('mb_strlen') ? mb_strlen($msg, 'UTF-8') : strlen($msg);
        if ($len > self::MSG_MAX || !preg_match('//u', $msg) || preg_match('/[\x00-\x08\x0B-\x1F\x7F]/', $msg) || preg_match('/<[a-z\/!]/i', $msg)) {
            return $fail(400, 'پیام حداکثر ۳۰۰ نویسهٔ متن ساده باشد.', 'The message must be plain text of at most 300 characters.');
        }
        if (($data['confirm'] ?? null) !== true) {
            return $fail(400, 'برای ارسال درخواست، تأیید را علامت بزنید.', 'Tick the confirmation to send the request.');
        }
        $today = self::q()->where('from_client', $owner)->where('created_at', '>', self::ts(self::now() - 86400))->count();
        if ($today >= self::DAILY) {
            return $fail(429, 'حداکثر ۵ درخواست انتقال در روز مجاز است.', 'At most 5 transfer requests per day are allowed.');
        }
        $token = bin2hex(random_bytes(32));
        $id = (int) self::q()->insertGetId(['service_id' => $sid, 'domain' => Env::domain((string) $svc->domain), 'from_client' => $owner, 'to_client' => (int) $c->id,
            'email' => strtolower(trim((string) $c->email)), 'message' => $msg, 'token_hash' => self::hash($token), 'status' => 'pending',
            'expires_at' => self::ts(self::now() + self::TTL), 'created_by' => 'client:' . (int) ($req['client_id'] ?? $owner), 'created_at' => self::ts()]);
        $r = self::q()->where('id', $id)->first();
        $mailed = self::mailRequest($r, $token, $svc);
        self::log('#' . $id . ' ' . $r->domain . ' (service #' . $sid . ') requested to client #' . (int) $c->id . ' by ' . $who . ($mailed ? ', e-mailed' : ', e-mail failed'), $owner);
        self::log('#' . $id . ' incoming request for ' . $r->domain . ' from client #' . $owner, (int) $c->id);
        return [201, $state() + ['mailed' => $mailed]];
    }

    // ------------------------------------------------------------------ recipient side

    /** Open requests addressed to this client (validated, memoised per request). */
    public static function incoming(int $clientId): array
    {
        if ($clientId <= 0 || !self::ensure()) {
            return [];
        }
        if (!isset(self::$memo[$clientId])) {
            $rows = self::q()->where('to_client', $clientId)->whereIn('status', self::OPEN)->orderBy('id')->get()->all();
            self::$memo[$clientId] = array_values(array_filter(array_map([self::class, 'settle'], $rows), function ($r) {
                return $r && in_array((string) $r->status, self::OPEN, true);
            }));
        }
        return self::$memo[$clientId];
    }

    /** Count of pending requests waiting for this client's answer. */
    public static function pendingCount(int $clientId): int
    {
        return count(array_filter(self::incoming($clientId), function ($r) {
            return $r->status === 'pending';
        }));
    }

    private static function csrf(): string
    {
        return function_exists('pasargadcdn_csrf_token') ? \pasargadcdn_csrf_token() : '';
    }

    private static function csrfOk($v): bool
    {
        $s = (string) ($_SESSION['pasargadcdn_csrf'] ?? '');
        return $s !== '' && is_string($v) && hash_equals($s, $v);
    }

    /** The request of $id or $token for recipient $clientId (IDOR guard: other clients get null). */
    private static function forRecipient(int $id, string $token, int $clientId)
    {
        if ($clientId <= 0 || !self::ensure()) {
            return null;
        }
        if ($token !== '') {
            if (!preg_match(self::TOKEN_RE, $token)) {
                return null;
            }
            $r = self::q()->where('token_hash', self::hash($token))->first();
        } else {
            $r = $id > 0 ? self::q()->where('id', $id)->first() : null;
        }
        return $r && (int) $r->to_client === $clientId ? self::settle($r) : null;
    }

    private static function emailMatches($r, int $clientId): bool
    {
        $c = self::client($clientId);
        return $c && strtolower(trim((string) $c->email)) === (string) $r->email;
    }

    /** Accept / decline: [tone, message]. */
    public static function answer(int $id, string $token, int $clientId, bool $accept): array
    {
        $r = self::forRecipient($id, $token, $clientId);
        if (!$r || !self::emailMatches($r, $clientId)) {
            return ['danger', self::tx('درخواست انتقال پیدا نشد یا برای حساب دیگری است.', 'Transfer request not found, or it is for another account.')];
        }
        if ($r->status !== 'pending') {
            [$fa, $en] = self::STATUS[(string) $r->status] ?? [(string) $r->status, (string) $r->status];
            return ['warning', self::tx('این درخواست دیگر قابل پاسخ نیست: ' . $fa, 'This request can no longer be answered: ' . $en)];
        }
        if (!$accept) {
            self::q()->where('id', (int) $r->id)->where('status', 'pending')->update(['status' => 'declined', 'token_hash' => null, 'decided_at' => self::ts()]);
            self::log('#' . (int) $r->id . ' (' . $r->domain . ') declined by the recipient', $clientId);
            self::log('#' . (int) $r->id . ' (' . $r->domain . ') declined by client #' . $clientId, (int) $r->from_client);
            self::mailResult($r, 'declined');
            self::$memo = [];
            return ['info', self::tx('درخواست انتقال رد شد.', 'Transfer request declined.')];
        }
        // single use: the token is cleared the moment the request is claimed
        $n = self::q()->where('id', (int) $r->id)->where('status', 'pending')
            ->update(['status' => 'awaiting', 'token_hash' => null, 'accepted_at' => self::ts()]);
        if (!$n) {
            return ['warning', self::tx('این درخواست دیگر قابل پاسخ نیست.', 'This request can no longer be answered.')];
        }
        self::$memo = [];
        self::log('#' . (int) $r->id . ' (' . $r->domain . ') accepted by the recipient', $clientId);
        self::log('#' . (int) $r->id . ' (' . $r->domain . ') accepted by client #' . $clientId, (int) $r->from_client);
        if (self::approval()) {
            self::adminNotice($r, 'awaiting');
            self::mailResult($r, 'awaiting');
            return ['info', self::tx('درخواست پذیرفته شد و پس از تأیید مدیر انجام می‌شود.', 'Accepted; the transfer runs once an administrator approves it.')];
        }
        $row = self::q()->where('id', (int) $r->id)->first();
        [$ok, $msg] = self::execute($row, 0);
        return $ok ? ['success', self::tx('انتقال انجام شد؛ ' . $r->domain . ' اکنون در فهرست سرویس‌های شماست.', 'Done — ' . $r->domain . ' is now one of your services.')]
            : ['danger', self::tx('انتقال انجام نشد: ', 'The transfer failed: ') . $msg];
    }

    /** Runs an accepted (awaiting) request through Transfer::runCustomer(). [ok, message] */
    public static function execute($r, int $admin): array
    {
        $why = self::problem($r);
        if ($why !== '' && $why !== 'expired') {
            self::q()->where('id', (int) $r->id)->whereIn('status', self::OPEN)->update(['status' => 'cancelled', 'reason' => $why, 'token_hash' => null, 'decided_at' => self::ts()]);
            self::log('#' . (int) $r->id . ' (' . $r->domain . ') cancelled before running: ' . $why, (int) $r->from_client);
            self::mailResult($r, 'failed', $why);
            return [false, $why];
        }
        [$ok, $msg, $steps] = Transfer::runCustomer((int) $r->service_id, (int) $r->to_client, (int) $r->id, $admin);
        self::q()->where('id', (int) $r->id)->update(['status' => $ok ? 'done' : 'failed', 'reason' => $ok ? null : 'error', 'token_hash' => null,
            'decided_at' => self::ts(), 'admin_id' => $admin,
            'detail' => json_encode(['message' => $msg, 'steps' => array_map(function ($s) { return $s[1] ?? ''; }, $steps)], JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR)]);
        self::log('#' . (int) $r->id . ' (' . $r->domain . ') ' . ($ok ? 'executed — the service moved to client #' . (int) $r->to_client : 'failed: ' . $msg), (int) $r->from_client);
        self::log('#' . (int) $r->id . ' (' . $r->domain . ') ' . ($ok ? 'executed — the service is now yours' : 'failed: ' . $msg), (int) $r->to_client);
        self::mailResult($r, $ok ? ($admin > 0 ? 'approved' : 'done') : 'failed', $ok ? '' : $msg);
        self::adminNotice($r, $ok ? 'done' : 'failed', $msg);
        self::$memo = [];
        return [$ok, $msg];
    }

    /** Client area route page=transfer: a WHMCS client-area array. */
    public static function clientArea(array $get, array $post, string $method, int $clientId): array
    {
        $title = self::tx('انتقال دامنه به حساب شما', 'Domain transfers to your account');
        $html = $clientId > 0 ? self::page($get, $post, $method, $clientId) : '';
        return ['pagetitle' => $title, 'breadcrumb' => [self::ROUTE => $title], 'templatefile' => 'pricing', 'requirelogin' => true,
            'forcessl' => false, 'vars' => ['pcdn_html' => $html, 'pcdn_lang' => self::lang()]];
    }

    private static function form(string $action, array $fields, string $label, string $cls, string $confirm = ''): string
    {
        $h = '<form method="post" action="' . self::e(self::ROUTE) . '" style="display:inline-block;margin:2px"'
            . ($confirm !== '' ? ' onsubmit="return confirm(this.getAttribute(\'data-confirm\'))" data-confirm="' . self::e($confirm) . '"' : '') . '>'
            . '<input type="hidden" name="pcdn_csrf" value="' . self::e(self::csrf()) . '"><input type="hidden" name="a" value="' . self::e($action) . '">';
        foreach ($fields as $k => $v) {
            $h .= '<input type="hidden" name="' . self::e($k) . '" value="' . self::e($v) . '">';
        }
        return $h . '<button type="submit" class="' . self::e($cls) . '">' . self::e($label) . '</button></form>';
    }

    /** The summary list shown to the recipient (same facts as the owner sees). */
    public static function summaryHtml(array $s, string $lang): string
    {
        $li = function ($fa, $en, $v) use ($lang) {
            return '<li><strong>' . self::e(self::tx($fa, $en, $lang)) . ':</strong> ' . $v . '</li>';
        };
        $money = function ($v) use ($s) {
            return self::e(number_format((float) $v, (float) $v == (int) $v ? 0 : 2) . ($s['currency'] !== '' ? ' ' . $s['currency'] : ''));
        };
        return '<ul class="pcdn-xfer-summary" data-xfer-summary="1">'
            . $li('سرویس', 'Service', '#' . (int) $s['service_id'] . ' — ' . self::e($s['product']))
            . $li('دامنه', 'Domain', '<span dir="ltr">' . self::e($s['domain']) . '</span>')
            . $li('دورهٔ پرداخت', 'Billing cycle', self::e($s['cycle']))
            . $li('سررسید بعدی', 'Next due date', '<span dir="ltr">' . self::e($s['nextdue']) . '</span>')
            . $li('مبلغ تمدید', 'Recurring amount', $money($s['amount']))
            . $li('صورت‌حساب‌های پرداخت‌نشدهٔ همین سرویس که منتقل می‌شوند', 'Unpaid invoices of this service that move', (int) $s['unpaid']['count']
                . ((int) $s['unpaid']['count'] > 0 ? ' — ' . $money($s['unpaid']['total']) : ''))
            . '<li>' . self::e(self::tx('همهٔ تنظیمات، رکوردهای DNS، SSL، قوانین و آمار سایت هم منتقل می‌شوند. کلیدهای API، رمز وب‌هوک‌ها و ارسال لاگ، نشست‌های دسترسی محافظت‌شده و کلیدهای ذخیره‌سازی باطل یا عوض می‌شوند و اشتراک‌های دامنه لغو می‌شوند.',
                'All settings, DNS records, SSL, rules and statistics move too. API keys, webhook / log-export secrets, protected-access sessions and storage keys are revoked or rotated, and domain shares are revoked.', $lang)) . '</li></ul>';
    }

    private static function page(array $get, array $post, string $method, int $clientId): string
    {
        $lang = self::lang();
        $flash = '';
        if ($method === 'POST') {
            if (!self::csrfOk($post['pcdn_csrf'] ?? null)) {
                $flash = '<div class="alert alert-danger" data-xfer-flash="danger">' . self::e(self::tx('درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.', 'Invalid request; reload the page.')) . '</div>';
            } else {
                $a = is_string($post['a'] ?? null) ? $post['a'] : '';
                [$tone, $msg] = in_array($a, ['accept', 'decline'], true)
                    ? self::answer((int) ($post['id'] ?? 0), is_string($post['token'] ?? null) ? $post['token'] : '', $clientId, $a === 'accept')
                    : ['danger', self::tx('عملیات نامعتبر است.', 'Invalid action.')];
                $flash = '<div class="alert alert-' . $tone . '" role="status" data-xfer-flash="' . self::e($tone) . '">' . self::e($msg) . '</div>';
            }
        }
        $h = '<div class="pcdn-xfer-page" dir="' . ($lang === 'en' ? 'ltr' : 'rtl') . '" data-xfer-page="1">' . $flash;
        $tok = is_string($get['token'] ?? null) ? $get['token'] : '';
        if ($tok !== '' && $method !== 'POST') {
            $r = self::forRecipient(0, $tok, $clientId);
            if (!$r || !self::emailMatches($r, $clientId)) {
                $any = preg_match(self::TOKEN_RE, $tok) && self::ensure() ? self::q()->where('token_hash', self::hash($tok))->first() : null;
                $h .= '<div class="alert alert-warning" data-xfer-state="' . ($any ? 'wrong-account' : 'invalid') . '">' . self::e($any
                    ? self::tx('این درخواست برای حساب دیگری است؛ با حسابی وارد شوید که ایمیل اصلی آن همان ایمیل درخواست است.', 'This request is for another account; log in with the account whose primary e-mail received it.')
                    : self::tx('درخواست انتقال پیدا نشد یا قبلاً پاسخ داده شده است.', 'Transfer request not found or already answered.')) . '</div>';
            }
        }
        $rows = self::incoming($clientId);
        if (!$rows) {
            $h .= '<div class="alert alert-info" data-xfer-empty="1">' . self::e(self::tx('درخواست انتقال دامنه‌ای برای شما در انتظار نیست.', 'No domain transfer is waiting for you.')) . '</div>';
        }
        foreach ($rows as $r) {
            $svc = Capsule::table('tblhosting')->where('id', (int) $r->service_id)->first();
            $h .= '<div class="panel panel-default card" data-xfer-request="' . (int) $r->id . '" style="margin-bottom:16px"><div class="panel-body card-body">'
                . '<h3 style="margin-top:0;font-size:17px"><span dir="ltr">' . self::e($r->domain) . '</span> — ' . self::e(self::tx('از طرف ', 'from ') . self::displayName((int) $r->from_client)) . '</h3>'
                . ((string) ($r->message ?? '') !== '' ? '<blockquote class="pcdn-xfer-msg" dir="auto" style="white-space:pre-wrap;overflow-wrap:anywhere;font-size:14px;border-inline-start:3px solid #d1d5db;margin:8px 0;padding:6px 12px">' . self::e($r->message) . '</blockquote>' : '')
                . ($svc ? self::summaryHtml(self::summary($svc, $lang), $lang) : '')
                . '<p class="text-muted small">' . self::e(self::tx('پس از پذیرش، سرویس با همان دوره و سررسید به حساب شما منتقل می‌شود و صورت‌حساب‌های بعدی آن برای شما صادر می‌شود. اعتبار حساب و صورت‌حساب‌های پرداخت‌شده منتقل نمی‌شوند.',
                    'After you accept, the service moves to your account with the same cycle and due date and its next invoices are issued to you. Account credit and paid invoices do not move.')) . '</p>';
            if ($r->status === 'awaiting') {
                $h .= '<div class="alert alert-info" data-xfer-state="awaiting">' . self::e(self::tx('پذیرفته‌اید؛ انتقال پس از تأیید مدیر انجام می‌شود.', 'Accepted; the transfer runs after an administrator approves it.')) . '</div>';
            } else {
                $h .= '<p class="small">' . self::e(self::tx('اعتبار این درخواست تا ', 'Valid until ')) . '<span dir="ltr">' . self::e(substr((string) $r->expires_at, 0, 16)) . '</span></p>'
                    . self::form('accept', ['id' => (int) $r->id], self::tx('پذیرش انتقال', 'Accept transfer'), 'btn btn-primary',
                        self::tx('سرویس ' . $r->domain . ' با صورت‌حساب‌هایش به حساب شما منتقل شود؟', 'Move ' . $r->domain . ' with its invoices to your account?'))
                    . self::form('decline', ['id' => (int) $r->id], self::tx('رد', 'Decline'), 'btn btn-default');
            }
            $h .= '</div></div>';
        }
        return $h . '</div>';
    }

    /** Home card body of pending requests ('' when none). */
    public static function homeCard(int $clientId): string
    {
        $rows = self::incoming($clientId);
        if (!$rows) {
            return '';
        }
        $h = '<div class="pcdn-xfer-card" data-xfer-card="1"><ul class="list-unstyled">';
        foreach ($rows as $r) {
            $h .= '<li><strong dir="ltr">' . self::e($r->domain) . '</strong> — ' . self::e(self::tx('از طرف ', 'from ') . self::displayName((int) $r->from_client))
                . ' <small class="text-muted">' . self::e($r->status === 'awaiting' ? self::tx('در انتظار تأیید مدیر', 'waiting for approval') : self::tx('در انتظار پاسخ شما', 'waiting for your answer')) . '</small></li>';
        }
        return $h . '</ul></div>';
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
            self::EMAIL_REQUEST => ['درخواست انتقال دامنه {$xfer_domain} به حساب شما',
                $fa('<p>{$xfer_owner} می‌خواهد سرویس CDN دامنهٔ <strong dir="ltr">{$xfer_domain}</strong> را به حساب شما منتقل کند.</p>'
                    . '{if $xfer_message}<p style="background:#f4f6f8;padding:8px 12px;white-space:pre-wrap">{$xfer_message}</p>{/if}'
                    . '<ul><li>سرویس: {$xfer_product} — دورهٔ پرداخت: {$xfer_cycle}</li><li>سررسید بعدی: <span dir="ltr">{$xfer_nextdue}</span> — مبلغ تمدید: {$xfer_amount}</li>'
                    . '<li>صورت‌حساب‌های پرداخت‌نشدهٔ همین سرویس که به شما منتقل می‌شوند: {$xfer_unpaid}</li></ul>'
                    . '<p>با پذیرش، سرویس با همهٔ تنظیمات و صورت‌حساب‌های بعدی‌اش به حساب شما می‌آید. <a href="{$xfer_link}">مشاهده و پذیرش یا رد درخواست</a> — این پیوند تا {$xfer_expires} معتبر است.</p>'),
                'Request to transfer {$xfer_domain} to your account',
                $en('<p>{$xfer_owner} wants to transfer the CDN service of <strong>{$xfer_domain}</strong> to your account.</p>'
                    . '{if $xfer_message}<p style="background:#f4f6f8;padding:8px 12px;white-space:pre-wrap">{$xfer_message}</p>{/if}'
                    . '<ul><li>Service: {$xfer_product} — billing cycle: {$xfer_cycle}</li><li>Next due date: {$xfer_nextdue} — recurring amount: {$xfer_amount}</li>'
                    . '<li>Unpaid invoices of this service that move to you: {$xfer_unpaid}</li></ul>'
                    . '<p>If you accept, the service with all its settings and its next invoices comes to your account. <a href="{$xfer_link}">View and accept or decline the request</a> — the link is valid until {$xfer_expires}.</p>')],
            self::EMAIL_RESULT => ['درخواست انتقال {$xfer_domain}: {$xfer_result}',
                $fa('<p>نتیجهٔ درخواست انتقال سرویس CDN دامنهٔ <strong dir="ltr">{$xfer_domain}</strong> به {$xfer_recipient}: <strong>{$xfer_result}</strong>.</p>{if $xfer_note}<p>{$xfer_note}</p>{/if}'),
                'Transfer request for {$xfer_domain}: {$xfer_result}',
                $en('<p>Your request to transfer the CDN service of <strong>{$xfer_domain}</strong> to {$xfer_recipient}: <strong>{$xfer_result}</strong>.</p>{if $xfer_note}<p>{$xfer_note}</p>{/if}')],
        ];
    }

    /** Creates the templates when missing; an unedited earlier body (LEGACY_BODIES) is upgraded, an edited one never touched. */
    public static function ensureTemplates(): void
    {
        $now = date('Y-m-d H:i:s');
        $cols = Capsule::schema()->getColumnListing('tblemailtemplates');
        foreach (self::templates() as $name => [$faSub, $faBody, $enSub, $enBody]) {
            foreach (['' => [$faSub, $faBody], 'english' => [$enSub, $enBody]] as $lang => [$sub, $body]) {
                $cur = Capsule::table('tblemailtemplates')->where('type', 'general')->where('name', $name)->where('language', $lang)->first(['id', 'message']);
                if ($cur) {
                    if (in_array(sha1((string) $cur->message), self::LEGACY_BODIES, true)) {
                        Capsule::table('tblemailtemplates')->where('id', (int) $cur->id)->update(['message' => $body, 'subject' => $sub]);
                    }
                    continue;
                }
                Capsule::table('tblemailtemplates')->insert(array_intersect_key(['type' => 'general', 'name' => $name, 'subject' => $sub, 'message' => $body,
                    'attachments' => '', 'fromname' => '', 'fromemail' => '', 'disabled' => 0, 'custom' => 1, 'language' => $lang, 'copyto' => '',
                    'blind_copy_to' => '', 'plaintext' => 0, 'created_at' => $now, 'updated_at' => $now], array_flip($cols)));
            }
        }
    }

    private static function send(string $tpl, int $clientId, array $vars): bool
    {
        try {
            self::ensureTemplates();
        } catch (\Throwable $e) {
            return false;
        }
        $r = Env::localApi('SendEmail', ['messagename' => $tpl, 'id' => $clientId, 'customvars' => base64_encode(serialize($vars))]);
        return ($r['result'] ?? '') === 'success';
    }

    private static function clientLang(int $id): string
    {
        $c = self::client($id);
        return strtolower((string) ($c->language ?? '')) === 'english' ? 'en' : 'fa';
    }

    private static function mailRequest($r, string $token, $svc): bool
    {
        $lang = self::clientLang((int) $r->to_client);
        $s = self::summary($svc, $lang);
        $amount = number_format((float) $s['amount'], (float) $s['amount'] == (int) $s['amount'] ? 0 : 2) . ($s['currency'] !== '' ? ' ' . $s['currency'] : '');
        return self::send(self::EMAIL_REQUEST, (int) $r->to_client, ['xfer_domain' => (string) $r->domain, 'xfer_owner' => self::displayName((int) $r->from_client),
            'xfer_message' => (string) ($r->message ?? ''), 'xfer_product' => $s['product'], 'xfer_cycle' => $s['cycle'], 'xfer_nextdue' => $s['nextdue'],
            'xfer_amount' => $amount, 'xfer_unpaid' => (string) $s['unpaid']['count'],
            'xfer_link' => Shares::systemUrl() . self::ROUTE . '&token=' . $token, 'xfer_expires' => substr((string) $r->expires_at, 0, 10)]);
    }

    const RESULT = ['done' => ['انجام شد', 'completed'], 'approved' => ['با تأیید مدیر انجام شد', 'approved and completed'],
        'awaiting' => ['پذیرفته شد؛ در انتظار تأیید مدیر', 'accepted, waiting for administrator approval'], 'declined' => ['توسط گیرنده رد شد', 'declined by the recipient'],
        'expired' => ['منقضی شد (۷ روز بی‌پاسخ)', 'expired (no answer in 7 days)'], 'rejected' => ['توسط مدیر رد شد', 'rejected by the administrator'],
        'failed' => ['انجام نشد', 'failed']];

    private static function mailResult($r, string $kind, string $note = ''): bool
    {
        $lang = self::clientLang((int) $r->from_client);
        [$fa, $en] = self::RESULT[$kind] ?? [$kind, $kind];
        return self::send(self::EMAIL_RESULT, (int) $r->from_client, ['xfer_domain' => (string) $r->domain, 'xfer_result' => $lang === 'en' ? $en : $fa,
            'xfer_recipient' => self::displayName((int) $r->to_client), 'xfer_note' => $note]);
    }

    /** Admin notice (WHMCS SendAdminEmail, custom subject / message to the system admins). */
    private static function adminNotice($r, string $kind, string $note = ''): void
    {
        [$fa] = self::RESULT[$kind] ?? [$kind];
        $msg = 'درخواست انتقال مشتری #' . (int) $r->id . ': ' . $r->domain . ' (سرویس #' . (int) $r->service_id . ') از مشتری #' . (int) $r->from_client
            . ' به مشتری #' . (int) $r->to_client . ' — ' . $fa . ($note !== '' ? ' — ' . $note : '') . '. ' . ($kind === 'awaiting'
                ? 'برای تأیید یا رد: افزونهٔ مدیریت CDN پاسارگاد ← «انتقال دامنه».' : '');
        Env::localApi('SendAdminEmail', ['customsubject' => 'Pasargad CDN: درخواست انتقال ' . $r->domain . ' — ' . $fa,
            'custommessage' => '<p>' . self::e($msg) . '</p>', 'type' => 'system']);
    }

    // ------------------------------------------------------------------ admin («انتقال دامنه» tab)

    /** Approval queue + latest customer requests. */
    public static function adminCard(): string
    {
        if (!self::ensure()) {
            return '';
        }
        foreach (self::q()->whereIn('status', self::OPEN)->get()->all() as $r) {
            self::settle($r);
        }
        $wait = self::q()->where('status', 'awaiting')->orderBy('id')->get()->all();
        $recent = self::q()->orderBy('id', 'desc')->limit(15)->get()->all();
        $row = function ($r, bool $actions) {
            [$fa, , $tone] = self::STATUS[(string) $r->status] ?? [(string) $r->status, '', 'muted'];
            return '<tr data-xreq="' . (int) $r->id . '"><td>#' . View::n((int) $r->id) . '</td><td>' . View::ltr((string) $r->domain) . '<div class="pcdna-small"><a href="'
                . View::e(Data::serviceUrl((int) $r->from_client, (int) $r->service_id)) . '">سرویس #' . View::n((int) $r->service_id) . '</a></div></td><td><a href="'
                . View::e(Data::clientUrl((int) $r->from_client)) . '">#' . View::n((int) $r->from_client) . '</a></td><td><a href="' . View::e(Data::clientUrl((int) $r->to_client))
                . '">#' . View::n((int) $r->to_client) . '</a> ' . View::ltr((string) $r->email) . '</td><td>' . View::badge($fa, $tone)
                . ($r->reason ? ' <span class="pcdna-small pcdna-muted">' . View::e((string) $r->reason) . '</span>' : '') . '</td><td class="pcdna-small">'
                . View::e(View::date($r->created_at, true)) . '</td><td class="pcdna-actions">'
                . ($actions ? View::postButton(['page' => 'transfer'], 'xfer_approve', ['id' => (int) $r->id], 'تأیید و اجرا', 'pcdna-btn pcdna-btn-sm pcdna-btn-primary',
                        'انتقال ' . $r->domain . ' به مشتری #' . (int) $r->to_client . ' اجرا شود؟', 'check')
                    . View::postButton(['page' => 'transfer'], 'xfer_reject', ['id' => (int) $r->id], 'رد', 'pcdna-btn pcdna-btn-sm pcdna-btn-danger', 'درخواست رد شود؟', 'x') : '')
                . '</td></tr>';
        };
        $head = '<div class="pcdna-table-wrap"><table class="pcdna-table" %s><thead><tr><th>#</th><th>دامنه</th><th>از</th><th>به</th><th>وضعیت</th><th>زمان</th><th></th></tr></thead><tbody>';
        $q = '<p class="pcdna-muted">«انتقال توسط مشتری»: ' . (self::enabled() ? View::badge('روشن', 'ok') : View::badge('خاموش', 'muted'))
            . ' · «تأیید مدیر لازم است»: ' . (self::approval() ? View::badge('روشن', 'warn') : View::badge('خاموش', 'muted')) . ' (تنظیمات افزونه)</p>';
        $q .= $wait ? sprintf($head, 'data-xfer-queue="1"') . implode('', array_map(function ($r) use ($row) { return $row($r, true); }, $wait)) . '</tbody></table></div>'
            : '<p class="pcdna-okline" data-xfer-queue-empty="1">' . View::icon('check') . '<span>درخواستی در انتظار تأیید نیست.</span></p>';
        if ($recent) {
            $q .= '<h4>درخواست‌های اخیر مشتریان</h4>' . sprintf($head, 'data-xfer-requests="1"') . implode('', array_map(function ($r) use ($row) { return $row($r, false); }, $recent)) . '</tbody></table></div>';
        }
        return View::card('درخواست‌های انتقال مشتریان' . ($wait ? ' (' . View::n(count($wait)) . ' در انتظار تأیید)' : ''), $q, '', '', 'users');
    }

    /** Admin approve / reject. [tone, html] */
    public static function adminAction(string $action, int $id, int $admin): array
    {
        if (!Env::adminHasAccess()) {
            return ['bad', 'نقش مدیریتی شما به این ماژول دسترسی ندارد.'];
        }
        $r = self::ensure() ? self::q()->where('id', $id)->first() : null;
        if (!$r || $r->status !== 'awaiting') {
            return ['bad', 'درخواستی در انتظار تأیید با این شناسه نیست.'];
        }
        if ($action === 'xfer_reject') {
            self::q()->where('id', $id)->where('status', 'awaiting')->update(['status' => 'rejected', 'decided_at' => self::ts(), 'admin_id' => $admin]);
            self::log('#' . $id . ' (' . $r->domain . ') rejected by ' . Env::adminLabel(), (int) $r->from_client);
            self::log('#' . $id . ' (' . $r->domain . ') rejected by ' . Env::adminLabel(), (int) $r->to_client);
            self::mailResult($r, 'rejected');
            return ['ok', 'درخواست #' . View::n($id) . ' رد شد.'];
        }
        [$ok, $msg] = self::execute($r, $admin);
        return $ok ? ['ok', 'انتقال ' . View::ltr((string) $r->domain) . ' به مشتری #' . View::n((int) $r->to_client) . ' انجام شد.']
            : ['bad', View::e('انتقال انجام نشد: ' . $msg)];
    }

    /** Daily cron: open requests are re-validated (expired / cancelled). Free when not due (memoised settings). */
    public static function onCron(): void
    {
        try {
            if (!Env::loadServerModule() || (int) (\pasargadcdn_addon_settings()[self::CRON_KEY] ?? 0) > self::now() || !self::ensure()) {
                return;
            }
            foreach (self::q()->whereIn('status', self::OPEN)->get()->all() as $r) {
                self::settle($r);
            }
            Env::saveSetting(self::CRON_KEY, (string) (self::now() + 86400));
            \pasargadcdn_addon_settings(true);
        } catch (\Throwable $e) {
            Env::log('customer transfer cron error: ' . $e->getMessage());
        }
    }
}
