<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

require_once __DIR__ . '/I18n.php';

if (class_exists(__NAMESPACE__ . '\\Shares', false)) {
    return;
}

/**
 * SPEC §20 — domain sharing: the owner of a CDN service (or the operator, for operator sites) shares ONE domain with
 * another WHMCS client account in a role (viewer | dns | editor). Billing and ownership never move.
 *
 * Table mod_pasargadcdn_shares (one row per invitation / membership):
 *   service_id (owner's service) | operator_domain (operator site), domain, owner_client_id (null for operator sites),
 *   member_client_id (null until accepted), email (invitee, lower-case), role, status pending|active|revoked|declined|expired|left,
 *   token_hash (sha256 of the 32-byte invite token; cleared once used), expires_at, created_by ("client:<id>" | "admin:<id>"),
 *   created_at, accepted_at, revoked_at.
 *
 * Shared by the server module (owner page «اشتراک دامنه» through api.php local op `shares`, Terminate cleanup, service
 * state) and the admin addon (members' «دامنه‌های اشتراکی» route, operator sites, transfer wizard, admin page, cron).
 * Every lookup by id is scoped (owner scope or member id) so an id never reaches another owner's / member's row; invite
 * tokens are only ever compared hashed and never logged.
 */
class Shares
{
    const TABLE = 'mod_pasargadcdn_shares';
    const ROLES = ['viewer', 'dns', 'editor'];
    const STATUSES = ['pending', 'active', 'revoked', 'declined', 'expired', 'left'];
    const LIVE = ['pending', 'active'];
    const TTL = 604800; // 7 days
    const MAX_MEMBERS = 20;
    const MAX_PENDING = 50;
    const EMAIL_INVITE = 'دعوت به مدیریت دامنه';
    const EMAIL_ACCEPTED = 'پذیرش دعوت مدیریت دامنه';
    const TOKEN_RE = '/^[0-9a-f]{64}$/D';

    /** @var callable|null tests: fn(): int */
    public static $clock = null;
    /** @var bool|null memo: table present */
    private static $ready = null;

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
    }

    /** Creates the table when missing (addon activate / upgrade, first use). Never throws. */
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
                    $t->integer('service_id')->nullable();
                    $t->string('operator_domain', 253)->nullable();
                    $t->string('domain', 253);
                    $t->integer('owner_client_id')->nullable();
                    $t->integer('member_client_id')->nullable();
                    $t->string('email', 191);
                    $t->string('role', 16);
                    $t->string('status', 16)->default('pending');
                    $t->char('token_hash', 64)->nullable();
                    $t->dateTime('expires_at')->nullable();
                    $t->string('created_by', 32)->default('');
                    $t->dateTime('created_at')->nullable();
                    $t->dateTime('accepted_at')->nullable();
                    $t->dateTime('revoked_at')->nullable();
                    $t->index(['service_id', 'status'], 'mod_pcdn_shares_service');
                    $t->index(['domain', 'status'], 'mod_pcdn_shares_domain');
                    $t->index(['member_client_id', 'status'], 'mod_pcdn_shares_member');
                    $t->index(['email', 'status'], 'mod_pcdn_shares_email');
                    $t->index('token_hash', 'mod_pcdn_shares_token');
                });
            }
            return self::$ready = true;
        } catch (\Throwable $e) {
            self::$ready = false;
            return false;
        }
    }

    // ------------------------------------------------------------------ settings

    public static function settings(): array
    {
        $s = function_exists('pasargadcdn_addon_settings') ? \pasargadcdn_addon_settings() : [];
        $num = function ($k, $d, $max) use ($s) {
            $v = trim((string) ($s[$k] ?? ''));
            return ctype_digit($v) && (int) $v > 0 ? min($max, (int) $v) : $d;
        };
        return [
            'max_members' => $num('share_max_members', self::MAX_MEMBERS, 500),
            'max_pending' => $num('share_max_pending', self::MAX_PENDING, 1000),
            'notify_owner' => !array_key_exists('share_notify_owner', $s) || in_array(strtolower(trim((string) $s['share_notify_owner'])), ['on', '1', 'yes', 'true'], true),
        ];
    }

    public static function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    public static function validEmail(string $e): bool
    {
        return strlen($e) <= 191 && (bool) filter_var($e, FILTER_VALIDATE_EMAIL);
    }

    private static function q()
    {
        return Capsule::table(self::TABLE);
    }

    /** owner scope: ['service_id' => int] or ['operator_domain' => string]. */
    private static function scoped(array $owner)
    {
        $q = self::q();
        if (!empty($owner['service_id'])) {
            return $q->where('service_id', (int) $owner['service_id']);
        }
        return $q->whereNull('service_id')->where('operator_domain', strtolower((string) ($owner['operator_domain'] ?? '')));
    }

    /** Display name of the owner for a member: company, else first name — never e-mail / contact data. */
    public static function ownerName($row): string
    {
        if (empty($row->owner_client_id)) {
            return I18n::tr('اپراتور پلتفرم');
        }
        $c = Capsule::table('tblclients')->where('id', (int) $row->owner_client_id)->first(['companyname', 'firstname']);
        $n = $c ? trim((string) ($c->companyname ?: $c->firstname)) : '';
        return $n !== '' ? $n : '—';
    }

    // ------------------------------------------------------------------ owner side

    /**
     * New invitation. $owner: ['service_id'?, 'operator_domain'?, 'domain', 'owner_client_id'?]. Returns
     * [true, ['row' => object, 'token' => string, 'client' => ?object]] or [false, Persian error].
     */
    public static function invite(array $owner, string $email, string $role, string $createdBy): array
    {
        if (!self::ensure()) {
            return [false, 'ذخیره در WHMCS ممکن نشد؛ دوباره تلاش کنید.'];
        }
        $email = strtolower(trim($email));
        if (!self::validEmail($email)) {
            return [false, 'ایمیل نامعتبر است.'];
        }
        if (!in_array($role, self::ROLES, true)) {
            return [false, 'نقش نامعتبر است.'];
        }
        $ownerId = (int) ($owner['owner_client_id'] ?? 0);
        $client = Capsule::table('tblclients')->whereRaw('LOWER(email) = ?', [$email])->first(['id', 'email', 'firstname', 'language']);
        if ($ownerId > 0) {
            if ($client && (int) $client->id === $ownerId) {
                return [false, 'نمی‌توانید خودتان را دعوت کنید.'];
            }
            if (self::ownTeam($ownerId, $email)) {
                return [false, 'این ایمیل عضو تیم حساب خود شماست؛ برای دسترسی او از «مدیریت کاربران» حساب WHMCS استفاده کنید.'];
            }
        }
        $live = self::scoped($owner)->whereIn('status', self::LIVE)->get(['id', 'email', 'status', 'member_client_id']);
        foreach ($live as $r) {
            if ($r->email === $email || ($client && (int) $r->member_client_id === (int) $client->id)) {
                return [false, $r->status === 'active' ? 'این شخص همین حالا عضو این دامنه است؛ نقش او را تغییر دهید.' : 'برای این ایمیل یک دعوت در انتظار هست؛ آن را لغو و دوباره دعوت کنید.'];
            }
        }
        $cfg = self::settings();
        if (count($live) >= $cfg['max_members']) {
            return [false, I18n::tr('حداکثر %s عضو (و دعوت در انتظار) برای هر دامنه مجاز است.', $cfg['max_members'])];
        }
        $pending = $ownerId > 0 ? self::q()->where('owner_client_id', $ownerId)->where('status', 'pending')->count()
            : self::q()->whereNull('owner_client_id')->where('status', 'pending')->count();
        if ($pending >= $cfg['max_pending']) {
            return [false, I18n::tr('حداکثر %s دعوت در انتظار مجاز است؛ دعوت‌های قدیمی را لغو کنید.', $cfg['max_pending'])];
        }
        $token = bin2hex(random_bytes(32));
        $id = (int) self::q()->insertGetId(['service_id' => !empty($owner['service_id']) ? (int) $owner['service_id'] : null,
            'operator_domain' => empty($owner['service_id']) ? strtolower((string) ($owner['operator_domain'] ?? '')) : null,
            'domain' => strtolower((string) $owner['domain']), 'owner_client_id' => $ownerId > 0 ? $ownerId : null, 'member_client_id' => null,
            'email' => $email, 'role' => $role, 'status' => 'pending', 'token_hash' => self::hash($token),
            'expires_at' => self::ts(self::now() + self::TTL), 'created_by' => substr($createdBy, 0, 32), 'created_at' => self::ts()]);
        return [true, ['row' => self::q()->where('id', $id)->first(), 'token' => $token, 'client' => $client]];
    }

    /** WHMCS 8: a user with this e-mail belongs to the owner's own account (team access). */
    private static function ownTeam(int $ownerId, string $email): bool
    {
        try {
            if (!Capsule::schema()->hasTable('tblusers') || !Capsule::schema()->hasTable('tblusers_clients')) {
                return false;
            }
            return Capsule::table('tblusers as u')->join('tblusers_clients as uc', 'uc.auth_user_id', '=', 'u.id')
                ->where('uc.client_id', $ownerId)->whereRaw('LOWER(u.email) = ?', [$email])->exists();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Live rows of an owner scope (members + pending invites). */
    public static function forOwner(array $owner): array
    {
        if (!self::ensure()) {
            return [];
        }
        return self::scoped($owner)->whereIn('status', self::LIVE)->orderBy('id')->get()->all();
    }

    /** Owner view of a row (no token, no member contact beyond the e-mail they were invited with). */
    public static function ownerView($r): array
    {
        $name = '';
        if ((int) $r->member_client_id > 0) {
            $c = Capsule::table('tblclients')->where('id', (int) $r->member_client_id)->first(['firstname', 'lastname', 'companyname']);
            $name = $c ? trim(trim((string) $c->firstname . ' ' . (string) $c->lastname) ?: (string) $c->companyname) : '';
        }
        return ['id' => (int) $r->id, 'email' => (string) $r->email, 'name' => $name, 'role' => (string) $r->role, 'status' => (string) $r->status,
            'created_at' => (string) $r->created_at, 'expires_at' => $r->status === 'pending' ? (string) $r->expires_at : null,
            'accepted_at' => $r->accepted_at ? (string) $r->accepted_at : null];
    }

    public static function setRole(int $id, array $owner, string $role): ?object
    {
        if (!in_array($role, self::ROLES, true) || !self::ensure()) {
            return null;
        }
        $n = self::scoped($owner)->where('id', $id)->whereIn('status', self::LIVE)->update(['role' => $role]);
        return $n ? self::q()->where('id', $id)->first() : null;
    }

    public static function revoke(int $id, array $owner): ?object
    {
        if (!self::ensure()) {
            return null;
        }
        $n = self::scoped($owner)->where('id', $id)->whereIn('status', self::LIVE)
            ->update(['status' => 'revoked', 'token_hash' => null, 'revoked_at' => self::ts()]);
        return $n ? self::q()->where('id', $id)->first() : null;
    }

    // ------------------------------------------------------------------ member side

    private static function clientEmail(int $clientId): string
    {
        return strtolower(trim((string) Capsule::table('tblclients')->where('id', $clientId)->value('email')));
    }

    /** Pending, unexpired invitations addressed to this client's primary e-mail. */
    public static function pendingFor(int $clientId): array
    {
        if ($clientId <= 0 || !self::ensure()) {
            return [];
        }
        $email = self::clientEmail($clientId);
        if ($email === '') {
            return [];
        }
        return self::q()->where('email', $email)->where('status', 'pending')->where('expires_at', '>', self::ts())->orderBy('id')->get()->all();
    }

    /** The pending invite of a token (any e-mail) or null — for the accept page. */
    public static function byToken(string $token)
    {
        if (!preg_match(self::TOKEN_RE, $token) || !self::ensure()) {
            return null;
        }
        return self::q()->where('token_hash', self::hash($token))->first();
    }

    /**
     * Accept (or decline) by token for the logged-in client: pending, unexpired, e-mail = the client's primary e-mail,
     * the member limit still holds; the token is single use (cleared). [true, row] | [false, Persian error]
     */
    public static function answer(string $token, int $clientId, bool $accept): array
    {
        $r = self::byToken($token);
        if (!$r || $clientId <= 0) {
            return [false, 'دعوت پیدا نشد یا قبلاً استفاده شده است.'];
        }
        if ($r->status !== 'pending') {
            return [false, 'دعوت پیدا نشد یا قبلاً استفاده شده است.'];
        }
        if (strtotime((string) $r->expires_at) <= self::now()) {
            self::q()->where('id', $r->id)->where('status', 'pending')->update(['status' => 'expired', 'token_hash' => null]);
            return [false, 'این دعوت منقضی شده است؛ از مالک دامنه بخواهید دوباره دعوت کند.'];
        }
        if (self::clientEmail($clientId) !== (string) $r->email) {
            return [false, 'این دعوت برای ایمیل دیگری است؛ با حسابی وارد شوید که ایمیل اصلی آن همان ایمیل دعوت است.'];
        }
        if ((int) $r->owner_client_id === $clientId) {
            return [false, 'نمی‌توانید دعوت دامنهٔ خودتان را بپذیرید.'];
        }
        if (!$accept) {
            self::q()->where('id', $r->id)->where('status', 'pending')->update(['status' => 'declined', 'token_hash' => null, 'revoked_at' => self::ts()]);
            return [true, self::q()->where('id', $r->id)->first()];
        }
        $scope = $r->service_id ? ['service_id' => (int) $r->service_id] : ['operator_domain' => (string) $r->operator_domain];
        if (self::scoped($scope)->where('status', 'active')->where('member_client_id', $clientId)->exists()) {
            self::q()->where('id', $r->id)->update(['status' => 'declined', 'token_hash' => null]);
            return [false, 'شما همین حالا عضو این دامنه هستید.'];
        }
        if (self::scoped($scope)->where('status', 'active')->count() >= self::settings()['max_members']) {
            return [false, 'ظرفیت اعضای این دامنه پر است؛ با مالک دامنه هماهنگ کنید.'];
        }
        $n = self::q()->where('id', $r->id)->where('status', 'pending')->update(['status' => 'active', 'member_client_id' => $clientId,
            'token_hash' => null, 'accepted_at' => self::ts()]);
        return $n ? [true, self::q()->where('id', $r->id)->first()] : [false, 'دعوت پیدا نشد یا قبلاً استفاده شده است.'];
    }

    /** Pending invite by id for this client (the home card / list buttons — no token needed, e-mail must match). */
    public static function pendingById(int $id, int $clientId)
    {
        if ($id <= 0 || $clientId <= 0 || !self::ensure()) {
            return null;
        }
        $r = self::q()->where('id', $id)->where('status', 'pending')->first();
        return $r && (string) $r->email === self::clientEmail($clientId) && strtotime((string) $r->expires_at) > self::now() ? $r : null;
    }

    /** Accept / decline a pending invite by id for the logged-in client (same rules as answer()). */
    public static function answerById(int $id, int $clientId, bool $accept): array
    {
        $r = self::pendingById($id, $clientId);
        if (!$r) {
            return [false, 'دعوت پیدا نشد یا قبلاً استفاده شده است.'];
        }
        // re-arm a one-time token for this row so both paths share answer()
        $tok = bin2hex(random_bytes(32));
        self::q()->where('id', $r->id)->where('status', 'pending')->update(['token_hash' => self::hash($tok)]);
        return self::answer($tok, $clientId, $accept);
    }

    /** Active memberships of a member. */
    public static function activeFor(int $clientId): array
    {
        if ($clientId <= 0 || !self::ensure()) {
            return [];
        }
        return self::q()->where('member_client_id', $clientId)->where('status', 'active')->orderBy('domain')->get()->all();
    }

    /** The active membership $id of $clientId, or null (IDOR guard: another member's id answers null). */
    public static function member(int $id, int $clientId)
    {
        if ($id <= 0 || $clientId <= 0 || !self::ensure()) {
            return null;
        }
        return self::q()->where('id', $id)->where('member_client_id', $clientId)->where('status', 'active')->first();
    }

    public static function leave(int $id, int $clientId): ?object
    {
        $r = self::member($id, $clientId);
        if (!$r) {
            return null;
        }
        self::q()->where('id', $id)->where('status', 'active')->update(['status' => 'left', 'revoked_at' => self::ts()]);
        return self::q()->where('id', $id)->first();
    }

    // ------------------------------------------------------------------ lifecycle

    /** Daily cron: pending invites past their expiry → expired. Returns the count. */
    public static function expire(): int
    {
        if (!self::ensure()) {
            return 0;
        }
        return (int) self::q()->where('status', 'pending')->where('expires_at', '<=', self::ts())->update(['status' => 'expired', 'token_hash' => null]);
    }

    /** Terminate / transfer: every live share of a service ends. Returns the count. */
    public static function removeForService(int $sid): int
    {
        if ($sid <= 0) {
            return 0;
        }
        try {
            return (int) self::q()->where('service_id', $sid)->whereIn('status', self::LIVE)
                ->update(['status' => 'revoked', 'token_hash' => null, 'revoked_at' => self::ts()]);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** Site deleted / transferred: every live share of a domain (service or operator scope) ends. */
    public static function removeForDomain(string $domain): int
    {
        try {
            return (int) self::q()->where('domain', strtolower($domain))->whereIn('status', self::LIVE)
                ->update(['status' => 'revoked', 'token_hash' => null, 'revoked_at' => self::ts()]);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** Transfer with «keep shares»: the live rows of $domain follow the site to its new owner scope. */
    public static function repoint(string $domain, ?int $serviceId, ?int $ownerClientId): int
    {
        try {
            $q = self::q()->where('domain', strtolower($domain))->whereIn('status', self::LIVE);
            $n = (int) (clone $q)->update(['service_id' => $serviceId ?: null, 'operator_domain' => $serviceId ? null : strtolower($domain),
                'owner_client_id' => $ownerClientId ?: null]);
            // a member who is the new owner no longer needs a share
            if ($ownerClientId) {
                $email = self::clientEmail($ownerClientId);
                self::q()->where('domain', strtolower($domain))->whereIn('status', self::LIVE)->where(function ($w) use ($ownerClientId, $email) {
                    $w->where('member_client_id', $ownerClientId)->orWhere('email', $email);
                })->update(['status' => 'revoked', 'token_hash' => null, 'revoked_at' => self::ts()]);
            }
            return $n;
        } catch (\Throwable $e) {
            return 0;
        }
    }

    // ------------------------------------------------------------------ e-mails

    /** name => [fa subject, fa body, en subject, en body] — general templates sent with the recipient client id. */
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
            self::EMAIL_INVITE => ['دعوت به مدیریت دامنه {$share_domain}',
                $fa('<p>{$share_owner} شما را برای مدیریت CDN دامنهٔ <strong dir="ltr">{$share_domain}</strong> با نقش «{$share_role}» دعوت کرده است.</p>'
                    . '<p><a href="{$share_link}">پذیرش یا رد دعوت</a> — این پیوند تا {$share_expires} معتبر است و فقط با حسابی که ایمیل اصلی آن همین ایمیل است پذیرفته می‌شود.</p>'
                    . '<p>با پذیرش، صورت‌حساب و مالکیت دامنه تغییری نمی‌کند.</p>'),
                'Invitation to manage {$share_domain}',
                $en('<p>{$share_owner} invited you to manage the CDN of <strong>{$share_domain}</strong> with the role "{$share_role}".</p>'
                    . '<p><a href="{$share_link}">Accept or decline the invitation</a> — the link is valid until {$share_expires} and can only be accepted by the account whose primary e-mail is this address.</p>'
                    . '<p>Accepting does not change the domain\'s billing or ownership.</p>')],
            self::EMAIL_ACCEPTED => ['دعوت مدیریت {$share_domain} پذیرفته شد',
                $fa('<p>{$share_member} دعوت شما برای مدیریت دامنهٔ <strong dir="ltr">{$share_domain}</strong> با نقش «{$share_role}» را پذیرفت. اعضا را از صفحهٔ «اشتراک دامنه» در پنل CDN مدیریت کنید.</p>'),
                'Invitation to manage {$share_domain} accepted',
                $en('<p>{$share_member} accepted your invitation to manage <strong>{$share_domain}</strong> with the role "{$share_role}". Manage members from the "Domain sharing" page of the CDN panel.</p>')],
        ];
    }

    /** Creates the templates (fa + english, type general) when missing; never overwrites an edited one. */
    public static function ensureTemplates(): void
    {
        $now = date('Y-m-d H:i:s');
        foreach (self::templates() as $name => [$faSub, $faBody, $enSub, $enBody]) {
            foreach (['' => [$faSub, $faBody], 'english' => [$enSub, $enBody]] as $lang => [$sub, $body]) {
                if (Capsule::table('tblemailtemplates')->where('type', 'general')->where('name', $name)->where('language', $lang)->exists()) {
                    continue;
                }
                $row = ['type' => 'general', 'name' => $name, 'subject' => $sub, 'message' => $body, 'attachments' => '', 'fromname' => '',
                    'fromemail' => '', 'disabled' => 0, 'custom' => 1, 'language' => $lang, 'copyto' => '', 'blind_copy_to' => '', 'plaintext' => 0,
                    'created_at' => $now, 'updated_at' => $now];
                $cols = Capsule::schema()->getColumnListing('tblemailtemplates');
                Capsule::table('tblemailtemplates')->insert(array_intersect_key($row, array_flip($cols)));
            }
        }
    }

    public static function roleLabel(string $role, string $lang = 'fa'): string
    {
        $fa = ['viewer' => 'مشاهده‌گر', 'dns' => 'مدیر DNS', 'editor' => 'ویرایشگر'];
        $en = ['viewer' => 'Viewer', 'dns' => 'DNS manager', 'editor' => 'Editor'];
        return ($lang === 'en' ? $en : $fa)[$role] ?? $role;
    }

    /** WHMCS System URL (for links in e-mails), with a trailing slash. */
    public static function systemUrl(): string
    {
        try {
            $u = (string) Capsule::table('tblconfiguration')->where('setting', 'SystemURL')->value('value');
        } catch (\Throwable $e) {
            $u = '';
        }
        return $u === '' ? '' : rtrim($u, '/') . '/';
    }

    public static function inviteLink(string $token): string
    {
        return self::systemUrl() . 'index.php?m=pasargadcdn_admin&page=shared&invite=' . $token;
    }

    /** SendEmail (general template) to a client; best effort. */
    public static function mail(string $template, int $clientId, array $vars): bool
    {
        if ($clientId <= 0 || !function_exists('localAPI')) {
            return false;
        }
        try {
            self::ensureTemplates();
            $r = localAPI('SendEmail', ['messagename' => $template, 'id' => $clientId, 'customvars' => base64_encode(serialize($vars))]);
            return is_array($r) && ($r['result'] ?? '') === 'success';
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** The invite e-mail to an existing client (the token only travels in the e-mail / the owner's one-time answer). */
    public static function mailInvite($row, string $token, $client, string $ownerName): bool
    {
        if (!$client) {
            return false;
        }
        $lang = strtolower((string) ($client->language ?? '')) === 'english' ? 'en' : 'fa';
        return self::mail(self::EMAIL_INVITE, (int) $client->id, ['share_domain' => (string) $row->domain, 'share_role' => self::roleLabel((string) $row->role, $lang),
            'share_owner' => $ownerName, 'share_link' => self::inviteLink($token), 'share_expires' => substr((string) $row->expires_at, 0, 10)]);
    }

    /** Owner notice when an invite was accepted (setting «share_notify_owner», default on; operator sites: none). */
    public static function mailAccepted($row): bool
    {
        if (empty($row->owner_client_id) || !self::settings()['notify_owner']) {
            return false;
        }
        $m = Capsule::table('tblclients')->where('id', (int) $row->member_client_id)->first(['firstname', 'lastname', 'companyname']);
        $name = $m ? trim(trim((string) $m->firstname . ' ' . (string) $m->lastname) ?: (string) $m->companyname) : '';
        return self::mail(self::EMAIL_ACCEPTED, (int) $row->owner_client_id, ['share_domain' => (string) $row->domain,
            'share_role' => self::roleLabel((string) $row->role), 'share_member' => $name . ' (' . (string) $row->email . ')']);
    }

    public static function log(string $msg, int $uid = 0): void
    {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: share ' . $msg, $uid);
        }
    }
}
