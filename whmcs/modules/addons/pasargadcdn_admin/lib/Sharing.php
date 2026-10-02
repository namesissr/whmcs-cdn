<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ClientApi;
use PasargadCdn\I18n;
use PasargadCdn\Shares;
use PasargadCdn\TeamAccess;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Sharing', false)) {
    return;
}

/**
 * SPEC §20 — the addon side of domain sharing:
 *
 *  - client area `index.php?m=pasargadcdn_admin&page=shared` («دامنه‌های اشتراکی»): the member's invitations (accept /
 *    decline, bound to the client's primary e-mail), shared domains (role, owner display name only), «مدیریت» → the module's
 *    client app in a `shared` context, «خروج»; `page=shared&invite=<token>` is the e-mailed accept link;
 *  - `page=sharedapi&share=<id>&path=…` — the app's JSON proxy for a member: client session + module CSRF; the share row is
 *    re-read on EVERY request (member id, status active, owner service still the owner's and live), so a revoked / left /
 *    re-roled member is refused (403) or limited on the next call; ClientApi::handle() then applies the whitelist and the
 *    role's allow-list (deny by default) and audits every write with `share:<member>:<role>`;
 *  - admin: page «اشتراک‌ها» (all shares, filters, revoke, audit trail), operator-site sharing (Operator page), cron expiry,
 *    home-page card of pending invitations.
 */
final class Sharing
{
    const ROUTE = 'index.php?m=pasargadcdn_admin&page=shared';
    const API = 'index.php?m=pasargadcdn_admin&page=sharedapi';
    const CRON_KV = 'shares_expire';

    /** @var callable|null tests: receives [status, content type, body, filename] instead of exit */
    public static $sink = null;
    /** @var string|null tests: request body */
    public static $body = null;
    /** @var callable|null tests: ClientApi factory */
    public static $apiFactory = null;

    private static function lang(): string
    {
        return function_exists('pasargadcdn_lang') ? \pasargadcdn_lang([]) : 'fa';
    }

    private static function tx(string $fa, string $en): string
    {
        return self::lang() === 'en' ? $en : $fa;
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

    // ------------------------------------------------------------------ the member's context (re-checked per request)

    /**
     * The shared context of share $id for member $clientId, or null: active row of this member; the owner's service still
     * belongs to the share's owner, is a CDN service on the share's domain and is Active (read-write) or Suspended (read-only);
     * operator shares use the addon's server.
     */
    public static function context(int $id, int $clientId): ?array
    {
        $r = Shares::member($id, $clientId);
        if (!$r) {
            return null;
        }
        $readonly = false;
        if ($r->service_id) {
            $svc = Capsule::table('tblhosting')->where('id', (int) $r->service_id)->first(['id', 'userid', 'packageid', 'server', 'domain', 'domainstatus']);
            if (!$svc || (int) $svc->userid !== (int) $r->owner_client_id || Env::domain((string) $svc->domain) !== (string) $r->domain
                || !Env::isCdnProduct((int) $svc->packageid) || !in_array((string) $svc->domainstatus, ['Active', 'Suspended'], true)) {
                return null;
            }
            $readonly = (string) $svc->domainstatus !== 'Active';
            $server = Capsule::table('tblservers')->where('id', (int) $svc->server)->first();
        } else {
            $s = Env::server();
            $server = $s ? Capsule::table('tblservers')->where('id', (int) $s->id)->first() : null;
        }
        if (!$server || ($server->type ?? '') !== 'pasargadcdn' || !Env::validHostname((string) $r->domain)) {
            return null;
        }
        return ['kind' => 'shared', 'share_id' => (int) $r->id, 'role' => (string) $r->role, 'domain' => (string) $r->domain, 'server' => $server,
            'service_id' => (int) $r->service_id, 'owner_client_id' => (int) $r->owner_client_id, 'readonly' => $readonly, 'row' => $r];
    }

    // ------------------------------------------------------------------ JSON API (page=sharedapi)

    public static function emit(int $code, string $type, string $body, string $file = ''): void
    {
        if (self::$sink) {
            (self::$sink)([$code, $type, $body, $file]);
            return;
        }
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        if (!headers_sent()) {
            http_response_code($code);
            header('Content-Type: ' . $type);
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
            if ($file !== '') {
                header('Content-Disposition: attachment; filename="' . preg_replace('/[^A-Za-z0-9._-]/', '', $file) . '"');
            }
        }
        echo $body;
        exit;
    }

    private static function readBody(int $max): string
    {
        return self::$body !== null ? self::$body : (string) file_get_contents('php://input', false, null, 0, $max);
    }

    /** [status, data|Download] of one app call. */
    public static function api(array $get, string $method, int $clientId): array
    {
        I18n::$current = ($_SERVER['HTTP_X_PCDN_LANG'] ?? '') === 'en' ? 'en' : 'fa';
        if ($clientId <= 0) {
            return [401, ['detail' => I18n::tr('لطفاً دوباره وارد حساب کاربری شوید.')]];
        }
        $csrf = (string) ($_SERVER['HTTP_X_PCDN_CSRF'] ?? '');
        if (!self::csrfOk($csrf)) {
            return [403, ['detail' => I18n::tr('درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.')]];
        }
        $id = ctype_digit((string) ($get['share'] ?? '')) ? (int) $get['share'] : 0;
        $ctx = self::context($id, $clientId);
        if ($ctx === null) {
            // revoked / left / expired share, another member's id, or the owner's service is gone: same answer
            return [403, ['detail' => self::tx('دسترسی شما به این دامنه برداشته شده یا وجود ندارد؛ فهرست دامنه‌های اشتراکی را دوباره باز کنید.',
                'Your access to this domain was removed or does not exist; reopen the list of shared domains.')]];
        }
        if (($get['action'] ?? '') === 'client-error') {
            return ClientApi::clientError(['method' => $method, 'id' => '', 'client_id' => $clientId, 'csrf' => $csrf,
                'session_csrf' => (string) ($_SESSION['pasargadcdn_csrf'] ?? ''), 'lang' => (string) ($_SERVER['HTTP_X_PCDN_LANG'] ?? ''),
                'body' => $method === 'POST' ? self::readBody(ClientApi::CLIENT_ERROR_MAX_BODY + 1) : ''], $_SESSION);
        }
        $path = is_string($get['path'] ?? null) ? $get['path'] : '';
        $body = $method === 'POST' || $method === 'PUT' ? self::readBody(ClientApi::maxBody($method, $path) + 1) : '';
        $query = $get;
        unset($query['m'], $query['page'], $query['share'], $query['id'], $query['path'], $query['action'], $query['rsid'], $query['rop'], $query['lop']);
        unset($ctx['row']);
        return ClientApi::handle(['method' => $method, 'id' => '', 'path' => $path, 'query' => $query, 'body' => $body, 'csrf' => $csrf,
            'session_csrf' => (string) ($_SESSION['pasargadcdn_csrf'] ?? ''), 'client_id' => $clientId,
            'readonly' => $method !== 'GET' && class_exists(TeamAccess::class) && TeamAccess::readonly(),
            'lang' => (string) ($_SERVER['HTTP_X_PCDN_LANG'] ?? ''), 'context' => $ctx], self::$apiFactory);
    }

    // ------------------------------------------------------------------ client area (page=shared / sharedapi)

    /** pasargadcdn_admin_clientarea() for page=shared / sharedapi: a WHMCS client-area array, or null after emitting JSON. */
    public static function clientArea(array $get, array $post, string $method, int $clientId): ?array
    {
        if (!Env::loadServerModule()) {
            return null;
        }
        if (($get['page'] ?? '') === 'sharedapi') {
            [$code, $data] = self::api($get, $method, $clientId);
            if ($data instanceof \PasargadCdn\Download) {
                self::emit($code, $data->type, $data->body, $data->filename);
            } else {
                self::emit($code, 'application/json; charset=utf-8', (string) json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            }
            return null;
        }
        $title = self::tx('دامنه‌های اشتراکی', 'Shared domains');
        $html = $clientId > 0 ? self::page($get, $post, $method, $clientId) : '';
        return ['pagetitle' => $title, 'breadcrumb' => [self::ROUTE => $title], 'templatefile' => 'pricing', 'requirelogin' => true,
            'forcessl' => false, 'vars' => ['pcdn_html' => $html, 'pcdn_lang' => self::lang()]];
    }

    private static function e($v): string
    {
        return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
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

    /** POST answer: [tone, text] */
    private static function act(array $post, int $clientId): array
    {
        if (!self::csrfOk($post['pcdn_csrf'] ?? null)) {
            return ['danger', self::tx('درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.', 'Invalid request; reload the page.')];
        }
        $a = is_string($post['a'] ?? null) ? $post['a'] : '';
        if (in_array($a, ['accept', 'decline'], true)) {
            $tok = is_string($post['invite'] ?? null) ? $post['invite'] : '';
            $id = (int) ($post['id'] ?? 0);
            [$ok, $res] = $tok !== '' ? Shares::answer($tok, $clientId, $a === 'accept') : Shares::answerById($id, $clientId, $a === 'accept');
            if (!$ok) {
                return ['danger', I18n::tr($res)];
            }
            Shares::log('#' . (int) $res->id . ' ' . ($a === 'accept' ? 'accepted' : 'declined') . ' by client #' . $clientId . ' (' . $res->domain . ', ' . $res->role . ')',
                (int) $res->owner_client_id);
            if ($a === 'accept') {
                Shares::mailAccepted($res);
                self::$memo = [];
                return ['success', self::tx('دعوت پذیرفته شد؛ اکنون می‌توانید ' . $res->domain . ' را مدیریت کنید.', 'Invitation accepted; you can now manage ' . $res->domain . '.'),
                    self::ROUTE . '&share=' . (int) $res->id];
            }
            return ['info', self::tx('دعوت رد شد.', 'Invitation declined.')];
        }
        if ($a === 'leave') {
            $r = Shares::leave((int) ($post['id'] ?? 0), $clientId);
            if (!$r) {
                return ['danger', self::tx('اشتراک پیدا نشد.', 'Share not found.')];
            }
            self::$memo = [];
            Shares::log('#' . (int) $r->id . ' left by client #' . $clientId . ' (' . $r->domain . ')', (int) $r->owner_client_id);
            return ['info', self::tx('از مدیریت ' . $r->domain . ' خارج شدید.', 'You left ' . $r->domain . '.')];
        }
        return ['danger', self::tx('عملیات نامعتبر است.', 'Invalid action.')];
    }

    private static function roleBadge(string $role): string
    {
        return '<span class="label label-info" data-role="' . self::e($role) . '">' . self::e(Shares::roleLabel($role, self::lang())) . '</span>';
    }

    private static function page(array $get, array $post, string $method, int $clientId): string
    {
        $en = self::lang() === 'en';
        $dir = $en ? 'ltr' : 'rtl';
        $flash = '';
        if ($method === 'POST') {
            $res = self::act($post, $clientId);
            [$tone, $msg] = $res;
            $go = isset($res[2]) ? ' <a class="btn btn-primary btn-sm" data-manage-now="1" href="' . self::e($res[2]) . '">' . self::e(self::tx('مدیریت دامنه', 'Manage the domain')) . '</a>' : '';
            $flash = '<div class="alert alert-' . $tone . '" role="status" data-share-flash="' . self::e($tone) . '">' . self::e($msg) . $go . '</div>';
        }
        $sid = ctype_digit((string) ($get['share'] ?? '')) ? (int) $get['share'] : 0;
        if ($sid > 0 && $method !== 'POST') {
            return '<div class="pcdn-shared-page" dir="' . $dir . '">' . self::app($sid, $clientId) . '</div>';
        }
        $h = '<div class="pcdn-shared-page" dir="' . $dir . '" lang="' . ($en ? 'en' : 'fa') . '" data-shared-page="1">' . $flash;
        $tok = is_string($get['invite'] ?? null) ? $get['invite'] : '';
        if ($tok !== '' && $method !== 'POST') {
            $h .= self::inviteBox($tok, $clientId);
        }
        $pending = Shares::pendingFor($clientId);
        if ($pending) {
            $h .= '<h3>' . self::e(self::tx('دعوت‌های در انتظار', 'Pending invitations')) . '</h3><div class="table-responsive"><table class="table" data-invites="1"><tbody>';
            foreach ($pending as $r) {
                $h .= '<tr data-invite-id="' . (int) $r->id . '"><td dir="ltr"><strong>' . self::e($r->domain) . '</strong></td><td>' . self::roleBadge((string) $r->role) . '</td>'
                    . '<td>' . self::e(self::tx('از طرف ', 'From ') . Shares::ownerName($r)) . '</td><td>'
                    . self::form('accept', ['id' => (int) $r->id], self::tx('پذیرش', 'Accept'), 'btn btn-primary btn-sm')
                    . self::form('decline', ['id' => (int) $r->id], self::tx('رد', 'Decline'), 'btn btn-default btn-sm') . '</td></tr>';
            }
            $h .= '</tbody></table></div>';
        }
        $rows = Shares::activeFor($clientId);
        $h .= '<h3>' . self::e(self::tx('دامنه‌هایی که با شما به اشتراک گذاشته شده‌اند', 'Domains shared with you')) . '</h3>';
        if (!$rows) {
            $h .= '<div class="alert alert-info" data-shares-empty="1">' . self::e(self::tx('هنوز دامنه‌ای با شما به اشتراک گذاشته نشده است. وقتی مالک یک دامنه شما را دعوت کند، دعوت اینجا و در صفحهٔ اصلی ناحیهٔ کاربری نمایش داده می‌شود.',
                'No domain has been shared with you yet. When an owner invites you, the invitation shows here and on your client-area home page.')) . '</div>';
        } else {
            $h .= '<div class="table-responsive"><table class="table" data-shares="1"><thead><tr><th>' . self::e(self::tx('دامنه', 'Domain')) . '</th><th>'
                . self::e(self::tx('نقش', 'Role')) . '</th><th>' . self::e(self::tx('مالک', 'Owner')) . '</th><th></th></tr></thead><tbody>';
            foreach ($rows as $r) {
                $h .= '<tr data-share-id="' . (int) $r->id . '"><td dir="ltr"><strong>' . self::e($r->domain) . '</strong></td><td>' . self::roleBadge((string) $r->role) . '</td>'
                    . '<td>' . self::e(Shares::ownerName($r)) . '</td><td><a class="btn btn-primary btn-sm" data-manage="1" href="' . self::e(self::ROUTE . '&share=' . (int) $r->id) . '">'
                    . self::e(self::tx('مدیریت', 'Manage')) . '</a> '
                    . self::form('leave', ['id' => (int) $r->id], self::tx('خروج', 'Leave'), 'btn btn-default btn-sm',
                        self::tx('دسترسی شما به ' . $r->domain . ' حذف شود؟', 'Remove your access to ' . $r->domain . '?')) . '</td></tr>';
            }
            $h .= '</tbody></table></div>';
        }
        $h .= '<p class="text-muted small">' . self::e(self::tx('صورت‌حساب و مالکیت این دامنه‌ها نزد مالک آن‌هاست؛ هر تغییر شما با نام شما در گزارش تغییرات مالک ثبت می‌شود.',
            'Billing and ownership of these domains stay with their owners; every change you make is recorded under your name in the owner\'s change log.')) . '</p>';
        return $h . '</div>';
    }

    /** The e-mailed accept link: the invite (domain, role, owner name) with accept / decline. */
    private static function inviteBox(string $tok, int $clientId): string
    {
        $r = Shares::byToken($tok);
        if (!$r || $r->status !== 'pending') {
            return '<div class="alert alert-warning" data-invite-state="invalid">' . self::e(I18n::tr('دعوت پیدا نشد یا قبلاً استفاده شده است.')) . '</div>';
        }
        if (strtotime((string) $r->expires_at) <= Shares::now()) {
            return '<div class="alert alert-warning" data-invite-state="expired">' . self::e(I18n::tr('این دعوت منقضی شده است؛ از مالک دامنه بخواهید دوباره دعوت کند.')) . '</div>';
        }
        $mine = strtolower((string) Capsule::table('tblclients')->where('id', $clientId)->value('email')) === (string) $r->email;
        $h = '<div class="panel panel-default" data-invite-state="' . ($mine ? 'ok' : 'wrong-email') . '"><div class="panel-body"><p>'
            . self::e(self::tx(Shares::ownerName($r) . ' شما را برای مدیریت ', Shares::ownerName($r) . ' invited you to manage ')) . '<strong dir="ltr">' . self::e($r->domain) . '</strong> '
            . self::e(self::tx('دعوت کرده است — نقش: ', '— role: ')) . self::roleBadge((string) $r->role) . '</p>'
            . '<p class="text-muted" data-role-help="1">' . self::e(Shares::roleHelp((string) $r->role, self::lang())) . '</p>'
            . '<p class="text-muted small">' . self::e(self::tx('بعد از پذیرش، این دامنه در منوی «سرویس‌ها ← دامنه‌های اشتراکی»، صفحهٔ اصلی و کادر کناری «سرویس‌های من» دیده می‌شود؛ روی «مدیریت» کنار آن کلیک کنید.',
                'After accepting, the domain shows under "Services → Shared domains", on the home page and in the "My Services" sidebar; click "Manage" next to it.')) . '</p>';
        if (!$mine) {
            return $h . '<div class="alert alert-danger">' . self::e(I18n::tr('این دعوت برای ایمیل دیگری است؛ با حسابی وارد شوید که ایمیل اصلی آن همان ایمیل دعوت است.')) . '</div></div></div>';
        }
        return $h . self::form('accept', ['invite' => $tok], self::tx('پذیرش دعوت', 'Accept invitation'), 'btn btn-primary')
            . self::form('decline', ['invite' => $tok], self::tx('رد دعوت', 'Decline'), 'btn btn-default') . '</div></div>';
    }

    /** The module's client app bound to share $id (shared context). No owner billing data in the boot. */
    private static function app(int $id, int $clientId): string
    {
        $back = '<p><a href="' . self::e(self::ROUTE) . '">' . self::e(self::tx('→ دامنه‌های اشتراکی', '← Shared domains')) . '</a></p>';
        $ctx = self::context($id, $clientId);
        if (!$ctx) {
            return $back . '<div class="alert alert-danger" data-share-denied="1">' . self::e(self::tx('دسترسی شما به این دامنه برداشته شده یا وجود ندارد.', 'Your access to this domain was removed or does not exist.')) . '</div>';
        }
        $lang = self::lang();
        $prev = I18n::$current;
        I18n::$current = $lang;
        $boot = ['serviceId' => $id, 'lang' => $lang, 'domain' => $ctx['domain'], 'active' => !$ctx['readonly'], 'site' => null, 'error' => null,
            'readonly' => class_exists(TeamAccess::class) && TeamAccess::readonly(), 'growth' => ['persist' => false],
            'share' => ['id' => $id, 'role' => $ctx['role'], 'owner' => Shares::ownerName($ctx['row']), 'back' => self::ROUTE]];
        try {
            $boot['site'] = ApiClient::fromServerRow($ctx['server'], 20)->get(ApiClient::site($ctx['domain']));
        } catch (\Throwable $e) {
            $boot['error'] = $e->getMessage();
        }
        I18n::$current = $prev;
        $base = function_exists('pasargadcdn_module_url') ? \pasargadcdn_module_url() : 'modules/servers/pasargadcdn';
        $assets = \pasargadcdn_assets($base, $lang);
        $h = '<link rel="stylesheet" href="' . self::e($assets['css']) . '">'
            . '<div id="pcdn-app" class="pcdn" dir="' . ($lang === 'en' ? 'ltr' : 'rtl') . '" lang="' . $lang . '" data-api="' . self::e(self::API . '&share=' . $id)
            . '" data-csrf="' . self::e(self::csrf()) . '" data-shared="1"><div class="pcdn-boot-loading" role="status">'
            . self::e(self::tx('در حال بارگذاری پنل CDN…', 'Loading the CDN panel…')) . '</div></div>'
            . '<script type="application/json" id="pcdn-boot">' . \pasargadcdn_boot_json($boot) . '</script>';
        foreach ($assets['scripts'] as $s) {
            $h .= '<script src="' . self::e($s) . '" defer></script>';
        }
        return $back . $h;
    }

    // ------------------------------------------------------------------ home card / cron

    /** @var array<int, array> per-request memo of activeFor/pendingFor (the hooks run on every client page) */
    private static $memo = [];

    /** Drop the per-request memo (after an accept/leave, and in tests). */
    public static function forget(): void
    {
        self::$memo = [];
    }

    /** ['active' => rows, 'pending' => rows] of $clientId, memoised for this request. */
    public static function mine(int $clientId): array
    {
        if ($clientId <= 0) {
            return ['active' => [], 'pending' => []];
        }
        if (!isset(self::$memo[$clientId])) {
            self::$memo[$clientId] = ['active' => Shares::activeFor($clientId), 'pending' => Shares::pendingFor($clientId)];
        }
        return self::$memo[$clientId];
    }

    /** Menu label «دامنه‌های اشتراکی» (+ the count of pending invitations). */
    public static function menuLabel(int $clientId): string
    {
        $m = self::mine($clientId);
        $n = count($m['pending']);
        return self::tx('دامنه‌های اشتراکی', 'Shared domains') . ($n > 0 ? ' (' . $n . ')' : '');
    }

    /** [label, uri] links: one «مدیریت» link per active shared domain, then the list page. */
    public static function links(int $clientId): array
    {
        $out = [];
        foreach (self::mine($clientId)['active'] as $r) {
            $out[] = [(string) $r->domain, self::ROUTE . '&share=' . (int) $r->id, (int) $r->id];
        }
        return $out;
    }

    /** Home panel body listing the active shared domains with «مدیریت» buttons ('' when none). */
    public static function homeSharedCard(int $clientId): string
    {
        $rows = self::mine($clientId)['active'];
        if (!$rows) {
            return '';
        }
        $h = '<div class="pcdn-share-card" data-shared-card="1"><ul class="list-unstyled">';
        foreach ($rows as $r) {
            $h .= '<li style="margin:4px 0"><strong dir="ltr">' . self::e($r->domain) . '</strong> ' . self::roleBadge((string) $r->role)
                . ' <a class="btn btn-primary btn-xs" data-manage="1" href="' . self::e(self::ROUTE . '&share=' . (int) $r->id) . '">'
                . self::e(self::tx('مدیریت', 'Manage')) . '</a></li>';
        }
        return $h . '</ul></div>';
    }

    /**
     * «دامنه‌های اشتراکی» box placed at the top of the client's «My Services» page (a shared domain is not a WHMCS
     * service of the member, so the services table itself cannot list it). '' when the client has none.
     */
    public static function servicesBox(int $clientId): string
    {
        $m = self::mine($clientId);
        if (!$m['active'] && !$m['pending']) {
            return '';
        }
        $en = self::lang() === 'en';
        $h = '<div class="card panel panel-default pcdn-shared-services" id="pcdn-shared-services" dir="' . ($en ? 'ltr' : 'rtl') . '" style="margin-bottom:20px">'
            . '<div class="card-header panel-heading"><h3 class="card-title panel-title" style="margin:0;font-size:16px">'
            . self::e(self::tx('دامنه‌های اشتراکی', 'Shared domains')) . '</h3></div><div class="card-body panel-body">'
            . '<p class="text-muted small" style="margin-top:0">' . self::e(self::tx('این دامنه‌ها را دیگران با شما به اشتراک گذاشته‌اند؛ صورت‌حساب و مالکیت آن‌ها نزد مالک است.',
                'Other accounts shared these domains with you; billing and ownership stay with the owner.')) . '</p>';
        if ($m['active']) {
            $h .= '<div class="table-responsive"><table class="table table-list" style="margin-bottom:0"><thead><tr><th>' . self::e(self::tx('دامنه', 'Domain')) . '</th><th>'
                . self::e(self::tx('نقش شما', 'Your role')) . '</th><th>' . self::e(self::tx('مالک', 'Owner')) . '</th><th></th></tr></thead><tbody>';
            foreach ($m['active'] as $r) {
                $h .= '<tr data-shared-row="' . (int) $r->id . '"><td dir="ltr"><strong>' . self::e($r->domain) . '</strong></td><td>' . self::roleBadge((string) $r->role) . '</td><td>'
                    . self::e(Shares::ownerName($r)) . '</td><td><a class="btn btn-primary btn-sm" data-manage="1" href="' . self::e(self::ROUTE . '&share=' . (int) $r->id) . '">'
                    . self::e(self::tx('مدیریت', 'Manage')) . '</a></td></tr>';
            }
            $h .= '</tbody></table></div>';
        }
        if ($m['pending']) {
            $h .= '<p style="margin:10px 0 0"><a class="btn btn-default btn-sm" href="' . self::e(self::ROUTE) . '">'
                . self::e(self::tx(count($m['pending']) . ' دعوت در انتظار پذیرش — مشاهده', count($m['pending']) . ' pending invitation(s) — view')) . '</a></p>';
        }
        return $h . '</div></div>';
    }

    /** «دعوت به مدیریت دامنه» card body for the client-area home ('' when nothing is pending). */
    public static function homeCard(int $clientId): string
    {
        $rows = self::mine($clientId)['pending'];
        if (!$rows) {
            return '';
        }
        $h = '<div class="pcdn-share-card" data-share-card="1"><ul class="list-unstyled">';
        foreach ($rows as $r) {
            $h .= '<li><strong dir="ltr">' . self::e($r->domain) . '</strong> — ' . self::roleBadge((string) $r->role) . ' <small class="text-muted">'
                . self::e(Shares::ownerName($r)) . '</small></li>';
        }
        return $h . '</ul></div>';
    }

    /** AfterCronJob: once a day, pending invitations past their 7 days → expired. */
    public static function onCron(): void
    {
        try {
            if (!Env::loadServerModule()) {
                return;
            }
            // the due time lives in the memoised addon settings: a cron run that is not due costs no query
            if ((int) (\pasargadcdn_addon_settings()[self::CRON_KV . '_next'] ?? 0) > Shares::now()) {
                return;
            }
            $n = Shares::expire();
            Env::saveSetting(self::CRON_KV . '_next', (string) (Shares::now() + 86400));
            \pasargadcdn_addon_settings(true);
            if ($n) {
                Env::log('shares: ' . $n . ' pending invitation(s) expired');
            }
        } catch (\Throwable $e) {
            Env::log('shares cron error: ' . $e->getMessage());
        }
    }

    // ------------------------------------------------------------------ admin

    const STATUS_FA = ['pending' => ['در انتظار', 'warn'], 'active' => ['فعال', 'ok'], 'revoked' => ['لغوشده', 'muted'], 'declined' => ['ردشده', 'muted'],
        'expired' => ['منقضی', 'muted'], 'left' => ['خارج‌شده', 'muted']];

    /** Admin action share_revoke (any share; CSRF checked by Admin). */
    public static function adminRevoke(int $id, int $admin): array
    {
        if (!Shares::ensure()) {
            return ['bad', 'جدول اشتراک‌ها در دسترس نیست.'];
        }
        $r = Capsule::table(Shares::TABLE)->where('id', $id)->first();
        if (!$r || !in_array((string) $r->status, Shares::LIVE, true)) {
            return ['bad', 'اشتراک فعال یا دعوت در انتظاری با این شناسه نیست.'];
        }
        Capsule::table(Shares::TABLE)->where('id', $id)->update(['status' => 'revoked', 'token_hash' => null, 'revoked_at' => date('Y-m-d H:i:s')]);
        Shares::log('#' . $id . ' (' . $r->email . ', ' . $r->domain . ') revoked by ' . Env::adminLabel(), (int) $r->owner_client_id);
        return ['ok', 'دسترسی ' . View::ltr((string) $r->email) . ' به ' . View::ltr((string) $r->domain) . ' لغو شد.'];
    }

    /** Admin invite for an operator site (Operator page). [tone, html] */
    public static function adminInvite(string $domain, string $email, string $role): array
    {
        [$ok, $res] = Shares::invite(['operator_domain' => $domain, 'domain' => $domain], $email, $role, 'admin:' . Env::adminId());
        if (!$ok) {
            return ['bad', View::e($res)];
        }
        $row = $res['row'];
        $mailed = Shares::mailInvite($row, $res['token'], $res['client'], Shares::ownerName($row));
        Shares::log('#' . (int) $row->id . ' invite operator site ' . $domain . ' (' . $role . ') to ' . $row->email . ' by ' . Env::adminLabel()
            . ($res['client'] ? ' — existing client #' . (int) $res['client']->id : ' — no account yet'));
        if (!$res['client']) {
            return ['warn', 'دعوت ساخته شد. این ایمیل هنوز حساب ندارد؛ این پیوند را (فقط همین یک بار نمایش داده می‌شود) برای او بفرستید: '
                . View::copyable(Shares::inviteLink($res['token']), 'کپی پیوند')];
        }
        return ['ok', 'دعوت برای ' . View::ltr((string) $row->email) . ' ساخته شد' . ($mailed ? ' و ایمیل شد.' : ' (در صفحهٔ اصلی ناحیهٔ کاربری او نمایش داده می‌شود).')];
    }

    public static function adminPage(array $get): string
    {
        if (!Shares::ensure()) {
            return View::alert('bad', 'جدول اشتراک‌ها ساخته نشد.');
        }
        $f = ['q' => View::clip(Env::input($get['q'] ?? ''), 100), 'status' => isset(self::STATUS_FA[(string) ($get['status'] ?? '')]) ? (string) $get['status'] : '',
            'service' => (int) ($get['service'] ?? 0)];
        $q = Capsule::table(Shares::TABLE);
        if ($f['q'] !== '') {
            $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], strtolower($f['q'])) . '%';
            $q->where(function ($w) use ($like) {
                $w->where('domain', 'like', $like)->orWhere('email', 'like', $like);
            });
        }
        if ($f['status'] !== '') {
            $q->where('status', $f['status']);
        }
        if ($f['service'] > 0) {
            $q->where('service_id', $f['service']);
        }
        $rows = $q->orderBy('id', 'desc')->limit(200)->get()->all();
        $st = ['' => 'همه وضعیت‌ها'];
        foreach (self::STATUS_FA as $k => [$t]) {
            $st[$k] = $t;
        }
        $h = View::alert('info', 'اشتراک دامنه (§20): مالک یک سرویس CDN (یا مدیر، برای دامنه‌های اپراتور) یک دامنه را با حساب WHMCS دیگری با نقش مشاهده‌گر / مدیر DNS / ویرایشگر به اشتراک می‌گذارد. صورت‌حساب و مالکیت جابه‌جا نمی‌شود.');
        $h .= '<form method="get" action="' . View::e((string) (parse_url(View::$link, PHP_URL_PATH) ?: 'addonmodules.php')) . '" class="pcdna-filters" role="search">'
            . '<input type="hidden" name="module" value="' . View::e(Env::MODULE) . '"><input type="hidden" name="page" value="shares">'
            . '<label class="pcdna-search">' . View::icon('search') . '<input type="search" name="q" class="pcdna-input" value="' . View::e($f['q']) . '" placeholder="دامنه یا ایمیل" aria-label="جستجو"></label>'
            . View::select('status', $st, $f['status'], ' aria-label="وضعیت"')
            . ($f['service'] > 0 ? '<input type="hidden" name="service" value="' . $f['service'] . '">' : '')
            . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('search') . '<span>اعمال</span></button></form>';
        if (!$rows) {
            $h .= View::card('اشتراک‌ها', View::emptyState('اشتراکی پیدا نشد', '', 'users'), '', '', 'users');
        } else {
            $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-shares"><thead><tr><th>#</th><th>دامنه</th><th>مالک</th><th>عضو</th><th>نقش</th><th>وضعیت</th><th>تاریخ</th><th></th></tr></thead><tbody>';
            foreach ($rows as $r) {
                [$sl, $tone] = self::STATUS_FA[(string) $r->status] ?? [(string) $r->status, 'muted'];
                $owner = $r->owner_client_id ? '<a href="' . View::e(Data::clientUrl((int) $r->owner_client_id)) . '">مشتری #' . View::n((int) $r->owner_client_id) . '</a>'
                    . ($r->service_id ? ' · <a href="' . View::e(Data::serviceUrl((int) $r->owner_client_id, (int) $r->service_id)) . '">سرویس #' . View::n((int) $r->service_id) . '</a>' : '')
                    : View::badge('اپراتور', 'violet');
                $member = View::ltr((string) $r->email) . ($r->member_client_id ? '<div class="pcdna-small"><a href="' . View::e(Data::clientUrl((int) $r->member_client_id)) . '">مشتری #'
                    . View::n((int) $r->member_client_id) . '</a></div>' : '');
                $t .= '<tr data-share-row="' . (int) $r->id . '"><td>' . View::n((int) $r->id) . '</td><td>' . View::ltr((string) $r->domain) . '</td><td>' . $owner . '</td><td>' . $member . '</td>'
                    . '<td>' . View::e(Shares::roleLabel((string) $r->role)) . '</td><td>' . View::badge($sl, $tone) . '</td>'
                    . '<td class="pcdna-small">' . View::e(View::date($r->created_at)) . ($r->accepted_at ? '<br>پذیرش: ' . View::e(View::date($r->accepted_at)) : '')
                    . ($r->revoked_at ? '<br>پایان: ' . View::e(View::date($r->revoked_at)) : '') . '</td><td class="pcdna-actions">'
                    . (in_array((string) $r->status, Shares::LIVE, true) ? View::postButton(['page' => 'shares'], 'share_revoke', ['id' => (int) $r->id], 'لغو دسترسی',
                        'pcdna-btn pcdna-btn-sm pcdna-btn-danger', 'دسترسی ' . $r->email . ' به ' . $r->domain . ' لغو شود؟', 'trash') : '') . '</td></tr>';
            }
            $h .= View::card('اشتراک‌ها (' . View::n(count($rows)) . ')', $t . '</tbody></table></div>', '', 'pcdna-flush', 'users');
        }
        return $h . self::auditCard($f['q']);
    }

    /** The share audit trail from WHMCS's activity log (invites, accepts, revokes, members' writes). */
    private static function auditCard(string $q): string
    {
        if (!Env::hasTable('tblactivitylog')) {
            return '';
        }
        $rows = Capsule::table('tblactivitylog')->where(function ($w) {
            $w->where('description', 'like', 'Pasargad CDN: share %')->orWhere('description', 'like', 'Pasargad CDN [share:%');
        });
        if ($q !== '') {
            $rows->where('description', 'like', '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $q) . '%');
        }
        $rows = $rows->orderBy('id', 'desc')->limit(100)->get(['date', 'description', 'userid'])->all();
        $b = $rows ? '<div class="pcdna-table-wrap"><table class="pcdna-table" data-share-audit="1"><thead><tr><th>زمان</th><th>رویداد</th></tr></thead><tbody>'
            . implode('', array_map(function ($r) {
                return '<tr><td class="pcdna-small pcdna-nowrap">' . View::e(View::date($r->date, true)) . '</td><td dir="ltr" class="pcdna-small">' . View::e($r->description) . '</td></tr>';
            }, $rows)) . '</tbody></table></div>' : '<p class="pcdna-muted">رویدادی ثبت نشده است.</p>';
        return View::card('سابقهٔ اشتراک‌ها (Activity Log)', $b, '', '', 'history');
    }
}
