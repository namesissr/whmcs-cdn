<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

require_once __DIR__ . '/I18n.php';

if (!class_exists(__NAMESPACE__ . '\\Download', false)) {
    /**
     * SPEC §18.3: a file the controller produced (statement PDF/CSV, audit CSV) that the proxy streams to
     * the browser as is: api.php / the admin addon send it with this type and an attachment filename
     * instead of JSON. Only ClientApi::download() makes one, after checking type, size and signature.
     */
    final class Download
    {
        public $body;
        public $type;
        public $filename;

        public function __construct(string $body, string $type, string $filename)
        {
            $this->body = $body;
            $this->type = $type;
            $this->filename = $filename;
        }

        /** Response headers (api.php / Admin::emit add Cache-Control: no-store and nosniff). */
        public function headers(): array
        {
            return ['Content-Type: ' . $this->type, 'Content-Length: ' . strlen($this->body),
                'Content-Disposition: attachment; filename="' . $this->filename . '"'];
        }
    }
}

if (class_exists(__NAMESPACE__ . '\\ClientApi', false)) {
    return;
}

/**
 * Core of api.php — the JSON proxy between the client-area app and the
 * controller. Kept free of globals so it can be tested without WHMCS:
 * api.php collects the request + session facts and calls handle().
 *
 * The site domain always comes from the service row, never from the client;
 * the client only picks one of the whitelisted sub-paths below.
 *
 * Admin mode (the addon's «مدیریت کامل» page, 'admin_id' > 0 in the request):
 * same whitelist, CSRF and domain-from-service rules, but no ownership check
 * and writes are allowed whatever the WHMCS status is; every admin write is
 * recorded with logActivity().
 *
 * Operator context (SPEC §19.1, admin mode + 'context' => ['domain', 'server']): the addon's «دامنه‌های اپراتور»
 * manager. No WHMCS service: the domain and server come from the addon's session-bound context of ONE operator
 * site (checked against the controller's owner_kind), never from the request; same whitelist and validation.
 *
 * Reseller mode (SPEC §10.5, 'reseller_site_id' > 0): the same whitelist, CSRF,
 * query rules and proxy, but the domain is resolved from the reseller's OWN
 * sub-site row (mod_pasargadcdn_reseller_sites) keyed by (id, userid). A reseller
 * can only ever reach a sub-site whose userid matches the logged-in client; the
 * same "not found" answer covers a missing row and one owned by someone else.
 * 'reseller_op' carries the reseller-level actions (list/create/delete/report).
 *
 * Language (SPEC §16.10): error details are written in Persian and answered in English when the
 * client app is English ('lang' => 'en', from its X-PCDN-Lang header); admin mode stays Persian.
 */
class ClientApi
{
    const MAX_BODY = 262144; // 256 KB

    /**
     * SPEC §16.9: body limit of PUT config/functions only — the whole section with every function's
     * code (up to 32 × 256 KiB of UTF-8, i.e. 8 MiB, plus JSON escaping); every other call keeps
     * MAX_BODY. See maxBody().
     */
    const MAX_BODY_FUNCTIONS = 9437184; // 9 MB

    // Wave 6B (SPEC §14.2) added transform, redirects and bots; Wave 6D (§14.3) logs and webhooks;
    // Wave 8 (§16.4/§16.5/§16.7) l4 (TCP/UDP apps), video and dns_secondary; §16.9 functions (edge functions).
    // Wave 10 (SPEC §18.1/§18.2): waiting_room and access (bodies re-checked by sectionBody()).
    // Wave 14 (SPEC §23.7): rum (real user monitoring, gated by the plan feature `rum`).
    const SECTIONS = 'cache|ssl|waf|ddos|firewall|ratelimit|pagerules|pools|headers|hotlink|image|errorpages|tunnel|transform|redirects|bots|logs|webhooks|l4|video|dns_secondary|functions|waiting_room|access|rum';

    /** Webhook ids are assigned by the controller: "wh_" + 8 hex (SPEC §14.3.3). */
    const WEBHOOK_ID = 'wh_[0-9a-f]{8}';

    /**
     * SPEC §16.8 bucket name as the controller accepts it (storage.validate_name / NAME_RE): 3–40
     * characters of a-z, 0-9 and -, starting and ending with a letter or digit. Anything else never
     * leaves WHMCS (the controller prefixes it and never lets a name choose a host).
     */
    const BUCKET = '[a-z0-9][a-z0-9-]{1,38}[a-z0-9]';

    /**
     * SPEC §17.2 learning-mode proposal id, as the controller makes it (waf_learning.proposal_id:
     * "p_" + 16 hex of sha256(kind:target)); POST waf/learning/apply carries 1..MAX_APPLY_IDS of them
     * and nothing else.
     */
    const PROPOSAL_ID = '/^p_[0-9a-f]{16}$/D';
    const MAX_APPLY_IDS = 100;

    /** method => [sub-path regex relative to /api/v1/sites/{domain}, ...] */
    const ROUTES = [
        'GET' => [
            '', 'config/(?:' . self::SECTIONS . ')', 'records', 'records/export', 'dnssec',
            'analytics', 'events', 'usage', 'tunnel/stats', 'apikeys', 'origin-pull-ca',
            // Wave 6D (SPEC §14.3.1–§14.3.4)
            'analytics/live', 'logs/status', 'webhooks/deliveries', 'sla',
            // Wave 7 (SPEC §15.3/§15.4): tunnel quality, tunnel usage and origin health — read-only
            'tunnel/quality', 'tunnel/usage', 'tunnel/health',
            // SPEC §16.8 object storage: overview + buckets (never a secret — the controller returns
            // secret_key only in the create / rotate-key answers) and the file manager's listing
            'storage', 'storage/buckets', 'storage/buckets/' . self::BUCKET . '/objects',
            // SPEC §16.9 edge functions: invocations / CPU / errors of the last `hours` (read-only)
            'functions/stats',
            // SPEC §17.3 WAF learning mode: state, progress and proposals (read-only; starting / stopping
            // is a PUT config/waf with `learning`)
            'waf/learning',
            // SPEC §18.1–§18.3 (wave 10): waiting-room live stats, access sign-in log, monthly statement
            // (format=json here; pdf/csv are streamed by download()) and the site's audit entries (json/csv)
            self::W10_WAITING_ROOM, self::W10_ACCESS_LOG, self::W10_STATEMENT, self::W10_AUDIT,
            // SPEC §22.11 / §22.12 (wave 13): recommended client settings per path (edge timers, keepalive, mux, HTTP/3
            // availability — never a node name or address) and the «why did my connection drop?» report (read-only)
            self::W16_PROFILE, self::W16_DROPS,
            // SPEC §23.4 / §23.7 / §23.8 (wave 14): settings history (list, one version, diff), RUM report, diagnostics report
            // (customer audience only — the `audience` query is refused, see QUERY_DENY)
            self::W17_HISTORY, self::W17_VERSION, self::W17_DIFF, self::W17_RUM, self::W17_DIAG,
        ],
        'POST' => ['records', 'records/import', 'dnssec', 'purge', 'ns-check', 'ssl', 'tunnel/check', 'apikeys', 'redirects/import',
            'logs/test', 'webhooks/' . self::WEBHOOK_ID . '/(?:rotate|test)',
            // Wave 8 (SPEC §16.6): new image transform secret (returned once, never logged — ApiClient::redact)
            'image/transform-secret',
            // SPEC §16.8: new bucket / new access key — secret_key returned once, never logged (ApiClient::redact)
            'storage/buckets', 'storage/buckets/' . self::BUCKET . '/rotate-key',
            // SPEC §16.8 file manager: presigned upload / download URLs (one object, minutes), the
            // multipart handshake, folders, rename and delete. A presigned URL is a credential for
            // that one object, so these answers are not logged either (ApiClient::quiet).
            'storage/buckets/' . self::BUCKET . '/objects/(?:upload|download|folder|rename|delete)',
            'storage/buckets/' . self::BUCKET . '/objects/multipart',
            'storage/buckets/' . self::BUCKET . '/objects/multipart/(?:parts|complete|abort)',
            // SPEC §17.3: apply the chosen learning-mode proposals — body re-checked by applyBody()
            'waf/learning/apply',
            // SPEC §18.2: new access secret (all sign-in sessions end) — body must be empty, see sectionBody()
            self::W10_ACCESS_ROTATE,
            // SPEC §23.4: restore a version ({sections|null, dry_run}); §23.6: provider import preview (the customer's key passes
            // through to the controller only — never logged, see ApiClient::quiet) and apply — bodies re-checked by w17Body()
            self::W17_RESTORE, self::W17_IMPORT_PREVIEW, self::W17_IMPORT_APPLY],
        'PUT' => ['config/(?:' . self::SECTIONS . ')', 'records/[1-9][0-9]{0,9}', 'ssl/custom', 'ssl/origin-client'],
        'DELETE' => ['records/[1-9][0-9]{0,9}', 'ssl/custom', 'apikeys/[1-9][0-9]{0,9}', 'ssl/origin-client',
            // Wave 8 (SPEC §16.6): forget the image transform secret (unsigned transforms allowed again)
            'image/transform-secret',
            // SPEC §16.8: delete an (empty, unused) bucket — 409 otherwise
            'storage/buckets/' . self::BUCKET,
            // SPEC §23.6: forget an import session (the fetched provider data) before it expires
            self::W17_IMPORT_SESSION],
    ];

    /**
     * Whitelisted sub-paths that are NOT under /api/v1/sites/{domain}: public, site-independent
     * controller files fetched server-side so the browser never needs (or learns) the controller
     * URL. Same login/CSRF/ownership rules as every other path. sub-path => controller path.
     */
    const PUBLIC_FILES = ['origin-pull-ca' => '/origin-pull-ca.pem'];
    const MAX_PEM = 65536;

    /** Query parameters the client may pass, per sub-path, with their allowed values. */
    const QUERY = [
        'analytics' => ['period' => '/^(24h|7d|30d)$/D'],
        'events' => ['limit' => '/^([1-9][0-9]{0,2}|1000)$/D'],
        'usage' => ['days' => '/^([1-9][0-9]{0,2})$/D'],
        'tunnel/stats' => ['hours' => '/^(24|168|720)$/D'],
        // Wave 6D: live minutes 1..1440 (the app uses 15/60/360/1440), deliveries limit 1..200, SLA month YYYY-MM.
        'analytics/live' => ['minutes' => '/^([1-9][0-9]{0,2}|1[0-3][0-9]{2}|14[0-3][0-9]|1440)$/D'],
        'webhooks/deliveries' => ['limit' => '/^([1-9][0-9]?|1[0-9]{2}|200)$/D'],
        'sla' => ['month' => '/^[0-9]{4}-(0[1-9]|1[0-2])$/D'],
        // Wave 7: quality hours 1..744 (the app uses 24/168/720), tunnel usage days 1..90 (the app uses 30).
        'tunnel/quality' => ['hours' => '/^([1-9]|[1-9][0-9]|[1-6][0-9]{2}|7[0-3][0-9]|74[0-4])$/D'],
        'tunnel/usage' => ['days' => '/^([1-9]|[1-8][0-9]|90)$/D'],
        // SPEC §16.9: functions stats hours 1..744 (the app uses 24 and 168)
        'functions/stats' => ['hours' => '/^([1-9]|[1-9][0-9]|[1-6][0-9]{2}|7[0-3][0-9]|74[0-4])$/D'],
        // SPEC §18.3: statement month YYYY-MM, format pdf|csv|json, lang fa|en; audit from/to (date or ISO-8601 UTC), json|csv
        self::W10_STATEMENT => ['month' => '/^[0-9]{4}-(0[1-9]|1[0-2])$/D', 'format' => '/^(pdf|csv|json)$/D', 'lang' => '/^(fa|en)$/D'],
        self::W10_AUDIT => ['from' => self::W10_TIME, 'to' => self::W10_TIME, 'format' => '/^(json|csv)$/D'],
        self::W10_ACCESS_LOG => ['limit' => '/^([1-9][0-9]?|1[0-9]{2}|200)$/D'],
        self::W10_WAITING_ROOM => ['hours' => '/^([1-9]|[1-9][0-9]|1[0-5][0-9]|16[0-8])$/D'],
        // SPEC §22.12: drops report hours 1..744, same rule as tunnel/quality (the app uses 24/168/720). tunnel/profile takes no query.
        self::W16_DROPS => ['hours' => '/^([1-9]|[1-9][0-9]|[1-6][0-9]{2}|7[0-3][0-9]|74[0-4])$/D'],
        // SPEC §23.4: history page size 1..200, `before` a version number; §23.7: RUM window and breakdown
        self::W17_HISTORY => ['limit' => '/^([1-9][0-9]?|1[0-9]{2}|200)$/D', 'before' => '/^[0-9]{1,9}$/D'],
        self::W17_RUM => ['hours' => '/^(24|168|720)$/D', 'by' => '/^(country|isp|region|device|path)$/D'],
    ];

    /** Query rules of parametrised sub-paths (regex => [key => value regex]); exact QUERY keys win. */
    const QUERY_RE = [
        // SPEC §23.4: diff against `current` or another version, optionally one section
        self::W17_DIFF => ['against' => '/^(current|[0-9]{1,9})$/D', 'section' => '/^(' . self::SECTIONS . ')$/D'],
        // SPEC §16.8 file manager listing: the folder being viewed, the server's own continuation
        // token, and the page size. A key is customer content, so anything but a control character
        // and a `..` segment is allowed through; the controller validates the key itself.
        'storage/buckets/' . self::BUCKET . '/objects' => [
            'prefix' => '/^(?!.*\.\.)[^\x00-\x1f\x7f]{0,1024}$/uD',
            'token' => '/^[^\x00-\x1f\x7f]{1,2048}$/uD',
            'limit' => '/^([1-9][0-9]{0,2}|1000)$/D',
        ],
    ];

    /**
     * Query keys that make the whole call invalid (400) instead of being dropped: SPEC §23.8 — the client app never asks for
     * the admin audience of the diagnostics report (`internal` node facts); only the admin addon calls it with the admin key.
     */
    const QUERY_DENY = [self::W17_DIAG => ['audience']];

    // ------------------------------------------------------------------ wave 14 (SPEC §23) — release safety, operations, customer experience
    /** GET ?limit&before → {versions: [{version, at, actor: {kind, label, id}, source, sections, restored_from, restorable}], current, retention} */
    const W17_HISTORY = 'config/history';
    /** GET → {version, at, actor, source, sections, config: {section: redacted value}} */
    const W17_VERSION = 'config/history/[0-9]{1,9}';
    /** GET ?against=current|N&section → {from, to, sections: {name: [ops]}, redacted} */
    const W17_DIFF = 'config/history/[0-9]{1,9}/diff';
    /** POST {sections: [..]|null, dry_run: bool} → {version|null, restored_from, applied, unchanged, dropped, warnings} */
    const W17_RESTORE = 'config/history/[0-9]{1,9}/restore';
    /** GET ?hours&by → {enabled, sample_rate, n, metrics, thresholds, by, series, cdn_impact, has_data} (404 = plan has no rum) */
    const W17_RUM = 'rum';
    /** GET → customer-audience report (labels, never node names / IPs); the ticket flow uses the session-bound local op `diag` */
    const W17_DIAG = 'diagnostics';
    /** POST {provider: arvan|cloudflare, api_key, zone?} → {session_id, expires_at, provider, zone, report} */
    const W17_IMPORT_PREVIEW = 'import/preview';
    /** POST {session_id, records, replace_records, record_names, sections} → {records, sections, config_version, dns_error} */
    const W17_IMPORT_APPLY = 'import/apply';
    /** DELETE → 204 */
    const W17_IMPORT_SESSION = 'import/imp_[0-9a-f]{16}';
    /** Sections an import may apply (§23.6 mapping table). */
    const W17_IMPORT_SECTIONS = ['cache', 'ssl', 'firewall', 'redirects', 'ddos', 'ratelimit'];

    /**
     * SPEC §23.5 account-level alert routes (relative to /api/v1/accounts/{client id}/alerts — the client id is ALWAYS the
     * session's own, never input): method => [regex, ...]. Proxied by accountOp() with the service's controller.
     */
    const ACCOUNT_ROUTES = [
        'GET' => ['', 'targets/link/[A-Z2-9]{8}'],
        'PUT' => ['subscriptions'],
        'POST' => ['targets/sms', 'targets/[1-9][0-9]{0,9}/verify', 'targets/(?:bale|telegram)/link', 'test'],
        'DELETE' => ['targets/[1-9][0-9]{0,9}'],
    ];
    const ALERT_CHANNELS = ['email', 'sms', 'bale', 'telegram'];
    const ALERT_EVENT = '/^[a-z][a-z_]{1,24}\\.[a-z][a-z_]{1,24}$/D';
    const HHMM = '/^([01][0-9]|2[0-3]):[0-5][0-9]$/D';

    // ------------------------------------------------------------------ wave 13 (SPEC §22) — tunnel speed and stability
    /** GET → {edge: {...timers}, http3: {site, nodes, nodes_h3, available}, paths: [{id, idle_timeout_s, recommended, http3, …}]} (§22.11) */
    const W16_PROFILE = 'tunnel/profile';
    /** GET ?hours → {hours, total, reasons, rejected, paths, series, maintenance, plan, top, has_data} (§22.12) */
    const W16_DROPS = 'tunnel/drops';

    // ------------------------------------------------------------------ wave 10 (SPEC §18) — the controller contract in one place
    /** GET → {enabled, active_estimate, queued_estimate, last_hour: {...}, hourly: [...]} (§18.1) */
    const W10_WAITING_ROOM = 'waiting-room';
    /** GET → last ≤200 sign-ins / failures: [{t, app, email_hash, ok}] or {events: [...]} (§18.2) */
    const W10_ACCESS_LOG = 'access/log';
    /** POST {} → new access_secret, every access session invalid (§18.2) */
    const W10_ACCESS_ROTATE = 'access/rotate';
    /** GET ?month&format=pdf|csv|json&lang (§18.3) */
    const W10_STATEMENT = 'statement';
    /** GET ?from&to&format=json|csv (§18.3) */
    const W10_AUDIT = 'audit';
    /** Controller path of the client error forwarder (§18.4), admin key. */
    const W10_CLIENT_ERRORS = '/api/v1/client-errors';
    /** Audit range bounds: YYYY-MM-DD or YYYY-MM-DDTHH:MM[:SS]Z. */
    const W10_TIME = '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])(T([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?Z)?$/D';

    /**
     * SPEC §18.3 downloads streamed as files: sub-path => format => [expected content type, extension, max bytes].
     * The statement PDF is ≤ 2 MB by contract (4 MB accepted); the audit CSV is ≤ 10 000 rows.
     */
    const DOWNLOADS = [
        self::W10_STATEMENT => ['pdf' => ['application/pdf', 'pdf', 4194304], 'csv' => ['text/csv; charset=utf-8', 'csv', 8388608]],
        self::W10_AUDIT => ['csv' => ['text/csv; charset=utf-8', 'csv', 8388608]],
    ];

    /** SPEC §18.4 client error reports: ≤ 10 per minute per session, body ≤ 16 KB. */
    const CLIENT_ERROR_RATE = 10;
    const CLIENT_ERROR_WINDOW = 60;
    const CLIENT_ERROR_MAX_BODY = 16384;
    const CLIENT_ERROR_STACK = 4096;

    // ------------------------------------------------------------------ SPEC §20.1 domain sharing: per-role allow-list (deny by default)
    const SHARE_ROLES = ['viewer', 'dns', 'editor'];
    /** Every whitelisted GET except the customer API keys (owner only). */
    const SHARE_READ_DENY = ['apikeys'];
    /**
     * SPEC §16.8: a POST that only reads. The file manager's listing is a GET, so every role can see
     * the file names; a download link is a POST because the key travels in the body, and withholding
     * it would leave a member staring at names they cannot open. Uploading, renaming and deleting
     * stay writes (SHARE_EDITOR).
     */
    const SHARE_READ_POST = ['storage/buckets/' . self::BUCKET . '/objects/download'];
    /** dns: records (incl. import / export), the NS re-check and the secondary-DNS section; DNSSEC is view-only. */
    const SHARE_DNS = [
        'POST' => ['records', 'records/import', 'ns-check'],
        'PUT' => ['config/dns_secondary', 'records/[1-9][0-9]{0,9}'],
        'DELETE' => ['records/[1-9][0-9]{0,9}'],
    ];
    /**
     * editor: every configuration write listed explicitly — NOT customer API keys (POST apikeys / DELETE apikeys/N) and NOT
     * storage bucket key rotation; billing / upgrade / add-ons / cancel / transfer / sharing / team / site delete are not
     * proxied at all. A route added to ROUTES later stays denied until it is listed here.
     */
    const SHARE_EDITOR = [
        'POST' => ['records', 'records/import', 'dnssec', 'purge', 'ns-check', 'ssl', 'tunnel/check', 'redirects/import', 'logs/test',
            'webhooks/' . self::WEBHOOK_ID . '/(?:rotate|test)', 'image/transform-secret', 'storage/buckets', 'waf/learning/apply', self::W10_ACCESS_ROTATE,
            // SPEC §16.8: the file manager's writes — upload (single and multipart), folders, rename
            // and delete. The listing and a download link are reads (SHARE_READ_DENY / _READ_POST).
            'storage/buckets/' . self::BUCKET . '/objects/(?:upload|folder|rename|delete)',
            'storage/buckets/' . self::BUCKET . '/objects/multipart',
            'storage/buckets/' . self::BUCKET . '/objects/multipart/(?:parts|complete|abort)',
            // SPEC §23.4: restoring a version needs the edit role (viewers and DNS managers see history and diffs only);
            // §23.6: a provider import writes DNS records AND sections, so it is an editor action too
            self::W17_RESTORE, self::W17_IMPORT_PREVIEW, self::W17_IMPORT_APPLY],
        'PUT' => ['config/(?:' . self::SECTIONS . ')', 'records/[1-9][0-9]{0,9}', 'ssl/custom', 'ssl/origin-client'],
        'DELETE' => ['records/[1-9][0-9]{0,9}', 'ssl/custom', 'ssl/origin-client', 'image/transform-secret', 'storage/buckets/' . self::BUCKET,
            self::W17_IMPORT_SESSION],
    ];

    /** May a member with $role call $method $path (already on the whitelist)? */
    public static function shareAllows(string $role, string $method, string $path): bool
    {
        if (!in_array($role, self::SHARE_ROLES, true) || !self::allowed($method, $path)) {
            return false;
        }
        if ($method === 'GET') {
            return !in_array($path, self::SHARE_READ_DENY, true);
        }
        if ($method === 'POST') {
            foreach (self::SHARE_READ_POST as $re) {
                if (preg_match('#^' . $re . '$#D', $path)) {
                    return true;
                }
            }
        }
        $list = $role === 'editor' ? self::SHARE_EDITOR : ($role === 'dns' ? self::SHARE_DNS : []);
        foreach ($list[$method] ?? [] as $re) {
            if (preg_match('#^' . $re . '$#D', $path)) {
                return true;
            }
        }
        return false;
    }

    /** Answer for a write by a read-only team member (SPEC §14.3.7). */
    const READONLY_DETAIL = 'دسترسی شما به این سرویس فقط‌خواندنی است؛ برای تغییر تنظیمات از مالک حساب بخواهید دسترسی «مدیریت محصولات» را به شما بدهد.';

    /**
     * @param array $req [
     *   'method' => 'GET', 'id' => '123', 'path' => 'config/cache', 'query' => [...],
     *   'body' => raw request body, 'csrf' => X-PCDN-CSRF header,
     *   'session_csrf' => token stored in the session, 'client_id' => logged-in client id or 0,
     *   'admin_id' => WHMCS admin id (admin mode only — set by the addon, never from input),
     *   'readonly' => true for a WHMCS user without the manage-products permission (TeamAccess, §14.3.7):
     *                 every non-GET call is refused with 403 before anything else happens,
     *   'lang' => 'fa' | 'en' — language of the error details (§16.10; ignored in admin mode except the operator context),
     *   'context' => SPEC §19.1 operator context ['domain' => ..., 'server' => tblservers row] (admin addon only),
     *   'admin_user' => the admin's username for the activity log (admin mode),
     * ]
     * @param callable|null $clientFactory fn(array $serverParams): ApiClient (tests)
     * @return array [http status, response array]
     */
    public static function handle(array $req, ?callable $clientFactory = null): array
    {
        $method = strtoupper((string) ($req['method'] ?? 'GET'));
        $path = (string) ($req['path'] ?? '');

        $adminId = (int) ($req['admin_id'] ?? 0);
        $admin = $adminId > 0;
        // SPEC §19.1: the operator-site manager (admin 'context') renders the app in either language
        $hasCtx = array_key_exists('context', $req);
        I18n::$current = (!$admin || $hasCtx) && ($req['lang'] ?? '') === 'en' ? 'en' : 'fa';
        if (!$admin && (int) ($req['client_id'] ?? 0) <= 0) {
            return self::fail(401, 'لطفاً دوباره وارد حساب کاربری شوید.');
        }
        $sessionToken = (string) ($req['session_csrf'] ?? '');
        if ($sessionToken === '' || !hash_equals($sessionToken, (string) ($req['csrf'] ?? ''))) {
            return self::fail(403, 'درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.');
        }
        // Team access (SPEC §14.3.7): a read-only WHMCS user may only read — this covers config
        // writes, purges, records, API keys, webhook tests/rotation and the reseller ops alike,
        // whatever the UI shows. Admin mode is never read-only.
        if (!$admin && !empty($req['readonly']) && $method !== 'GET') {
            return self::fail(403, self::READONLY_DETAIL);
        }
        // Reseller-level operations (list / create / delete sub-site, rolled-up report).
        // Not tied to a controller sub-path, so handled before the site whitelist.
        // Growth ops on WHMCS-side state of THIS service (onboarding progress, e-mail report opt-in):
        // same login / CSRF / read-only rules, ownership checked against tblhosting, never the controller.
        $lop = (string) ($req['local_op'] ?? '');
        if ($lop !== '') {
            return self::localOp($lop, $req, $admin);
        }
        $rop = (string) ($req['reseller_op'] ?? '');
        if ($rop !== '') {
            return self::resellerOp($rop, $req, $clientFactory);
        }
        // SPEC §23.5: account-level alert channels / subscriptions of the logged-in client (api.php `acct=<sub-path>`)
        if (array_key_exists('account_path', $req) && $req['account_path'] !== null) {
            return self::accountOp(is_string($req['account_path']) ? $req['account_path'] : "\0", $req, $admin, $clientFactory);
        }
        if (!self::allowed($method, $path)) {
            return self::fail(404, 'مسیر نامعتبر است.');
        }

        // SPEC §19.1 operator context (admin addon «دامنه‌های اپراتور» → manage): a synthetic context bound to ONE
        // operator domain and its server, built server-side by the addon (Admin\Operator::apiContext — never from
        // request input; api.php never passes 'context'). Same whitelist, CSRF, query and body rules as every
        // other mode; admin-only, every write audited with the admin's name.
        if ($hasCtx && is_array($req['context']) && ($req['context']['kind'] ?? '') === 'shared') {
            // SPEC §20.3: a member of a shared domain — the addon's «دامنه‌های اشتراکی» route builds this context from the
            // member's ACTIVE share row (re-read on every request), never from input: one domain, one role, owner's server.
            $ctx = $req['context'];
            $role = (string) ($ctx['role'] ?? '');
            if ($admin || (int) ($req['client_id'] ?? 0) <= 0 || !is_string($ctx['domain'] ?? null) || !is_object($ctx['server'] ?? null)
                || !in_array($role, self::SHARE_ROLES, true)) {
                return self::fail(404, 'سرویس یافت نشد.');
            }
            if (!self::shareAllows($role, $method, $path)) {
                return self::fail(403, 'نقش شما در این دامنه اجازهٔ این کار را نمی‌دهد.');
            }
            if ($method !== 'GET' && !empty($ctx['readonly'])) {
                return self::fail(403, 'این سرویس فعال نیست.');
            }
            $domain = \pasargadcdn_domain(['domain' => $ctx['domain']]);
            $svc = (object) ['id' => (int) ($ctx['service_id'] ?? 0), 'userid' => (int) ($ctx['owner_client_id'] ?? 0), 'domain' => $domain];
            return self::proxy($method, $path, $domain, $ctx['server'], $req, false, 0, $svc, $clientFactory);
        }
        if ($hasCtx) {
            $ctx = $req['context'];
            if (!$admin || !is_array($ctx) || !is_string($ctx['domain'] ?? null) || !is_object($ctx['server'] ?? null)) {
                return self::fail(404, 'سرویس یافت نشد.');
            }
            $domain = \pasargadcdn_domain(['domain' => $ctx['domain']]);
            $svc = (object) ['id' => 0, 'userid' => 0, 'domain' => $domain];
            return self::proxy($method, $path, $domain, $ctx['server'], $req, true, $adminId, $svc, $clientFactory);
        }

        // Reseller mode (SPEC §10.5): manage one of the logged-in client's OWN sub-sites.
        // The domain is resolved from mod_pasargadcdn_reseller_sites by (id, userid) — never
        // from client input — so a reseller can only ever reach a sub-site it owns.
        $rsid = (int) ($req['reseller_site_id'] ?? 0);
        if ($rsid > 0) {
            if ($admin) {
                return self::fail(404, 'سرویس یافت نشد.');
            }
            require_once __DIR__ . '/Reseller.php';
            $clientId = (int) ($req['client_id'] ?? 0);
            $row = Reseller::ownedSite($clientId, $rsid);
            // Same answer for "missing" and "not yours".
            if (!$row) {
                return self::fail(404, 'سرویس یافت نشد.');
            }
            // A sub-site cut by the wallet (suspended) may still be viewed, not written to.
            if ((int) $row->suspended === 1 && $method !== 'GET') {
                return self::fail(403, 'این زیرسایت به‌دلیل اتمام اعتبار نمایندگی موقتاً قطع است.');
            }
            $domain = \pasargadcdn_domain(['domain' => (string) $row->domain]);
            $server = Reseller::server();
            return self::proxy($method, $path, $domain, $server, $req, false, 0, null, $clientFactory);
        }

        $id = (string) ($req['id'] ?? '');
        if (!preg_match('/^[1-9][0-9]{0,9}$/D', $id)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }

        $svc = Capsule::table('tblhosting')->where('id', (int) $id)
            ->first(['id', 'userid', 'packageid', 'server', 'domain', 'domainstatus']);
        // Same answer for "missing" and "not yours" so ids can't be probed.
        if (!$svc || (!$admin && (int) $svc->userid !== (int) ($req['client_id'] ?? 0))) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $product = Capsule::table('tblproducts')->where('id', (int) $svc->packageid)->first(['servertype']);
        if (!$product || $product->servertype !== 'pasargadcdn') {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $status = (string) $svc->domainstatus;
        if (!$admin && ($method === 'GET' ? !in_array($status, ['Active', 'Suspended'], true) : $status !== 'Active')) {
            return self::fail(403, 'این سرویس فعال نیست.');
        }

        $domain = \pasargadcdn_domain(['domain' => $svc->domain]);
        $server = Capsule::table('tblservers')->where('id', (int) $svc->server)
            ->first(['type', 'hostname', 'ipaddress', 'secure', 'port', 'accesshash', 'password']);
        return self::proxy($method, $path, $domain, $server, $req, $admin, $adminId, $svc, $clientFactory);
    }

    /**
     * Release the PHP session write-lock before a long controller call. PHP serialises every request in
     * one browser session on a single session file lock, so while the client app's background boot calls
     * (tunnel/health, tunnel/profile, config/history, account alerts, …) are still in flight holding it,
     * the NEXT request — e.g. a page refresh calling session_start() — BLOCKS until they finish and the
     * page appears to hang; re-opening the service later works only because the calls have since drained.
     * By here the request has already READ everything it needs from the session (the CSRF token and the
     * client id, captured into $req by the entry point) and writes nothing more, so the lock can go now.
     * clientError() is the only path that writes the session and it never reaches these call sites.
     * A no-op under tests / CLI, where no session is active; @ silences a late-close notice.
     */
    private static function releaseSession(): void
    {
        if (\function_exists('session_write_close') && \session_status() === \PHP_SESSION_ACTIVE) {
            @\session_write_close();
        }
    }

    /**
     * Shared controller proxy tail: validate body/query/domain/server and forward the
     * whitelisted call to the controller, returning [status, data]. Used for normal,
     * admin and reseller-site modes alike (same whitelist, CSRF and rules).
     */
    private static function proxy(string $method, string $path, string $domain, $server, array $req,
                                  bool $admin, int $adminId, $svc, ?callable $clientFactory): array
    {
        self::releaseSession();
        $body = null;
        if ($method === 'POST' || $method === 'PUT') {
            $raw = (string) ($req['body'] ?? '');
            if (strlen($raw) > self::maxBody($method, $path)) {
                return self::fail(413, 'حجم درخواست بیش از حد مجاز است.');
            }
            $data = $raw === '' ? [] : json_decode($raw, true, 64);
            if (!is_array($data)) {
                return self::fail(400, 'بدنه درخواست باید JSON معتبر باشد.');
            }
            if ($method === 'POST' && $path === 'waf/learning/apply') {
                $data = self::applyBody($data);
                if ($data === null) {
                    return self::fail(400, 'پارامتر نامعتبر است.');
                }
            }
            // Wave 10 (SPEC §18.1/§18.2): the new sections and the rotate call carry exactly the contract's shape
            if ($method === 'POST' && $path === self::W10_ACCESS_ROTATE && $data !== []) {
                return self::fail(400, 'پارامتر نامعتبر است.');
            }
            if ($method === 'PUT' && ($path === 'config/waiting_room' || $path === 'config/access')) {
                $bad = $path === 'config/access' ? self::accessProblems($data) : self::waitingRoomProblems($data);
                if ($bad) {
                    return [422, ['detail' => $bad]];
                }
            }
            // Wave 14 (SPEC §23.4 / §23.6 / §23.7): restore, import and rum bodies carry exactly the contract's keys. The import
            // preview body holds the customer's provider key: an invalid one is refused WITHOUT echoing anything back.
            if (($method === 'POST' && self::w17Post($path)) || ($method === 'PUT' && $path === 'config/rum')) {
                $data = self::w17Body($method, $path, $data);
                if ($data === null) {
                    return self::fail(400, 'پارامتر نامعتبر است.');
                }
            }
            // Re-encoded, so only well-formed JSON ever reaches the controller.
            $body = json_encode($data === [] ? new \stdClass() : $data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }

        $query = self::query($path, (array) ($req['query'] ?? []));
        foreach (self::QUERY_DENY[$path] ?? [] as $deny) {
            if (array_key_exists($deny, (array) ($req['query'] ?? []))) {
                $query = null;
            }
        }
        if ($query === null) {
            return self::fail(400, 'پارامتر نامعتبر است.');
        }
        if ($method === 'GET' && $path === self::W10_STATEMENT) {
            // SPEC §18.3: the controller knows neither the plan name nor the prepaid block size — WHMCS adds them
            // from the service's product and the addon settings (never from the request)
            $extra = self::statementExtras($svc);
            if ($extra) {
                $query .= ($query === '' ? '?' : '&') . http_build_query($extra);
            }
        }

        // Defence in depth: the domain is admin/order data, keep it a plain hostname.
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/D', $domain)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        if (!$server || ($server->type ?? '') !== 'pasargadcdn') {
            return self::fail(502, 'سرور CDN برای این سرویس تنظیم نشده است.');
        }

        $target = ApiClient::site($domain) . ($path === '' ? '' : '/' . $path) . $query;
        try {
            $params = [
                'serverhostname' => $server->hostname,
                'serverip' => $server->ipaddress,
                'serversecure' => $server->secure,
                'serverport' => $server->port,
                'serveraccesshash' => $server->accesshash,
                'serverpassword' => (trim((string) $server->accesshash) === '' && function_exists('decrypt'))
                    ? decrypt($server->password) : '',
            ];
            // Admin pages keep every controller call within 10 s.
            $api = $clientFactory ? $clientFactory($params) : ApiClient::fromParams($params, $admin ? 10 : 20);
            $share = self::shareCtx($req);
            if ($share && method_exists($api, 'setActor')) {
                // SPEC §20.3: the controller records it as `on_behalf_of` in the audit detail
                $api->setActor(self::actor($req));
            } elseif (!$admin && (int) ($req['client_id'] ?? 0) > 0 && method_exists($api, 'setActor')) {
                // SPEC §23.4: the owner's own writes say `client:<id>` so the settings history shows «شما» (sent on writes only)
                $api->setActor('client:' . (int) $req['client_id']);
            }
            if ($method === 'POST' && $path === self::W17_IMPORT_PREVIEW && method_exists($api, 'quiet')) {
                // SPEC §23.6: the preview body carries the customer's provider key — never in the module log (nor the answer)
                $api->quiet(true);
            }
            // SPEC §16.8 file manager: the answer carries presigned URLs, which ARE the credential for
            // that one object until they expire — keep them out of the module log.
            if ($method === 'POST' && \preg_match('#^storage/buckets/[^/]+/objects/(?:upload|download|multipart)#', $path) === 1
                && \method_exists($api, 'quiet')) {
                $api->quiet(true);
            }
            if (isset(self::PUBLIC_FILES[$path])) {
                return self::pemFile($api, self::PUBLIC_FILES[$path]);
            }
            $fmt = $method === 'GET' ? self::downloadFormat($path, (array) ($req['query'] ?? [])) : null;
            if ($fmt !== null) {
                return self::download($api, $target, $path, $fmt, $domain, (array) ($req['query'] ?? []));
            }
            [$code, $data] = $api->raw($method, $target, $body);
        } catch (\Throwable $e) {
            self::log($method . ' ' . $target, $e->getMessage());
            if (self::shareCtx($req) && $method !== 'GET') {
                self::shareLog($req, $method, $path, $svc, 'failed: controller unreachable');
            }
            if ($admin && $method !== 'GET') {
                self::adminLog($adminId, $method, $path, $svc, 'failed: controller unreachable', (string) ($req['admin_user'] ?? ''));
            }
            return self::fail(502, 'اتصال به سرور CDN برقرار نشد.');
        }
        if ($admin && $method !== 'GET') {
            self::adminLog($adminId, $method, $path, $svc, 'HTTP ' . $code, (string) ($req['admin_user'] ?? ''));
        }
        if (self::shareCtx($req) && $method !== 'GET') {
            self::shareLog($req, $method, $path, $svc, 'HTTP ' . $code);
        }
        if ($code >= 500 || $code < 200 || ($code >= 300 && $code < 400)) {
            self::log($method . ' ' . $target, 'HTTP ' . $code);
            return self::fail(502, I18n::tr('خطای سرور CDN (HTTP %s)', $code));
        }
        if (!is_array($data)) {
            // Empty/non-JSON body: fine for a 2xx, generic message for a 4xx.
            return $code < 300 ? [$code, ['ok' => true]] : self::fail($code, I18n::tr('درخواست توسط سرور CDN رد شد (HTTP %s)', $code));
        }
        if ($code >= 400 && isset($data['detail']) && is_string($data['detail'])) {
            // SPEC §16.10: a known controller detail (e.g. the §16.8 storage refusals) in the app's language
            $data['detail'] = I18n::controller($data['detail']);
        }
        if ($code < 300 && $method === 'GET' && ($path === self::W17_HISTORY || preg_match('#^' . self::W17_VERSION . '$#D', $path))) {
            // SPEC §23.4: who changed it — «شما» / «همکار: نام» are resolved here (the controller only knows ids)
            $data = self::historyActors($data, $domain, $req);
        }
        return [$code, $data];
    }

    // ------------------------------------------------------------------ wave 14 (SPEC §23) helpers

    /** POST sub-paths whose body is re-checked by w17Body(). */
    private static function w17Post(string $path): bool
    {
        return $path === self::W17_IMPORT_PREVIEW || $path === self::W17_IMPORT_APPLY || (bool) preg_match('#^' . self::W17_RESTORE . '$#D', $path);
    }

    private static function isBool($v): bool
    {
        return is_bool($v);
    }

    /** A list of distinct section names (SECTIONS), ≤ $max; null when anything else. */
    private static function sectionList($v, int $max, array $only = []): ?array
    {
        if (!self::isList($v) || count($v) > $max) {
            return null;
        }
        $out = [];
        foreach ($v as $x) {
            if (!is_string($x) || !preg_match('/^(' . self::SECTIONS . ')$/D', $x) || ($only && !in_array($x, $only, true))) {
                return null;
            }
            $out[$x] = true;
        }
        return array_keys($out);
    }

    /**
     * Cleaned body of a wave-14 write, or null when it does not match the contract:
     *  - POST config/history/N/restore {sections: [names]|null, dry_run: bool} (§23.4);
     *  - POST import/preview {provider: arvan|cloudflare, api_key: 1..512 printable chars, zone?: hostname} (§23.6);
     *  - POST import/apply {session_id, records, replace_records, record_names: [..]|null, sections: [..]} (§23.6);
     *  - PUT config/rum {enabled, sample_rate 0.01..1, inject auto|manual, exclude_paths ≤ 20, spa} (§23.7).
     */
    public static function w17Body(string $method, string $path, array $d): ?array
    {
        if ($method === 'PUT' && $path === 'config/rum') {
            // SPEC §23.7 names the keys sample_rate / exclude_paths; the controller also answers with the edge names sample / exclude —
            // whichever the controller returned is sent back (same checks)
            foreach (['sample' => 'sample_rate', 'exclude' => 'exclude_paths'] as $alias => $k) {
                if (array_key_exists($alias, $d)) {
                    if (array_key_exists($k, $d)) {
                        return null;
                    }
                    $chk = self::w17Body('PUT', 'config/rum', [$k => $d[$alias]]);
                    if ($chk === null) {
                        return null;
                    }
                }
            }
            if (array_diff(array_keys($d), ['enabled', 'sample_rate', 'inject', 'exclude_paths', 'spa', 'sample', 'exclude'])) {
                return null;
            }
            if ((array_key_exists('enabled', $d) && !is_bool($d['enabled'])) || (array_key_exists('spa', $d) && !is_bool($d['spa']))
                || (array_key_exists('inject', $d) && !in_array($d['inject'], ['auto', 'manual'], true))
                || (array_key_exists('sample_rate', $d) && (!(is_int($d['sample_rate']) || is_float($d['sample_rate'])) || $d['sample_rate'] < 0.01 || $d['sample_rate'] > 1))) {
                return null;
            }
            if (array_key_exists('exclude_paths', $d)) {
                if (!self::isList($d['exclude_paths']) || count($d['exclude_paths']) > 20) {
                    return null;
                }
                foreach ($d['exclude_paths'] as $p) {
                    if (!is_string($p) || !preg_match('~^/[^\s?#]{0,199}$~D', $p)) {
                        return null;
                    }
                }
            }
            return $d;
        }
        if ($path === self::W17_IMPORT_PREVIEW) {
            $key = $d['api_key'] ?? null;
            if (array_diff(array_keys($d), ['provider', 'api_key', 'zone']) || !in_array($d['provider'] ?? null, ['arvan', 'cloudflare'], true)
                || !is_string($key) || $key === '' || strlen($key) > 512 || preg_match('/[\x00-\x1f\x7f]/', $key)) {
                return null;
            }
            $out = ['provider' => $d['provider'], 'api_key' => $key];
            if (isset($d['zone']) && $d['zone'] !== '') {
                $z = is_string($d['zone']) ? strtolower(trim($d['zone'])) : '';
                if (!preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/D', $z)) {
                    return null;
                }
                $out['zone'] = $z;
            }
            return $out;
        }
        if ($path === self::W17_IMPORT_APPLY) {
            if (array_diff(array_keys($d), ['session_id', 'records', 'replace_records', 'record_names', 'sections'])
                || !is_string($d['session_id'] ?? null) || !preg_match('/^imp_[0-9a-f]{16}$/D', $d['session_id'])) {
                return null;
            }
            $out = ['session_id' => $d['session_id'], 'records' => $d['records'] ?? true, 'replace_records' => $d['replace_records'] ?? false,
                'record_names' => $d['record_names'] ?? null, 'sections' => $d['sections'] ?? []];
            if (!is_bool($out['records']) || !is_bool($out['replace_records'])) {
                return null;
            }
            if ($out['record_names'] !== null) {
                if (!self::isList($out['record_names']) || count($out['record_names']) > 10000) {
                    return null;
                }
                foreach ($out['record_names'] as $n) {
                    if (!is_string($n) || $n === '' || strlen($n) > 300 || preg_match('/[\x00-\x1f\x7f]/', $n)) {
                        return null;
                    }
                }
            }
            $out['sections'] = self::sectionList($out['sections'], 10, self::W17_IMPORT_SECTIONS);
            return $out['sections'] === null ? null : $out;
        }
        // restore
        if (array_diff(array_keys($d), ['sections', 'dry_run']) || (array_key_exists('dry_run', $d) && !is_bool($d['dry_run']))) {
            return null;
        }
        $out = ['sections' => null, 'dry_run' => (bool) ($d['dry_run'] ?? false)];
        if (isset($d['sections'])) {
            $out['sections'] = self::sectionList($d['sections'], 40);
            if ($out['sections'] === null || !$out['sections']) {
                return null;
            }
        }
        return $out;
    }

    /**
     * SPEC §23.4 actor names for the history timeline. `self` marks the viewer's own changes («شما»); a collaborator of THIS
     * domain gets `name` (first + last name or company) — only members of a share row of this domain are looked up, so the
     * proxy never reveals another account's name. Never fails: an unknown member keeps its id only.
     */
    public static function historyActors($data, string $domain, array $req)
    {
        if (!is_array($data)) {
            return $data;
        }
        $viewer = (int) ($req['client_id'] ?? 0);
        $share = self::shareCtx($req);
        $names = [];
        $fix = function ($a) use ($viewer, $share, $domain, &$names) {
            if (!is_array($a)) {
                return $a;
            }
            $kind = (string) ($a['kind'] ?? '');
            $id = is_scalar($a['id'] ?? null) && ctype_digit((string) $a['id']) ? (int) $a['id'] : 0;
            if ($viewer > 0 && $id === $viewer && (($kind === 'client' && !$share) || ($kind === 'collaborator' && $share))) {
                $a['self'] = true;
            }
            if ($kind === 'collaborator' && $id > 0) {
                if (!array_key_exists($id, $names)) {
                    $names[$id] = null;
                    try {
                        require_once __DIR__ . '/Shares.php';
                        $row = Capsule::table(Shares::TABLE)->where('domain', strtolower($domain))->where('member_client_id', $id)->first();
                        if ($row) {
                            $c = Capsule::table('tblclients')->where('id', $id)->first(['firstname', 'lastname', 'companyname']);
                            $n = $c ? trim(trim((string) ($c->firstname ?? '') . ' ' . (string) ($c->lastname ?? '')) ?: (string) ($c->companyname ?? '')) : '';
                            $names[$id] = $n !== '' ? mb_substr($n, 0, 80) : null;
                        }
                    } catch (\Throwable $e) {
                        $names[$id] = null;
                    }
                }
                if ($names[$id] !== null) {
                    $a['name'] = $names[$id];
                }
            }
            return $a;
        };
        if (isset($data['versions']) && is_array($data['versions'])) {
            foreach ($data['versions'] as $i => $v) {
                if (is_array($v) && array_key_exists('actor', $v)) {
                    $data['versions'][$i]['actor'] = $fix($v['actor']);
                }
            }
        } elseif (array_key_exists('actor', $data)) {
            $data['actor'] = $fix($data['actor']);
        }
        return $data;
    }

    /**
     * SPEC §23.5: account-level alerts of the logged-in client — /api/v1/accounts/{client id}/alerts[/sub-path] on the
     * controller of one of the client's OWN CDN services (`id`). The client id is the session's, never input; admins,
     * shared members (collaborators get no subscriptions in this wave) and reseller sub-sites have no account op.
     * Read-only team users may read (writes were refused by handle()).
     */
    private static function accountOp(string $sub, array $req, bool $admin, ?callable $clientFactory): array
    {
        $method = strtoupper((string) ($req['method'] ?? 'GET'));
        $cid = (int) ($req['client_id'] ?? 0);
        if ($admin || $cid <= 0 || array_key_exists('context', $req) || (int) ($req['reseller_site_id'] ?? 0) > 0) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $ok = false;
        foreach (self::ACCOUNT_ROUTES[$method] ?? [] as $re) {
            $ok = $ok || preg_match('#^' . $re . '$#D', $sub) === 1;
        }
        if (!$ok) {
            return self::fail(404, 'مسیر نامعتبر است.');
        }
        $id = (string) ($req['id'] ?? '');
        if (!preg_match('/^[1-9][0-9]{0,9}$/D', $id)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $svc = Capsule::table('tblhosting')->where('id', (int) $id)->first(['id', 'userid', 'packageid', 'server', 'domain', 'domainstatus']);
        if (!$svc || (int) $svc->userid !== $cid) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $product = Capsule::table('tblproducts')->where('id', (int) $svc->packageid)->first(['servertype']);
        if (!$product || $product->servertype !== 'pasargadcdn' || !in_array((string) $svc->domainstatus, ['Active', 'Suspended'], true)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $server = Capsule::table('tblservers')->where('id', (int) $svc->server)
            ->first(['type', 'hostname', 'ipaddress', 'secure', 'port', 'accesshash', 'password']);
        if (!$server || ($server->type ?? '') !== 'pasargadcdn') {
            return self::fail(502, 'سرور CDN برای این سرویس تنظیم نشده است.');
        }
        $body = null;
        if ($method === 'POST' || $method === 'PUT') {
            $raw = (string) ($req['body'] ?? '');
            if (strlen($raw) > self::MAX_BODY) {
                return self::fail(413, 'حجم درخواست بیش از حد مجاز است.');
            }
            $data = $raw === '' ? [] : json_decode($raw, true, 32);
            if (!is_array($data)) {
                return self::fail(400, 'بدنه درخواست باید JSON معتبر باشد.');
            }
            $data = self::alertBody($method, $sub, $data);
            if ($data === null) {
                return self::fail(400, 'پارامتر نامعتبر است.');
            }
            $body = json_encode($data === [] ? new \stdClass() : $data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        $target = '/api/v1/accounts/' . $cid . '/alerts' . ($sub === '' ? '' : '/' . $sub);
        self::releaseSession();
        try {
            $params = ['serverhostname' => $server->hostname, 'serverip' => $server->ipaddress, 'serversecure' => $server->secure,
                'serverport' => $server->port, 'serveraccesshash' => $server->accesshash,
                'serverpassword' => (trim((string) $server->accesshash) === '' && function_exists('decrypt')) ? decrypt($server->password) : ''];
            $api = $clientFactory ? $clientFactory($params) : ApiClient::fromParams($params, 20);
            if (method_exists($api, 'setActor')) {
                $api->setActor('client:' . $cid);
            }
            [$code, $data] = $api->raw($method, $target, $body);
        } catch (\Throwable $e) {
            self::log($method . ' ' . $target, $e->getMessage());
            return self::fail(502, 'اتصال به سرور CDN برقرار نشد.');
        }
        if ($code >= 500 || $code < 200 || ($code >= 300 && $code < 400)) {
            self::log($method . ' ' . $target, 'HTTP ' . $code);
            return self::fail(502, I18n::tr('خطای سرور CDN (HTTP %s)', $code));
        }
        if (!is_array($data)) {
            return $code < 300 ? [$code, ['ok' => true]] : self::fail($code, I18n::tr('درخواست توسط سرور CDN رد شد (HTTP %s)', $code));
        }
        if ($code >= 400 && isset($data['detail']) && is_string($data['detail'])) {
            $data['detail'] = I18n::controller($data['detail']);
        }
        return [$code, $data];
    }

    /** Cleaned body of an account alert write (§23.5), or null. */
    public static function alertBody(string $method, string $sub, array $d): ?array
    {
        if ($method === 'PUT') {   // subscriptions: full replace
            if (array_keys($d) !== ['items'] || !self::isList($d['items']) || count($d['items']) > 100) {
                return null;
            }
            $items = [];
            foreach ($d['items'] as $it) {
                if (!is_array($it) || array_diff(array_keys($it), ['id', 'site', 'events', 'channels', 'lang', 'quiet_hours', 'enabled'])) {
                    return null;
                }
                $x = [];
                if (isset($it['id'])) {
                    if (!is_int($it['id']) || $it['id'] <= 0) {
                        return null;
                    }
                    $x['id'] = $it['id'];
                }
                $site = $it['site'] ?? null;
                if ($site !== null && (!is_string($site) || !preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/D', $site))) {
                    return null;
                }
                $x['site'] = $site;
                $ev = $it['events'] ?? null;
                if (!self::isList($ev) || !$ev || count($ev) > 30) {
                    return null;
                }
                foreach ($ev as $e) {
                    if (!is_string($e) || !preg_match(self::ALERT_EVENT, $e)) {
                        return null;
                    }
                }
                $ch = $it['channels'] ?? null;
                if (!self::isList($ch) || !$ch || array_diff($ch, self::ALERT_CHANNELS) || count(array_unique($ch)) !== count($ch)) {
                    return null;
                }
                $x['events'] = array_values(array_unique($ev));
                $x['channels'] = array_values($ch);
                $x['lang'] = in_array($it['lang'] ?? 'fa', ['fa', 'en'], true) ? ($it['lang'] ?? 'fa') : null;
                if ($x['lang'] === null) {
                    return null;
                }
                $q = $it['quiet_hours'] ?? null;
                if ($q !== null) {
                    if (!is_array($q) || array_diff(array_keys($q), ['start', 'end', 'bypass_critical']) || !is_string($q['start'] ?? null) || !is_string($q['end'] ?? null)
                        || !preg_match(self::HHMM, $q['start']) || !preg_match(self::HHMM, $q['end']) || $q['start'] === $q['end']
                        || (array_key_exists('bypass_critical', $q) && !is_bool($q['bypass_critical']))) {
                        return null;
                    }
                    $q = ['start' => $q['start'], 'end' => $q['end'], 'bypass_critical' => $q['bypass_critical'] ?? true];
                }
                $x['quiet_hours'] = $q;
                if (array_key_exists('enabled', $it) && !is_bool($it['enabled'])) {
                    return null;
                }
                $x['enabled'] = $it['enabled'] ?? true;
                $items[] = $x;
            }
            return ['items' => $items];
        }
        if ($sub === 'targets/sms') {
            return array_keys($d) === ['phone'] && is_string($d['phone']) && preg_match('/^\+[1-9][0-9]{7,14}$/D', $d['phone']) ? ['phone' => $d['phone']] : null;
        }
        if (preg_match('#^targets/[1-9][0-9]{0,9}/verify$#D', $sub)) {
            return array_keys($d) === ['code'] && is_string($d['code']) && preg_match('/^[0-9]{6}$/D', $d['code']) ? ['code' => $d['code']] : null;
        }
        if (preg_match('#^targets/(?:bale|telegram)/link$#D', $sub)) {
            return $d === [] ? [] : null;
        }
        if ($sub === 'test') {
            if (array_diff(array_keys($d), ['channel', 'target_id']) || !in_array($d['channel'] ?? null, self::ALERT_CHANNELS, true)
                || (array_key_exists('target_id', $d) && (!is_int($d['target_id']) || $d['target_id'] <= 0))) {
                return null;
            }
            return $d;
        }
        return null;
    }

    /**
     * A public certificate file of the controller (SPEC §14.2: the CA that signs the platform's
     * origin-pull client certificate), returned as JSON {pem, filename, fingerprint_sha256} for
     * the client app to offer as a download. Only well-formed CERTIFICATE blocks pass — anything
     * else (an HTML error page, a key) is refused.
     */
    private static function pemFile($api, string $file): array
    {
        if (!method_exists($api, 'rawText')) {
            return self::fail(502, 'دریافت گواهی از سرور CDN ممکن نشد.');
        }
        [$code, $text] = $api->rawText('GET', $file, self::MAX_PEM);
        if ($code === 404) {
            return self::fail(404, 'سرور CDN هنوز گواهی CA اتصال مبدأ را منتشر نکرده است.');
        }
        if ($code !== 200 || !is_string($text)) {
            self::log('GET ' . $file, 'HTTP ' . $code);
            return self::fail(502, I18n::tr('دریافت گواهی از سرور CDN ممکن نشد (HTTP %s)', $code));
        }
        $pem = trim(str_replace("\r\n", "\n", $text)) . "\n";
        $block = '-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+\/=\s]+?)-----END CERTIFICATE-----';
        if (strlen($pem) > self::MAX_PEM || stripos($pem, 'PRIVATE KEY') !== false
            || !preg_match('/\A(?:' . $block . '\s*)+\z/', $pem) || !preg_match('/' . $block . '/', $pem, $m)) {
            self::log('GET ' . $file, 'unexpected body');
            return self::fail(502, 'پاسخ سرور CDN گواهی معتبری نبود.');
        }
        // SHA-256 of the first certificate (DER) so the customer can check the file they install.
        $der = base64_decode((string) preg_replace('/\s+/', '', $m[1]), true);
        $fp = $der === false || $der === '' ? null : implode(':', str_split(strtoupper(hash('sha256', $der)), 2));
        return [200, ['pem' => $pem, 'filename' => 'pasargadcdn-origin-pull-ca.pem', 'fingerprint_sha256' => $fp]];
    }

    const RESELLER_OPS = ['list', 'create', 'delete', 'report', 'brand', 'bulk', 'export'];
    // SPEC §19.2: `transfer` (POST) dismisses the one-time «این دامنه به حساب شما منتقل شد» notice
    // SPEC §20.2: `shares` — the owner page «اشتراک دامنه» (GET list; POST {action: invite|role|revoke})
    // SPEC §19.3: `xfer` — the owner page «انتقال دامنه» (GET state; POST {action: preview|create|cancel}), run by the addon
    const LOCAL_OPS = ['state', 'onboarding', 'report', 'transfer', 'shares', 'xfer'];

    /**
     * Growth local ops (WHMCS-side, per service): GET state → {onboarding, report}; POST onboarding
     * {done?, skipped?, dismissed?}; POST report {freq: off|weekly|monthly}. Admin mode has no local ops.
     */
    private static function localOp(string $op, array $req, bool $admin): array
    {
        require_once __DIR__ . '/ServiceState.php';
        $method = strtoupper((string) ($req['method'] ?? 'GET'));
        if ($admin || !in_array($op, self::LOCAL_OPS, true)) {
            return self::fail(404, 'عملیات نامعتبر است.');
        }
        $id = (string) ($req['id'] ?? '');
        if (!preg_match('/^[1-9][0-9]{0,9}$/D', $id)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $svc = Capsule::table('tblhosting')->where('id', (int) $id)->first(['id', 'userid', 'packageid', 'domainstatus', 'domain']);
        if (!$svc || (int) $svc->userid !== (int) ($req['client_id'] ?? 0)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $product = Capsule::table('tblproducts')->where('id', (int) $svc->packageid)->first(['servertype']);
        if (!$product || $product->servertype !== 'pasargadcdn') {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        $status = (string) $svc->domainstatus;
        if ($method === 'GET' ? !in_array($status, ['Active', 'Suspended'], true) : $status !== 'Active') {
            return self::fail(403, 'این سرویس فعال نیست.');
        }
        $sid = (int) $svc->id;
        if ($op === 'shares') {
            return self::sharesOp($method, $svc, $req);
        }
        if ($op === 'xfer') {
            return self::xferOp($method, $svc, $req);
        }
        if (!ServiceState::ensure()) {
            return self::fail(503, 'ذخیره تنظیمات ممکن نشد؛ دوباره تلاش کنید.');
        }
        if ($op === 'state' && $method === 'GET') {
            $r = ServiceState::report($sid);
            return [200, ['onboarding' => ServiceState::onboarding($sid), 'report' => ['freq' => $r['freq'], 'last' => ServiceState::lastReport($sid)]]];
        }
        if ($method !== 'POST') {
            return self::fail(405, 'متد مجاز نیست.');
        }
        $data = self::jsonBody($req);
        if ($data === null) {
            return self::fail(400, 'بدنه درخواست باید JSON معتبر باشد.');
        }
        if ($op === 'onboarding') {
            $patch = array_intersect_key($data, ['done' => 1, 'skipped' => 1, 'dismissed' => 1]);
            foreach (['done', 'skipped'] as $k) {
                if (array_key_exists($k, $patch) && !is_array($patch[$k])) {
                    return self::fail(400, 'پارامتر نامعتبر است.');
                }
            }
            $saved = ServiceState::saveOnboarding($sid, $patch);
            return $saved === null ? self::fail(503, 'ذخیره تنظیمات ممکن نشد؛ دوباره تلاش کنید.') : [200, ['onboarding' => $saved]];
        }
        if ($op === 'transfer') {
            require_once __DIR__ . '/Transfers.php';
            return Transfers::dismiss($sid, (int) ($req['client_id'] ?? 0)) ? [200, ['ok' => true]]
                : self::fail(503, 'ذخیره تنظیمات ممکن نشد؛ دوباره تلاش کنید.');
        }
        if ($op === 'report') {
            $freq = is_string($data['freq'] ?? null) ? $data['freq'] : '';
            if (!in_array($freq, ServiceState::FREQS, true)) {
                return self::fail(400, 'پارامتر نامعتبر است.');
            }
            $saved = ServiceState::setReport($sid, $freq);
            return $saved === null ? self::fail(503, 'ذخیره تنظیمات ممکن نشد؛ دوباره تلاش کنید.')
                : [200, ['report' => ['freq' => $saved['freq'], 'last' => ServiceState::lastReport($sid)]]];
        }
        return self::fail(405, 'متد مجاز نیست.');
    }

    /** Admin addon libraries needed by the customer transfer (SPEC §19.3); false when the addon is not installed. */
    public static function loadTransferLibs(): bool
    {
        require_once __DIR__ . '/Shares.php';
        require_once __DIR__ . '/Transfers.php';
        $lib = dirname(__DIR__, 3) . '/addons/pasargadcdn_admin/lib/';
        if (!is_file($lib . 'CustomerTransfer.php')) {
            return false;
        }
        foreach (['Env', 'View', 'Data', 'Pages', 'Operator', 'Transfer', 'CustomerTransfer'] as $f) {
            require_once $lib . $f . '.php';
        }
        return true;
    }

    /**
     * SPEC §19.3 owner page «انتقال دامنه»: ownership, CSRF and the service product were checked by localOp(); read-only team
     * users are refused even for reads (api.php marks lop=xfer); shared members never reach here (their proxy drops `lop`).
     * The request itself (recipient, limits, token, e-mails) lives in the admin addon (Admin\CustomerTransfer).
     */
    private static function xferOp(string $method, $svc, array $req): array
    {
        if (!empty($req['readonly'])) {
            return self::fail(403, self::READONLY_DETAIL);
        }
        if (!self::loadTransferLibs()) {
            return self::fail(404, 'انتقال دامنه توسط مشتری فعال نیست.');
        }
        return \PasargadCdn\Admin\CustomerTransfer::ownerOp($method, $svc, $req);
    }

    /**
     * SPEC §20.2 owner page: the service owner (or an owner-side team member with manage rights — read-only team users are
     * refused even for reads) lists, invites, re-roles and revokes members of THIS service's domain. Ownership was checked by
     * localOp(); every id is scoped to this service. Invite tokens leave only in the invite e-mail, or once in this answer
     * as a link when the invitee has no WHMCS account yet (the owner forwards it).
     */
    private static function sharesOp(string $method, $svc, array $req): array
    {
        require_once __DIR__ . '/Shares.php';
        if (!empty($req['readonly'])) {
            return self::fail(403, self::READONLY_DETAIL);
        }
        $domain = \pasargadcdn_domain(['domain' => (string) ($svc->domain ?? '')]);
        $owner = ['service_id' => (int) $svc->id, 'owner_client_id' => (int) $svc->userid, 'domain' => $domain];
        if (!Shares::ensure()) {
            return self::fail(503, 'ذخیره تنظیمات ممکن نشد؛ دوباره تلاش کنید.');
        }
        $list = function () use ($owner) {
            $cfg = Shares::settings();
            return ['members' => array_map([Shares::class, 'ownerView'], Shares::forOwner($owner)), 'roles' => self::SHARE_ROLES,
                'max_members' => $cfg['max_members']];
        };
        if ($method === 'GET') {
            return [200, $list()];
        }
        $data = self::jsonBody($req);
        $action = is_string($data['action'] ?? null) ? $data['action'] : '';
        if ($data === null || !in_array($action, ['invite', 'role', 'revoke'], true)) {
            return self::fail(400, 'پارامتر نامعتبر است.');
        }
        $who = 'client #' . (int) ($req['client_id'] ?? 0);
        if ($action === 'invite') {
            [$ok, $res] = Shares::invite($owner, is_string($data['email'] ?? null) ? $data['email'] : '', is_string($data['role'] ?? null) ? $data['role'] : '',
                'client:' . (int) $svc->userid);
            if (!$ok) {
                return [400, ['detail' => I18n::tr($res)]];
            }
            $row = $res['row'];
            $ownerName = Shares::ownerName($row);
            $mailed = Shares::mailInvite($row, $res['token'], $res['client'], $ownerName);
            Shares::log('#' . (int) $row->id . ' invite ' . $domain . ' (' . $row->role . ') to ' . $row->email . ' by ' . $who
                . ($res['client'] ? ' — existing client #' . (int) $res['client']->id . ($mailed ? ', e-mailed' : ', e-mail failed') : ' — no account yet'), (int) $svc->userid);
            return [201, $list() + ['invited' => Shares::ownerView($row), 'mailed' => $mailed,
                // no WHMCS account with that e-mail: the owner forwards the register-then-accept link
                'link' => $res['client'] ? null : Shares::inviteLink($res['token'])]];
        }
        $id = (int) ($data['id'] ?? 0);
        if ($action === 'role') {
            $role = is_string($data['role'] ?? null) ? $data['role'] : '';
            $row = Shares::setRole($id, $owner, $role);
            if (!$row) {
                return self::fail(404, 'عضو یا دعوت پیدا نشد.');
            }
            Shares::log('#' . $id . ' role of ' . $row->email . ' on ' . $domain . ' set to ' . $role . ' by ' . $who, (int) $svc->userid);
            return [200, $list()];
        }
        $row = Shares::revoke($id, $owner);
        if (!$row) {
            return self::fail(404, 'عضو یا دعوت پیدا نشد.');
        }
        Shares::log('#' . $id . ' (' . $row->email . ') revoked on ' . $domain . ' by ' . $who, (int) $svc->userid);
        return [200, $list()];
    }

    /**
     * Reseller-level operations for the logged-in client (already CSRF-checked). Every op
     * verifies the client is an enabled reseller and only ever touches its own rows.
     */
    private static function resellerOp(string $op, array $req, ?callable $clientFactory): array
    {
        require_once __DIR__ . '/Reseller.php';
        $method = strtoupper((string) ($req['method'] ?? 'GET'));
        $clientId = (int) ($req['client_id'] ?? 0);
        if (!in_array($op, self::RESELLER_OPS, true)) {
            return self::fail(404, 'عملیات نامعتبر است.');
        }
        if ($clientId <= 0 || !Reseller::isReseller($clientId)) {
            // Non-resellers get the same generic answer — the panel is simply absent for them.
            return self::fail(404, 'یافت نشد.');
        }
        // Reseller report / bulk / export fan out to several controller calls; drop the session lock first
        // (see releaseSession) so they never hold up a concurrent page load in the same browser session.
        self::releaseSession();
        $factory = $clientFactory ? function ($server) use ($clientFactory) {
            return $clientFactory([
                'serverhostname' => $server->hostname, 'serverip' => $server->ipaddress,
                'serversecure' => $server->secure, 'serverport' => $server->port,
                'serveraccesshash' => $server->accesshash,
                'serverpassword' => (trim((string) ($server->accesshash ?? '')) === '' && function_exists('decrypt'))
                    ? decrypt($server->password) : '',
            ]);
        } : null;

        if ($op === 'list' && $method === 'GET') {
            $sites = [];
            $held = array_flip(Reseller::heldIds($clientId));
            foreach (Reseller::sites($clientId) as $r) {
                $sites[] = ['id' => (int) $r->id, 'domain' => (string) $r->domain, 'label' => (string) $r->label,
                    'suspended' => (int) $r->suspended === 1, 'held' => isset($held[(int) $r->id])];
            }
            $cfg = Reseller::config($clientId);
            return [200, ['sites' => $sites, 'max_sites' => $cfg['max_sites'], 'count' => count($sites)]];
        }
        if ($op === 'report' && $method === 'GET') {
            return [200, Reseller::report($clientId, $factory)];
        }
        // Growth: white-label (GET / POST {name, logo?}), bulk pause/resume (POST {ids, action}), usage CSV (GET).
        if ($op === 'brand' && $method === 'GET') {
            return [200, ['brand' => Reseller::brand($clientId)]];
        }
        if ($op === 'brand' && $method === 'POST') {
            $data = self::jsonBody($req);
            if ($data === null || !is_string($data['name'] ?? '') || (array_key_exists('logo', $data) && !is_string($data['logo']) && $data['logo'] !== null)) {
                return self::fail(400, 'بدنه درخواست باید JSON معتبر باشد.');
            }
            [$ok, $res] = Reseller::saveBrand($clientId, (string) ($data['name'] ?? ''), array_key_exists('logo', $data) ? $data['logo'] : null);
            return $ok ? [200, ['brand' => $res]] : self::fail(400, is_string($res) ? $res : 'ذخیره برند ممکن نشد؛ دوباره تلاش کنید.');
        }
        if ($op === 'bulk' && $method === 'POST') {
            $data = self::jsonBody($req);
            $action = is_string($data['action'] ?? null) ? $data['action'] : '';
            if ($data === null || !is_array($data['ids'] ?? null) || !in_array($action, ['suspend', 'unsuspend'], true)) {
                return self::fail(400, 'پارامتر نامعتبر است.');
            }
            return [200, Reseller::bulk($clientId, $data['ids'], $action, $factory)];
        }
        if ($op === 'export' && $method === 'GET') {
            return [200, Reseller::exportCsv($clientId, $factory)];
        }
        if ($op === 'create' && $method === 'POST') {
            $data = self::jsonBody($req);
            if ($data === null) {
                return self::fail(400, 'بدنه درخواست باید JSON معتبر باشد.');
            }
            [$ok, $res] = Reseller::createSite($clientId, (string) ($data['domain'] ?? ''),
                (string) ($data['origin_ip'] ?? ''), (string) ($data['label'] ?? ''), $factory);
            return $ok ? [201, $res] : self::fail(400, is_string($res) ? $res : 'ساخت زیرسایت ناموفق بود.');
        }
        if ($op === 'delete' && $method === 'POST') {
            $data = self::jsonBody($req);
            $rsid = (int) ($data['id'] ?? 0);
            [$ok, $msg] = Reseller::deleteSite($clientId, $rsid, $factory);
            return $ok ? [200, ['ok' => true, 'detail' => I18n::tr($msg)]] : self::fail(404, $msg);
        }
        return self::fail(405, 'متد مجاز نیست.');
    }

    /** Decode and re-validate a JSON request body ([] for empty), or null when malformed/oversized. */
    private static function jsonBody(array $req): ?array
    {
        $raw = (string) ($req['body'] ?? '');
        if (strlen($raw) > self::MAX_BODY) {
            return null;
        }
        if ($raw === '') {
            return [];
        }
        $data = json_decode($raw, true, 64);
        return is_array($data) ? $data : null;
    }

    /**
     * Largest request body accepted for this call: MAX_BODY_FUNCTIONS for PUT config/functions (the
     * edge-functions section carries every function's code, SPEC §16.9), MAX_BODY for everything else.
     * The entry points (api.php, the admin addon) read at most maxBody() + 1 bytes.
     */
    public static function maxBody(string $method, string $path): int
    {
        return strtoupper($method) === 'PUT' && $path === 'config/functions' ? self::MAX_BODY_FUNCTIONS : self::MAX_BODY;
    }

    /**
     * SPEC §17.3: the only body POST waf/learning/apply may carry — {ids: [1..100 distinct proposal ids]}.
     * Returns the cleaned body (just `ids`, order kept) or null when anything else is in it.
     */
    public static function applyBody(array $data): ?array
    {
        $ids = $data['ids'] ?? null;
        if (array_diff(array_keys($data), ['ids']) || !is_array($ids) || !$ids || count($ids) > self::MAX_APPLY_IDS
            || array_keys($ids) !== range(0, count($ids) - 1)) {
            return null;
        }
        foreach ($ids as $id) {
            if (!is_string($id) || !preg_match(self::PROPOSAL_ID, $id)) {
                return null;
            }
        }
        return ['ids' => array_values(array_unique($ids))];
    }

    // ------------------------------------------------------------------ wave 10 (SPEC §18)

    /**
     * SPEC §18.3: the format a GET of a download sub-path asks for when it is a file (pdf / csv), else null
     * (json or no format: the normal JSON proxy). The format has already passed QUERY.
     */
    public static function downloadFormat(string $path, array $query): ?string
    {
        $fmt = is_string($query['format'] ?? null) ? $query['format'] : '';
        return isset(self::DOWNLOADS[$path][$fmt]) ? $fmt : null;
    }

    /**
     * Streams a controller file through the proxy: only a 200 whose type and signature match the format and
     * whose size is within DOWNLOADS' cap becomes a Download; a controller 4xx keeps its JSON detail (404 =
     * older controller, the app hides the page), anything else is a generic 502.
     */
    private static function download($api, string $target, string $path, string $fmt, string $domain, array $query): array
    {
        [$type, $ext, $max] = self::DOWNLOADS[$path][$fmt];
        if (!method_exists($api, 'download')) {
            return self::fail(502, 'دریافت فایل از سرور CDN ممکن نشد.');
        }
        [$code, $body, $ctype] = $api->download($target, $max, $fmt === 'pdf' ? 'application/pdf, application/json;q=0.5' : 'text/csv, application/json;q=0.5');
        if ($body === null) {
            self::log('GET ' . $target, 'download over ' . $max . ' bytes');
            return self::fail(502, 'فایل دریافتی از سرور CDN بیش از حد بزرگ است.');
        }
        if ($code >= 400 && $code < 500) {
            $data = json_decode((string) $body, true);
            if (is_array($data) && isset($data['detail'])) {
                if (is_string($data['detail'])) {
                    $data['detail'] = I18n::controller($data['detail']);
                }
                return [$code, ['detail' => $data['detail']]];
            }
            return self::fail($code, I18n::tr('درخواست توسط سرور CDN رد شد (HTTP %s)', $code));
        }
        if ($code !== 200) {
            self::log('GET ' . $target, 'HTTP ' . $code);
            return self::fail(502, I18n::tr('خطای سرور CDN (HTTP %s)', $code));
        }
        $ct = strtolower(trim(explode(';', $ctype)[0]));
        $ok = $fmt === 'pdf' ? ($ct === 'application/pdf' && strncmp((string) $body, '%PDF-', 5) === 0)
            : (in_array($ct, ['text/csv', 'application/csv', 'text/plain'], true) && !preg_match('/^(\xEF\xBB\xBF)?\s*</', (string) $body));
        if (!$ok) {
            self::log('GET ' . $target, 'unexpected download ' . $ct);
            return self::fail(502, 'فایل دریافتی از سرور CDN معتبر نبود.');
        }
        $safe = (string) preg_replace('/[^a-z0-9.-]/', '', strtolower($domain));
        if ($path === self::W10_STATEMENT) {
            $month = is_string($query['month'] ?? null) ? $query['month'] : gmdate('Y-m');
            $name = 'pasargadcdn-statement-' . $safe . '-' . $month;
        } else {
            $from = is_string($query['from'] ?? null) ? substr($query['from'], 0, 10) : '';
            $to = is_string($query['to'] ?? null) ? substr($query['to'], 0, 10) : '';
            $name = 'pasargadcdn-audit-' . $safe . ($from !== '' ? '-' . $from : '') . ($to !== '' ? '-' . $to : '');
        }
        return [200, new Download((string) $body, $type, $name . '.' . $ext)];
    }

    /**
     * `plan` (the service's WHMCS product name, ≤ 100 characters) and `block_gb` (the prepaid traffic block size,
     * prepaid billing only) for GET statement. Reseller sub-sites have no WHMCS product: nothing is added.
     */
    public static function statementExtras($svc): array
    {
        $out = [];
        try {
            if ($svc && isset($svc->packageid)) {
                $prod = Capsule::table('tblproducts')->where('id', (int) $svc->packageid)->first(['name']);
                $name = trim((string) ($prod->name ?? ''));
                if ($name !== '') {
                    $out['plan'] = function_exists('mb_substr') ? mb_substr($name, 0, 100, 'UTF-8') : substr($name, 0, 100);
                }
                if (function_exists('pasargadcdn_billing_mode') && \pasargadcdn_billing_mode() === 'prepaid') {
                    $gb = (int) (\pasargadcdn_addon_settings()['block_gb'] ?? 10);
                    $out['block_gb'] = $gb > 0 ? $gb : 10;
                }
            }
        } catch (\Throwable $e) {
            return $out;
        }
        return $out;
    }

    /** A loc-tagged validation item in the controller's 422 list shape (the app places it next to the field). */
    private static function bad(array $loc, string $msg, ...$args): array
    {
        return ['loc' => array_merge(['body'], $loc), 'msg' => I18n::tr($msg, ...$args)];
    }

    private static function isInt($v, int $lo, int $hi): bool
    {
        return is_int($v) && $v >= $lo && $v <= $hi;
    }

    /** A JSON list (0..n-1 keys). */
    private static function isList($v): bool
    {
        return is_array($v) && ($v === [] || array_keys($v) === range(0, count($v) - 1));
    }

    /** URL path prefix as sections._prefixes accepts it: /…, PATH_PATTERN_RE characters, no * or ?, never /__pcdn. */
    public static function pathPrefix($p): bool
    {
        if (!is_string($p) || strlen($p) > 256 || !preg_match('#^/[A-Za-z0-9\-._~%!$&\'()+,;=:@/]*$#D', $p)) {
            return false;
        }
        return !($p === '/__pcdn' || strncmp($p, '/__pcdn/', 8) === 0 || strncmp($p, '/__pcdn_', 8) === 0);
    }

    /** IP or CIDR as sections._cidrs_list accepts it (networks no wider than /8 for IPv4, /16 for IPv6). */
    public static function cidr($v): bool
    {
        if (!is_string($v) || strlen($v) > 50 || !preg_match('#^([0-9A-Fa-f:.]+)(?:/([0-9]{1,3}))?$#D', trim($v), $m)) {
            return false;
        }
        $v4 = filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $v6 = !$v4 && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        if (!$v4 && !$v6) {
            return false;
        }
        if (!isset($m[2]) || $m[2] === '') {
            return true;
        }
        $len = (int) $m[2];
        return $v4 ? $len >= 8 && $len <= 32 : $len >= 16 && $len <= 128;
    }

    /** Plain text of an edge page: ≤ $max characters, no control characters except newline / tab. */
    private static function plainText($v, int $max): bool
    {
        if (!is_string($v)) {
            return false;
        }
        $len = function_exists('mb_strlen') ? mb_strlen($v, 'UTF-8') : strlen($v);
        return $len <= $max && preg_match('//u', $v) && !preg_match('/[\x00-\x08\x0B-\x1F\x7F]/', $v);
    }

    /** Checks a list of $what (prefix | cidr) under $loc with at most $max items; appends problems. */
    private static function listOf(array &$out, array $loc, $v, int $max, string $what, int $min = 0): void
    {
        if (!self::isList($v)) {
            $out[] = self::bad($loc, 'باید فهرست باشد.');
            return;
        }
        if (count($v) > $max) {
            $out[] = self::bad($loc, 'حداکثر %s مورد مجاز است.', $max);
            return;
        }
        if (count($v) < $min) {
            $out[] = self::bad($loc, 'دست‌کم یک مسیر لازم است.');
            return;
        }
        foreach ($v as $i => $x) {
            if ($what === 'prefix' && !self::pathPrefix($x)) {
                $out[] = self::bad(array_merge($loc, [$i]), 'پیشوند مسیر باید با / شروع شود، بدون * و ? باشد و حداکثر ۲۵۶ نویسه؛ مسیرهای /__pcdn/ رزرو شده‌اند.');
            } elseif ($what === 'cidr' && !self::cidr($x)) {
                $out[] = self::bad(array_merge($loc, [$i]), 'آدرس IP یا شبکهٔ نامعتبر است (شبکه حداکثر /8 برای IPv4 و /16 برای IPv6).');
            } elseif ($what === 'email' && !(is_string($x) && strlen($x) <= 254
                    && preg_match('/^([a-z0-9.!#$%&\'*+\/=?^_`{|}~-]{1,64})?@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/iD', $x))) {
                $out[] = self::bad(array_merge($loc, [$i]), 'ایمیل یا @دامنهٔ نامعتبر است (مثل a@b.com یا @company.com).');
            }
        }
    }

    /** Unknown keys of an object under $loc. */
    private static function keys(array &$out, array $loc, array $v, array $allowed): void
    {
        foreach (array_keys($v) as $k) {
            if (!in_array($k, $allowed, true)) {
                $out[] = self::bad(array_merge($loc, [(string) $k]), 'فیلد ناشناخته است.');
            }
        }
    }

    /**
     * SPEC §18.1 section `waiting_room` as WHMCS forwards it: exactly the contract's keys and types (the
     * controller re-validates everything). Returns the 422 items ([] = fine).
     */
    public static function waitingRoomProblems(array $d): array
    {
        $out = [];
        self::keys($out, [], $d, ['enabled', 'mode', 'paths', 'max_active', 'session_minutes', 'queue_page', 'bypass']);
        if (array_key_exists('enabled', $d) && !is_bool($d['enabled'])) {
            $out[] = self::bad(['enabled'], 'باید روشن یا خاموش باشد.');
        }
        if (array_key_exists('mode', $d) && !in_array($d['mode'], ['queue', 'off'], true)) {
            $out[] = self::bad(['mode'], 'مقدار نامعتبر است.');
        }
        if (array_key_exists('paths', $d)) {
            self::listOf($out, ['paths'], $d['paths'], 20, 'prefix', 1);
        }
        if (array_key_exists('max_active', $d) && !self::isInt($d['max_active'], 1, 1000000)) {
            $out[] = self::bad(['max_active'], 'باید عدد صحیح بین %s و %s باشد.', 1, 1000000);
        }
        if (array_key_exists('session_minutes', $d) && !self::isInt($d['session_minutes'], 1, 120)) {
            $out[] = self::bad(['session_minutes'], 'باید عدد صحیح بین %s و %s باشد.', 1, 120);
        }
        if (array_key_exists('queue_page', $d)) {
            $q = $d['queue_page'];
            if (!is_array($q) || (self::isList($q) && $q !== [])) {
                $out[] = self::bad(['queue_page'], 'مقدار نامعتبر است.');
            } else {
                self::keys($out, ['queue_page'], $q, ['title_fa', 'title_en', 'message_fa', 'message_en']);
                foreach (['title_fa', 'title_en', 'message_fa', 'message_en'] as $k) {
                    if (array_key_exists($k, $q) && !self::plainText($q[$k], 500)) {
                        $out[] = self::bad(['queue_page', $k], 'متن حداکثر ۵۰۰ نویسه و بدون نویسهٔ کنترلی باشد.');
                    }
                }
            }
        }
        if (array_key_exists('bypass', $d)) {
            $b = $d['bypass'];
            if (!is_array($b) || (self::isList($b) && $b !== [])) {
                $out[] = self::bad(['bypass'], 'مقدار نامعتبر است.');
            } else {
                self::keys($out, ['bypass'], $b, ['verified_bots', 'paths', 'ips']);
                if (array_key_exists('verified_bots', $b) && !is_bool($b['verified_bots'])) {
                    $out[] = self::bad(['bypass', 'verified_bots'], 'باید روشن یا خاموش باشد.');
                }
                if (array_key_exists('paths', $b)) {
                    self::listOf($out, ['bypass', 'paths'], $b['paths'], 20, 'prefix');
                }
                if (array_key_exists('ips', $b)) {
                    self::listOf($out, ['bypass', 'ips'], $b['ips'], 50, 'cidr');
                }
            }
        }
        return $out;
    }

    /** SPEC §18.2 section `access` as WHMCS forwards it (≤ 20 apps; keys, types and limits of the contract). */
    public static function accessProblems(array $d): array
    {
        $out = [];
        self::keys($out, [], $d, ['enabled', 'apps']);
        if (array_key_exists('enabled', $d) && !is_bool($d['enabled'])) {
            $out[] = self::bad(['enabled'], 'باید روشن یا خاموش باشد.');
        }
        if (!array_key_exists('apps', $d)) {
            return $out;
        }
        if (!self::isList($d['apps'])) {
            return array_merge($out, [self::bad(['apps'], 'باید فهرست باشد.')]);
        }
        if (count($d['apps']) > 20) {
            return array_merge($out, [self::bad(['apps'], 'حداکثر %s مورد مجاز است.', 20)]);
        }
        $ids = [];
        foreach ($d['apps'] as $i => $a) {
            $loc = ['apps', $i];
            if (!is_array($a) || (self::isList($a) && $a !== [])) {
                $out[] = self::bad($loc, 'مقدار نامعتبر است.');
                continue;
            }
            self::keys($out, $loc, $a, ['id', 'name', 'paths', 'methods', 'emails', 'ips', 'session_hours']);
            $id = $a['id'] ?? null;
            if (!is_string($id) || !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/D', $id)) {
                $out[] = self::bad(array_merge($loc, ['id']), 'شناسهٔ برنامه فقط حروف کوچک انگلیسی، عدد و - باشد (حداکثر ۳۲ نویسه).');
            } elseif (isset($ids[$id])) {
                $out[] = self::bad(array_merge($loc, ['id']), 'شناسهٔ برنامه‌ها باید یکتا باشد.');
            } else {
                $ids[$id] = true;
            }
            $name = $a['name'] ?? null;
            if (!self::plainText($name, 100) || trim((string) $name) === '' || strpos((string) $name, "\n") !== false) {
                $out[] = self::bad(array_merge($loc, ['name']), 'نام برنامه لازم است (حداکثر ۱۰۰ نویسه، یک خط).');
            }
            self::listOf($out, array_merge($loc, ['paths']), $a['paths'] ?? null, 20, 'prefix', 1);
            if (array_key_exists('methods', $a) && !in_array($a['methods'], ['otp', 'ip', 'otp_or_ip'], true)) {
                $out[] = self::bad(array_merge($loc, ['methods']), 'مقدار نامعتبر است.');
            }
            if (array_key_exists('emails', $a)) {
                self::listOf($out, array_merge($loc, ['emails']), $a['emails'], 200, 'email');
            }
            if (array_key_exists('ips', $a)) {
                self::listOf($out, array_merge($loc, ['ips']), $a['ips'], 100, 'cidr');
            }
            if (array_key_exists('session_hours', $a) && !self::isInt($a['session_hours'], 1, 720)) {
                $out[] = self::bad(array_merge($loc, ['session_hours']), 'باید عدد صحیح بین %s و %s باشد.', 1, 720);
            }
        }
        return $out;
    }

    /**
     * SPEC §18.4: a JavaScript error report of the client app (api.php `action=client-error`, POST, CSRF-checked).
     * At most CLIENT_ERROR_RATE per CLIENT_ERROR_WINDOW seconds per session ($session is the PHP session, by
     * reference), payload sanitized (sanitizeClientError), written to the WHMCS module log and forwarded to the
     * controller's POST /api/v1/client-errors with the service's server key (best effort, 3 s). The customer
     * always gets 202 unless refused (401 / 403 / 405 / 400 / 429).
     */
    public static function clientError(array $req, array &$session, ?callable $clientFactory = null): array
    {
        $adminId = (int) ($req['admin_id'] ?? 0);
        I18n::$current = $adminId <= 0 && ($req['lang'] ?? '') === 'en' ? 'en' : 'fa';
        if (strtoupper((string) ($req['method'] ?? 'GET')) !== 'POST') {
            return self::fail(405, 'متد مجاز نیست.');
        }
        if ($adminId <= 0 && (int) ($req['client_id'] ?? 0) <= 0) {
            return self::fail(401, 'لطفاً دوباره وارد حساب کاربری شوید.');
        }
        $tok = (string) ($req['session_csrf'] ?? '');
        if ($tok === '' || !hash_equals($tok, (string) ($req['csrf'] ?? ''))) {
            return self::fail(403, 'درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.');
        }
        $now = (int) ($req['now'] ?? time());
        $times = array_values(array_filter(is_array($session['pasargadcdn_client_errors'] ?? null) ? $session['pasargadcdn_client_errors'] : [],
            function ($t) use ($now) {
                return is_int($t) && $t > $now - self::CLIENT_ERROR_WINDOW && $t <= $now;
            }));
        if (count($times) >= self::CLIENT_ERROR_RATE) {
            $session['pasargadcdn_client_errors'] = $times;
            return self::fail(429, 'گزارش خطا بیش از حد مجاز است؛ کمی بعد دوباره تلاش کنید.');
        }
        $times[] = $now;
        $session['pasargadcdn_client_errors'] = $times;
        $raw = (string) ($req['body'] ?? '');
        $data = strlen($raw) > self::CLIENT_ERROR_MAX_BODY ? null : json_decode($raw, true, 8);
        if (!is_array($data)) {
            return self::fail(400, 'بدنه درخواست باید JSON معتبر باشد.');
        }
        $report = self::sanitizeClientError($data);
        if (function_exists('logModuleCall')) {
            logModuleCall('pasargadcdn', 'client-error', json_encode($report, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), '');
        }
        $forwarded = false;
        $server = self::errorServer($req, $adminId > 0);
        if ($server) {
            try {
                $params = ['serverhostname' => $server->hostname, 'serverip' => $server->ipaddress, 'serversecure' => $server->secure,
                    'serverport' => $server->port, 'serveraccesshash' => $server->accesshash,
                    'serverpassword' => (trim((string) $server->accesshash) === '' && function_exists('decrypt')) ? decrypt($server->password) : ''];
                $api = $clientFactory ? $clientFactory($params) : ApiClient::fromParams($params, 3);
                [$code] = $api->raw('POST', self::W10_CLIENT_ERRORS, json_encode($report, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                $forwarded = $code >= 200 && $code < 300;
            } catch (\Throwable $e) {
                self::log('POST ' . self::W10_CLIENT_ERRORS, $e->getMessage());
            }
        }
        return [202, ['ok' => true, 'forwarded' => $forwarded]];
    }

    /** The controller a report goes to: the server of the (owned) service the app runs for, else none. */
    private static function errorServer(array $req, bool $admin)
    {
        try {
            $rsid = (int) ($req['reseller_site_id'] ?? 0);
            if ($rsid > 0 && !$admin) {
                require_once __DIR__ . '/Reseller.php';
                return Reseller::ownedSite((int) ($req['client_id'] ?? 0), $rsid) ? Reseller::server() : null;
            }
            $id = (string) ($req['id'] ?? '');
            if (!preg_match('/^[1-9][0-9]{0,9}$/D', $id)) {
                return null;
            }
            $svc = Capsule::table('tblhosting')->where('id', (int) $id)->first(['id', 'userid', 'server']);
            if (!$svc || (!$admin && (int) $svc->userid !== (int) ($req['client_id'] ?? 0))) {
                return null;
            }
            $server = Capsule::table('tblservers')->where('id', (int) $svc->server)
                ->first(['type', 'hostname', 'ipaddress', 'secure', 'port', 'accesshash', 'password']);
            return $server && ($server->type ?? '') === 'pasargadcdn' ? $server : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** Masks personal data and secrets in free text: e-mails, IPv4 addresses, key=value secrets, long tokens. */
    public static function scrub(string $s): string
    {
        $s = (string) preg_replace('/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/', '[email]', $s);
        $s = (string) preg_replace('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', '[ip]', $s);
        $s = (string) preg_replace('/\b((?:api[_-]?)?key|token|secret|password|passwd|auth|session|csrf)(["\']?\s*[=:]\s*["\']?)[^\s"\'&,;)]+/i', '$1$2[redacted]', $s);
        return (string) preg_replace('/\b[A-Za-z0-9_\-]{32,}\b/', '[redacted]', $s);
    }

    /** URLs inside a text reduced to their path: no scheme / host, no query string, no fragment. */
    public static function stripUrls(string $s): string
    {
        $s = (string) preg_replace('#[a-z][a-z0-9+.-]*://[^/\s)]*#i', '', $s);
        return (string) preg_replace('/[?#][^\s):]*/', '', $s);
    }

    private static function clip(string $s, int $max): string
    {
        $s = (string) preg_replace('/[\x00-\x08\x0B-\x1F\x7F]/', '', $s);
        if (!preg_match('//u', $s)) {
            $s = function_exists('mb_convert_encoding') ? (string) mb_convert_encoding($s, 'UTF-8', 'UTF-8') : '';
        }
        if (strlen($s) <= $max) {
            return $s;
        }
        $cut = substr($s, 0, $max);
        // never end inside a multi-byte character
        return function_exists('mb_strcut') ? mb_strcut($s, 0, $max, 'UTF-8') : (string) preg_replace('/[\x80-\xBF]*[\xC0-\xFF]?$/', '', $cut);
    }

    /**
     * SPEC §18.4 report shape {message, source (path only), line, col, stack (≤ 4 KB, query strings stripped),
     * page, ua}: every field typed, clipped and scrubbed; unknown fields dropped.
     */
    public static function sanitizeClientError(array $d): array
    {
        $str = function ($k) use ($d) {
            return is_string($d[$k] ?? null) ? $d[$k] : '';
        };
        $int = function ($k) use ($d) {
            $v = $d[$k] ?? 0;
            return is_int($v) && $v >= 0 && $v <= 10000000 ? $v : 0;
        };
        $src = $str('source');
        $path = (string) (parse_url($src, PHP_URL_PATH) ?? '');
        if ($path === '' || $path[0] !== '/') {
            $path = '';
        }
        $page = $str('page');
        return [
            'message' => self::clip(self::scrub(self::stripUrls($str('message'))), 1000),
            'source' => self::clip(self::scrub($path), 300),
            'line' => $int('line'),
            'col' => $int('col'),
            'stack' => self::clip(self::scrub(self::stripUrls($str('stack'))), self::CLIENT_ERROR_STACK),
            'page' => preg_match('/^[a-z0-9_-]{1,40}$/D', $page) ? $page : 'unknown',
            'ua' => self::clip($str('ua'), 300),
        ];
    }

    public static function allowed(string $method, string $path): bool
    {
        foreach (self::ROUTES[$method] ?? [] as $re) {
            if (preg_match('#^' . $re . '$#D', $path)) {
                return true;
            }
        }
        return false;
    }

    /** Whitelisted query string for $path ('' when none), or null when a value is invalid. */
    private static function query(string $path, array $in): ?string
    {
        $out = [];
        $rules = self::QUERY[$path] ?? null;
        if ($rules === null) {
            $rules = [];
            foreach (self::QUERY_RE as $pre => $r) {
                if (preg_match('#^' . $pre . '$#D', $path)) {
                    $rules = $r;
                    break;
                }
            }
        }
        foreach ($rules as $key => $re) {
            if (!isset($in[$key])) {
                continue;
            }
            if (!is_string($in[$key]) || !preg_match($re, $in[$key])) {
                return null;
            }
            $out[$key] = $in[$key];
        }
        return $out ? '?' . http_build_query($out) : '';
    }

    /** Error answer; a known Persian message is sent in the request's language (I18n::$current). */
    private static function fail(int $code, string $detail): array
    {
        return [$code, ['detail' => I18n::tr($detail)]];
    }

    private static function adminLog(int $adminId, string $method, string $path, $svc, string $result, string $user = ''): void
    {
        if (function_exists('logActivity')) {
            // Path and service facts only — request bodies (certificates, keys) are never logged. The admin's
            // username (addon: tbladmins) is added when known; an operator site (SPEC §19.1) has no service.
            $user = (string) preg_replace('/[^\p{L}\p{N}._@ -]/u', '', $user);
            $on = (int) $svc->id > 0 ? sprintf('service #%d (%s)', (int) $svc->id, (string) $svc->domain)
                : sprintf('operator site %s', (string) $svc->domain);
            logActivity(sprintf('Pasargad CDN [admin #%d%s, full management]: %s %s on %s — %s',
                $adminId, $user !== '' ? ' ' . $user : '', $method, $path === '' ? '/' : $path, $on, $result), (int) $svc->userid);
        }
    }

    /** The shared-member context of a request, or null. */
    private static function shareCtx(array $req): ?array
    {
        $c = $req['context'] ?? null;
        return is_array($c) && ($c['kind'] ?? '') === 'shared' ? $c : null;
    }

    /** `share:<member client id>:<role>` (SPEC §20.3). */
    public static function actor(array $req): string
    {
        $c = self::shareCtx($req);
        return $c ? 'share:' . (int) ($req['client_id'] ?? 0) . ':' . (string) ($c['role'] ?? '') : '';
    }

    /** A member's write: WHMCS activity log (owner's client log) + module log, path and facts only — never a body. */
    private static function shareLog(array $req, string $method, string $path, $svc, string $result): void
    {
        $c = self::shareCtx($req);
        $line = sprintf('Pasargad CDN [%s]: %s %s on shared site %s (share #%d%s) — %s', self::actor($req), $method, $path === '' ? '/' : $path,
            (string) $svc->domain, (int) ($c['share_id'] ?? 0), (int) $svc->id > 0 ? ', service #' . (int) $svc->id : ', operator site', $result);
        if (function_exists('logActivity')) {
            logActivity($line, (int) $svc->userid);
        }
        if (function_exists('logModuleCall')) {
            logModuleCall('pasargadcdn', 'share ' . $method . ' ' . ($path === '' ? '/' : $path), self::actor($req), $result);
        }
    }

    private static function log(string $action, string $error): void
    {
        if (function_exists('logModuleCall')) {
            logModuleCall('pasargadcdn', 'clientapi ' . $action, '', $error);
        }
    }
}
