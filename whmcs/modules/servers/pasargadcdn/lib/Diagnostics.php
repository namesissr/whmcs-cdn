<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

require_once __DIR__ . '/I18n.php';
require_once __DIR__ . '/ApiClient.php';

if (class_exists(__NAMESPACE__ . '\\Diagnostics', false)) {
    return;
}

/**
 * SPEC §23.8 — «ارسال گزارش عیب‌یابی به پشتیبانی»: the client app's local op `diag` (api.php?lop=diag&id=<service>).
 *
 *   GET  → fetches GET /api/v1/sites/{d}/diagnostics (customer audience — the admin audience is never asked for here) and
 *          keeps the report server-side in the PHP session ($_SESSION['pcdn_diag'][report_id], 30 minutes, ≤ 3 per session),
 *          bound to the service, so what is sent is exactly what the customer saw. Answers the report, the Markdown message
 *          that will be sent (in the app's language), the support department and the client's own active tickets.
 *   POST {report_id, note?, mode: new|reply, ticket_id?} → localAPI OpenTicket (department from the addon setting
 *          `support_department`, else the first department) or AddTicketReply on one of the client's OWN open tickets (checked
 *          with GetTicket before replying). The JSON report goes as `pcdn-diagnostics-<id>.json` through `attachments` when the
 *          installed version supports it, else in a fenced block. A report is sent once; a tampered / expired id is refused.
 *
 * Login, CSRF, read-only team users (no POST) and service ownership are checked here exactly like the other local ops. The
 * report never contains secrets, node names or node addresses (controller contract); the message adds nothing else but the
 * customer's own note. Customer-facing text never names the billing software.
 */
final class Diagnostics
{
    const TTL = 1800;
    const MAX_REPORTS = 3;
    const MAX_NOTE = 2000;
    const MAX_JSON = 65536;
    const ID_RE = '/^dg_[0-9a-f]{12}$/D';
    /** First installed version whose OpenTicket / AddTicketReply take `attachments` (base64 JSON [{name, data}]). */
    const ATTACH_SINCE = '7.10.0';

    /** @var callable|null tests: fn(): int */
    public static $clock = null;

    private static function now(): int
    {
        return self::$clock ? (int) (self::$clock)() : time();
    }

    private static function fail(int $code, string $msg): array
    {
        return [$code, ['detail' => I18n::tr($msg)]];
    }

    /**
     * @param array $req ['method', 'id', 'body', 'csrf', 'session_csrf', 'client_id', 'readonly', 'lang']
     * @param array $session the PHP session (by reference — the report lives there)
     */
    public static function handle(array $req, array &$session, ?callable $clientFactory = null): array
    {
        $method = strtoupper((string) ($req['method'] ?? 'GET'));
        I18n::$current = ($req['lang'] ?? '') === 'en' ? 'en' : 'fa';
        $cid = (int) ($req['client_id'] ?? 0);
        if ($cid <= 0) {
            return self::fail(401, 'لطفاً دوباره وارد حساب کاربری شوید.');
        }
        $tok = (string) ($req['session_csrf'] ?? '');
        if ($tok === '' || !hash_equals($tok, (string) ($req['csrf'] ?? ''))) {
            return self::fail(403, 'درخواست نامعتبر است، صفحه را دوباره بارگذاری کنید.');
        }
        if ($method !== 'GET' && $method !== 'POST') {
            return self::fail(405, 'متد مجاز نیست.');
        }
        if ($method === 'POST' && !empty($req['readonly'])) {
            return [403, ['detail' => I18n::tr(ClientApi::READONLY_DETAIL)]];
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
        $domain = \pasargadcdn_domain(['domain' => (string) $svc->domain]);
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/D', $domain)) {
            return self::fail(404, 'سرویس یافت نشد.');
        }
        self::prune($session);
        if ($method === 'GET') {
            return self::fetch($svc, $domain, $cid, $session, $clientFactory);
        }
        return self::send($svc, $domain, $cid, (string) ($req['body'] ?? ''), $session);
    }

    /** Drops expired reports and keeps at most MAX_REPORTS (newest). */
    private static function prune(array &$session): void
    {
        $list = is_array($session['pcdn_diag'] ?? null) ? $session['pcdn_diag'] : [];
        $now = self::now();
        $list = array_filter($list, function ($x) use ($now) {
            return is_array($x) && $now - (int) ($x['at'] ?? 0) <= self::TTL;
        });
        uasort($list, function ($a, $b) {
            return (int) $b['at'] <=> (int) $a['at'];
        });
        $session['pcdn_diag'] = array_slice($list, 0, self::MAX_REPORTS, true);
    }

    private static function fetch($svc, string $domain, int $cid, array &$session, ?callable $clientFactory): array
    {
        $server = Capsule::table('tblservers')->where('id', (int) $svc->server)
            ->first(['type', 'hostname', 'ipaddress', 'secure', 'port', 'accesshash', 'password']);
        if (!$server || ($server->type ?? '') !== 'pasargadcdn') {
            return self::fail(502, 'سرور CDN برای این سرویس تنظیم نشده است.');
        }
        try {
            $params = ['serverhostname' => $server->hostname, 'serverip' => $server->ipaddress, 'serversecure' => $server->secure,
                'serverport' => $server->port, 'serveraccesshash' => $server->accesshash,
                'serverpassword' => (trim((string) $server->accesshash) === '' && function_exists('decrypt')) ? decrypt($server->password) : ''];
            $api = $clientFactory ? $clientFactory($params) : ApiClient::fromParams($params, 20);
            // the customer audience only (no query): the admin audience is the addon's, with the admin key
            [$code, $data] = $api->raw('GET', ApiClient::site($domain) . '/diagnostics');
        } catch (\Throwable $e) {
            return self::fail(502, 'اتصال به سرور CDN برقرار نشد.');
        }
        if ($code === 404) {
            return self::fail(404, 'گزارش عیب‌یابی روی این سرور فعال نیست.');
        }
        if ($code === 429) {
            return self::fail(429, 'تعداد گزارش‌های عیب‌یابی این ساعت به سقف رسیده است؛ کمی بعد دوباره تلاش کنید.');
        }
        if ($code < 200 || $code >= 300 || !is_array($data)) {
            return self::fail(502, I18n::tr('خطای سرور CDN (HTTP %s)', $code));
        }
        unset($data['internal']);   // defence in depth: the customer audience never carries it
        $rid = is_string($data['report_id'] ?? null) ? $data['report_id'] : '';
        $json = (string) json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (!preg_match(self::ID_RE, $rid) || strlen($json) > self::MAX_JSON) {
            return self::fail(502, 'پاسخ سرور CDN گزارش معتبری نبود.');
        }
        $session['pcdn_diag'][$rid] = ['sid' => (int) $svc->id, 'domain' => $domain, 'at' => self::now(), 'report' => $data];
        self::prune($session);
        $lang = I18n::$current;
        return [200, ['report' => $data, 'markdown' => self::markdown($data, $lang), 'department' => self::department(),
            'tickets' => self::tickets($cid), 'note_max' => self::MAX_NOTE, 'expires_in' => self::TTL,
            'subject' => self::subject($domain, $lang)]];
    }

    private static function send($svc, string $domain, int $cid, string $raw, array &$session): array
    {
        $d = $raw === '' ? null : json_decode($raw, true, 8);
        if (!is_array($d) || array_diff(array_keys($d), ['report_id', 'note', 'mode', 'ticket_id'])) {
            return self::fail(400, 'پارامتر نامعتبر است.');
        }
        $rid = is_string($d['report_id'] ?? null) ? $d['report_id'] : '';
        $entry = preg_match(self::ID_RE, $rid) ? ($session['pcdn_diag'][$rid] ?? null) : null;
        // the report must be one this session fetched for THIS service, still fresh — anything else is refused
        if (!is_array($entry) || (int) ($entry['sid'] ?? 0) !== (int) $svc->id || self::now() - (int) ($entry['at'] ?? 0) > self::TTL) {
            return self::fail(404, 'این گزارش منقضی شده یا معتبر نیست؛ گزارش را دوباره بگیرید.');
        }
        $note = $d['note'] ?? '';
        if (!is_string($note) || mb_strlen($note) > self::MAX_NOTE) {
            return self::fail(400, 'توضیح شما حداکثر ۲۰۰۰ نویسه است.');
        }
        $note = trim((string) preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/u', '', $note));
        $mode = $d['mode'] ?? 'new';
        if (!in_array($mode, ['new', 'reply'], true)) {
            return self::fail(400, 'پارامتر نامعتبر است.');
        }
        if (!function_exists('localAPI')) {
            return self::fail(503, 'ثبت تیکت در حال حاضر ممکن نیست؛ دوباره تلاش کنید.');
        }
        $report = $entry['report'];
        $lang = I18n::$current;
        $file = 'pcdn-diagnostics-' . $rid . '.json';
        $json = (string) json_encode($report, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        $attach = self::attachmentsSupported();
        $msg = self::markdown($report, $lang);
        if ($note !== '') {
            $msg .= "\n\n### " . self::L['note'][$lang === 'en' ? 1 : 0] . "\n\n" . self::esc($note);
        }
        if (!$attach) {
            $msg .= "\n\n" . self::L['json'][$lang === 'en' ? 1 : 0] . ' (`' . $file . "`):\n\n```json\n" . $json . "\n```";
        }
        $extra = $attach ? ['attachments' => base64_encode((string) json_encode([['name' => $file, 'data' => base64_encode($json)]]))] : [];
        if ($mode === 'reply') {
            $tid = $d['ticket_id'] ?? null;
            if (!is_int($tid) || $tid <= 0) {
                return self::fail(400, 'پارامتر نامعتبر است.');
            }
            // ownership: only one of the client's own tickets that is still open
            $t = localAPI('GetTicket', ['ticketid' => $tid]);
            if (($t['result'] ?? '') !== 'success' || (int) ($t['userid'] ?? 0) !== $cid || strcasecmp((string) ($t['status'] ?? ''), 'Closed') === 0) {
                return self::fail(404, 'تیکت یافت نشد.');
            }
            $r = localAPI('AddTicketReply', ['ticketid' => $tid, 'clientid' => $cid, 'message' => $msg, 'markdown' => true] + $extra);
            if (($r['result'] ?? '') !== 'success') {
                self::log($cid, 'diagnostics report ' . $rid . ' could not be added to ticket #' . $tid . ': ' . (string) ($r['message'] ?? ''));
                return self::fail(502, 'افزودن گزارش به تیکت ممکن نشد؛ دوباره تلاش کنید.');
            }
            unset($session['pcdn_diag'][$rid]);
            self::log($cid, 'diagnostics report ' . $rid . ' of ' . $domain . ' added to ticket #' . (string) ($t['tid'] ?? $tid) . ' (service #' . (int) $svc->id . ')');
            return [200, ['ok' => true, 'mode' => 'reply', 'ticket' => ['id' => $tid, 'tid' => (string) ($t['tid'] ?? '')], 'attached' => $attach]];
        }
        $dept = self::department();
        if (!$dept) {
            return self::fail(503, 'بخش پشتیبانی برای ثبت تیکت تعریف نشده است.');
        }
        $r = localAPI('OpenTicket', ['clientid' => $cid, 'deptid' => $dept['id'], 'subject' => self::subject($domain, $lang), 'message' => $msg,
            'priority' => 'Medium', 'markdown' => true, 'serviceid' => (int) $svc->id] + $extra);
        if (($r['result'] ?? '') !== 'success') {
            self::log($cid, 'diagnostics report ' . $rid . ' ticket could not be opened: ' . (string) ($r['message'] ?? ''));
            return self::fail(502, 'ثبت تیکت ممکن نشد؛ دوباره تلاش کنید.');
        }
        unset($session['pcdn_diag'][$rid]);
        self::log($cid, 'diagnostics report ' . $rid . ' of ' . $domain . ' sent as ticket #' . (string) ($r['tid'] ?? $r['id'] ?? '') . ' (service #' . (int) $svc->id . ')');
        return [201, ['ok' => true, 'mode' => 'new', 'ticket' => ['id' => (int) ($r['id'] ?? 0), 'tid' => (string) ($r['tid'] ?? '')], 'attached' => $attach]];
    }

    private static function log(int $cid, string $line): void
    {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: ' . $line, $cid);
        }
    }

    /** True when the installed version takes `attachments` on OpenTicket / AddTicketReply. Unknown → false (fenced block). */
    public static function attachmentsSupported(): bool
    {
        $v = (string) ($GLOBALS['CONFIG']['Version'] ?? '');
        if ($v === '') {
            try {
                $v = (string) Capsule::table('tblconfiguration')->where('setting', 'Version')->value('value');
            } catch (\Throwable $e) {
                $v = '';
            }
        }
        return preg_match('/^[0-9]+\.[0-9]+(\.[0-9]+)?/', $v, $m) === 1 && version_compare($m[0], self::ATTACH_SINCE, '>=');
    }

    /** {id, name} of the support department: the addon setting `support_department`, else the first one; null when none. */
    public static function department(): ?array
    {
        if (!function_exists('localAPI')) {
            return null;
        }
        $want = (int) (\pasargadcdn_addon_settings()['support_department'] ?? 0);
        $r = localAPI('GetSupportDepartments', ['ignore_dept_assignments' => true]);
        $list = $r['departments']['department'] ?? [];
        if (!is_array($list)) {
            return null;
        }
        $first = null;
        foreach ($list as $x) {
            if (!is_array($x) || (int) ($x['id'] ?? 0) <= 0) {
                continue;
            }
            $row = ['id' => (int) $x['id'], 'name' => (string) ($x['name'] ?? '')];
            $first = $first ?? $row;
            if ($want > 0 && $row['id'] === $want) {
                return $row;
            }
        }
        return $first;
    }

    /** The client's own active tickets (≤ 20): [{id, tid, subject, status}]. */
    public static function tickets(int $cid): array
    {
        if (!function_exists('localAPI')) {
            return [];
        }
        $r = localAPI('GetTickets', ['clientid' => $cid, 'status' => 'All Active Tickets', 'limitnum' => 20]);
        $out = [];
        foreach ((array) ($r['tickets']['ticket'] ?? []) as $x) {
            if (!is_array($x) || (int) ($x['id'] ?? 0) <= 0 || (isset($x['userid']) && (int) $x['userid'] !== $cid)) {
                continue;
            }
            if (strcasecmp((string) ($x['status'] ?? ''), 'Closed') === 0) {
                continue;
            }
            $out[] = ['id' => (int) $x['id'], 'tid' => (string) ($x['tid'] ?? ''), 'subject' => mb_substr((string) ($x['subject'] ?? ''), 0, 120),
                'status' => (string) ($x['status'] ?? '')];
        }
        return array_slice($out, 0, 20);
    }

    public static function subject(string $domain, string $lang): string
    {
        return $lang === 'en' ? 'Diagnostics report ' . $domain : 'گزارش عیب‌یابی ' . $domain;
    }

    /** [fa, en] labels of the Markdown message. */
    const L = [
        'title' => ['گزارش عیب‌یابی', 'Diagnostics report'],
        'generated' => ['زمان تهیه', 'Generated'],
        'id' => ['شناسهٔ گزارش', 'Report ID'],
        'site' => ['سایت', 'Site'],
        'domain' => ['دامنه', 'Domain'],
        'status' => ['وضعیت', 'Status'],
        'created' => ['ایجاد', 'Created'],
        'plan' => ['ترافیک پلن', 'Plan traffic'],
        'features' => ['امکانات فعال پلن', 'Plan features on'],
        'dns' => ['DNS', 'DNS'],
        'ns' => ['نیم‌سرورها تأیید شده', 'Nameservers verified'],
        'ns_found' => ['نیم‌سرورهای فعلی', 'Current nameservers'],
        'records' => ['رکوردها (پروکسی)', 'Records (proxied)'],
        'dnssec' => ['DNSSEC', 'DNSSEC'],
        'ssl' => ['SSL', 'SSL'],
        'expires' => ['انقضا', 'Expires'],
        'days_left' => ['روز مانده', 'days left'],
        'error' => ['خطا', 'Error'],
        'config' => ['خلاصهٔ تنظیمات', 'Settings summary'],
        'warnings' => ['هشدارها', 'Warnings'],
        'recent' => ['۲۴ ساعت گذشته', 'Last 24 hours'],
        'sec_events' => ['رویدادهای امنیتی', 'Security events'],
        'top_rules' => ['قوانین پرتکرار', 'Top rules'],
        'statuses' => ['کدهای پاسخ', 'Status codes'],
        'origin_err' => ['خطاهای سرور اصلی', 'Origin errors'],
        'platform_err' => ['خطاهای سکو', 'Platform errors'],
        'events' => ['رویدادها', 'Events'],
        'tunnel' => ['تونل', 'Tunnel'],
        'sessions' => ['نشست‌ها', 'Sessions'],
        'abnormal' => ['قطع غیرعادی', 'Abnormal disconnects'],
        'connect' => ['میانگین زمان اتصال', 'Average connect time'],
        'origin' => ['سرور پشت تونل', 'Server behind the tunnel'],
        'top_drop' => ['دلیل اصلی قطع', 'Main disconnect reason'],
        'nodes' => ['به تفکیک نود', 'Per node'],
        'usage' => ['مصرف این ماه', 'This month\'s usage'],
        'over' => ['ترافیک تمام شده', 'Traffic used up'],
        'history' => ['آخرین تغییرات تنظیمات', 'Recent settings changes'],
        'incidents' => ['رخدادهای سکو', 'Platform incidents'],
        'note' => ['توضیح مشتری', 'Customer note'],
        'json' => ['گزارش کامل (JSON)', 'Full report (JSON)'],
        'yes' => ['بله', 'yes'],
        'no' => ['خیر', 'no'],
        'none' => ['ندارد', 'none'],
    ];

    private static function l(string $k, string $lang): string
    {
        return self::L[$k][$lang === 'en' ? 1 : 0] ?? $k;
    }

    /** Markdown-safe text: report strings never become links, images, HTML or headings. */
    public static function esc($v): string
    {
        $s = is_scalar($v) ? (string) $v : '';
        $s = (string) preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/u', '', $s);
        return (string) preg_replace('/([\\\\`*_{}\[\]()#+!|<>~])/', '\\\\$1', $s);
    }

    private static function scalar($v, string $lang): string
    {
        if (is_bool($v)) {
            return self::l($v ? 'yes' : 'no', $lang);
        }
        if ($v === null || $v === '') {
            return '—';
        }
        if (is_array($v)) {
            $parts = [];
            foreach ($v as $k => $x) {
                if (is_scalar($x) || is_bool($x) || $x === null) {
                    $parts[] = (is_int($k) ? '' : $k . ': ') . self::scalar($x, $lang);
                }
            }
            return implode(', ', array_slice($parts, 0, 20));
        }
        return self::esc($v);
    }

    /** The ticket message: the customer-audience report as Markdown (headings, bullet lists), in the app's language. */
    public static function markdown(array $r, string $lang): string
    {
        $L = function ($k) use ($lang) {
            return self::l($k, $lang);
        };
        $o = ['## ' . $L('title') . ' — ' . self::esc($r['site']['domain'] ?? ''), '',
            '- ' . $L('id') . ': `' . self::esc($r['report_id'] ?? '') . '`', '- ' . $L('generated') . ': ' . self::esc($r['generated_at'] ?? '')];
        $site = is_array($r['site'] ?? null) ? $r['site'] : [];
        $o[] = '';
        $o[] = '### ' . $L('site');
        $o[] = '- ' . $L('status') . ': ' . self::esc($site['status'] ?? '—');
        if (!empty($site['created_at'])) {
            $o[] = '- ' . $L('created') . ': ' . self::esc($site['created_at']);
        }
        $plan = is_array($site['plan'] ?? null) ? $site['plan'] : [];
        if (isset($plan['bandwidth_limit_gb'])) {
            $o[] = '- ' . $L('plan') . ': ' . self::esc($plan['bandwidth_limit_gb']) . ' GB';
        }
        $on = [];
        foreach ((array) ($plan['features'] ?? []) as $k => $v) {
            if ($v === true) {
                $on[] = self::esc($k);
            }
        }
        if ($on) {
            $o[] = '- ' . $L('features') . ': ' . implode(', ', array_slice($on, 0, 40));
        }
        if (is_array($r['dns'] ?? null)) {
            $d = $r['dns'];
            $o[] = '';
            $o[] = '### ' . $L('dns');
            $o[] = '- ' . $L('ns') . ': ' . self::scalar($d['ns_verified'] ?? null, $lang);
            if (!empty($d['ns_found'])) {
                $o[] = '- ' . $L('ns_found') . ': ' . self::scalar($d['ns_found'], $lang);
            }
            $o[] = '- ' . $L('records') . ': ' . self::esc($d['records'] ?? 0) . ' (' . self::esc($d['proxied'] ?? 0) . ')';
            $o[] = '- ' . $L('dnssec') . ': ' . self::scalar($d['dnssec'] ?? null, $lang);
        }
        if (is_array($r['ssl'] ?? null)) {
            $s = $r['ssl'];
            $o[] = '';
            $o[] = '### ' . $L('ssl');
            $o[] = '- ' . $L('status') . ': ' . self::esc($s['status'] ?? '—') . (!empty($s['source']) ? ' (' . self::esc($s['source']) . ')' : '');
            if (!empty($s['expires_at'])) {
                $o[] = '- ' . $L('expires') . ': ' . self::esc($s['expires_at']) . (isset($s['days_left']) ? ' — ' . self::esc($s['days_left']) . ' ' . $L('days_left') : '');
            }
            if (!empty($s['error'])) {
                $o[] = '- ' . $L('error') . ': ' . self::esc($s['error']);
            }
        }
        if (is_array($r['config'] ?? null) && $r['config']) {
            $o[] = '';
            $o[] = '### ' . $L('config');
            foreach (array_slice($r['config'], 0, 40, true) as $sec => $v) {
                $o[] = '- ' . self::esc($sec) . ': ' . self::scalar($v, $lang);
            }
        }
        if (!empty($r['warnings']) && is_array($r['warnings'])) {
            $o[] = '';
            $o[] = '### ' . $L('warnings');
            foreach (array_slice($r['warnings'], 0, 30) as $w) {
                $o[] = '- ' . self::esc(is_scalar($w) ? $w : '');
            }
        }
        if (is_array($r['recent'] ?? null)) {
            $x = $r['recent'];
            $o[] = '';
            $o[] = '### ' . $L('recent');
            $o[] = '- ' . $L('sec_events') . ': ' . self::esc($x['security_events_24h'] ?? 0);
            if (!empty($x['top_rules']) && is_array($x['top_rules'])) {
                $o[] = '- ' . $L('top_rules') . ': ' . implode(', ', array_map(function ($t) {
                    return is_array($t) ? self::esc($t['rule'] ?? '') . ' × ' . self::esc($t['count'] ?? 0) : '';
                }, array_slice($x['top_rules'], 0, 10)));
            }
            if (is_array($x['status_24h'] ?? null)) {
                $o[] = '- ' . $L('statuses') . ': ' . self::scalar($x['status_24h'], $lang);
            }
            $o[] = '- ' . $L('origin_err') . ': ' . self::esc($x['origin_errors_24h'] ?? 0) . ' · ' . $L('platform_err') . ': ' . self::esc($x['platform_errors_24h'] ?? 0);
            if (!empty($x['events']) && is_array($x['events'])) {
                $o[] = '- ' . $L('events') . ': ' . implode(', ', array_map(function ($e) {
                    return is_array($e) ? self::esc($e['type'] ?? '') . ' (' . self::esc($e['t'] ?? '') . ')' : '';
                }, array_slice($x['events'], 0, 10)));
            }
        }
        if (is_array($r['tunnel'] ?? null)) {
            $tn = $r['tunnel'];
            $o[] = '';
            $o[] = '### ' . $L('tunnel');
            $o[] = '- ' . $L('sessions') . ': ' . self::esc($tn['sessions_24h'] ?? 0) . ' · ' . $L('abnormal') . ': ' . self::esc($tn['abnormal_pct'] ?? 0) . '%';
            $o[] = '- ' . $L('connect') . ': ' . self::esc($tn['connect_ms_avg'] ?? '—') . ' ms · ' . $L('origin') . ': ' . self::esc($tn['origin'] ?? '—');
            if (!empty($tn['top_drop_reason'])) {
                $o[] = '- ' . $L('top_drop') . ': ' . self::esc($tn['top_drop_reason']);
            }
            if (!empty($tn['nodes']) && is_array($tn['nodes'])) {
                $o[] = '- ' . $L('nodes') . ':';
                foreach (array_slice($tn['nodes'], 0, 20) as $n) {
                    if (!is_array($n)) {
                        continue;
                    }
                    // §23.12: city labels only — the report has no node names or addresses
                    $label = $lang === 'en' && !empty($n['label_en']) ? $n['label_en'] : ($n['label'] ?? '—');
                    $o[] = '  - ' . self::esc($label) . ': ' . self::esc($n['sessions'] ?? 0) . ' · ' . self::esc($n['abnormal_pct'] ?? 0) . '%';
                }
            }
        }
        if (is_array($r['usage'] ?? null)) {
            $u = $r['usage'];
            $o[] = '';
            $o[] = '### ' . $L('usage');
            $gb = isset($u['month_bytes']) ? round(((float) $u['month_bytes']) / 1073741824, 2) : 0;
            $o[] = '- ' . self::esc($gb) . ' GB / ' . self::esc($u['limit_gb'] ?? '—') . ' GB (' . self::esc($u['pct'] ?? 0) . '%)'
                . (!empty($u['over_quota']) ? ' — ' . $L('over') : '');
        }
        if (!empty($r['history']) && is_array($r['history'])) {
            $o[] = '';
            $o[] = '### ' . $L('history');
            foreach (array_slice($r['history'], 0, 10) as $h) {
                if (is_array($h)) {
                    $o[] = '- #' . self::esc($h['version'] ?? '') . ' ' . self::esc($h['at'] ?? '') . ' — ' . self::esc(implode(', ', array_filter((array) ($h['sections'] ?? []), 'is_string')))
                        . (is_array($h['actor'] ?? null) ? ' (' . self::esc($h['actor']['kind'] ?? '') . ')' : '');
                }
            }
        }
        if (!empty($r['incidents']) && is_array($r['incidents'])) {
            $o[] = '';
            $o[] = '### ' . $L('incidents');
            foreach (array_slice($r['incidents'], 0, 10) as $i) {
                if (is_array($i)) {
                    $o[] = '- ' . self::esc($i['title'] ?? '') . ' — ' . self::esc($i['status'] ?? '') . ' (' . self::esc($i['at'] ?? '') . ')';
                }
            }
        }
        return implode("\n", $o);
    }
}
