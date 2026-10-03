<?php

namespace PasargadCdn\Admin;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\AlertMail', false)) {
    return;
}

/**
 * SPEC §23.5 / §23.10 (wave 14) — e-mail delivery of the controller's customer notifications.
 *
 * The controller is the single notification engine (subscriptions, dedup, rate limits, quiet hours); it sends SMS / Bale /
 * Telegram itself and leaves e-mail rows in its outbox for WHMCS, which owns the customer's address and the e-mail templates.
 * On every cron run (AfterCronJob, like TunnelAlerts) each Pasargad CDN server is asked once:
 *   GET /api/v1/notifications/outbox?channel=email&after=<0, then next>&limit=200   (≤ 5 pages)
 * Each item {id, client_id, service_id, site, event, severity, lang, subject, text, vars, created_at} is sent with SendEmail to
 * the client (template «Pasargad CDN Alert», or «Pasargad CDN Abuse Notice» for `abuse.notice`), then the batch is acknowledged:
 *   POST /api/v1/notifications/outbox/ack {"results": {"<id>": "sent"|"failed"|"skipped"}}
 *  - dedupe: every item is claimed once in mod_pasargadcdn_alert_mail (unique server + item id) BEFORE the e-mail goes out; an
 *    item offered again because the ack was lost is acknowledged with its recorded result, never e-mailed twice;
 *  - `tunnel.origin_*` items are skipped (TunnelAlerts sends those e-mails; the controller never queues them — belt and braces);
 *  - unknown client, closed account, a service id that is not the client's: skipped;
 *  - fail-safe: an unreachable controller, a 5xx or an older controller (404: no outbox — re-checked after 6 hours) sends nothing,
 *    acknowledges nothing and never throws into the cron. Unacked rows are re-offered by the controller after 30 minutes.
 * Customer text comes from the controller's templates (no node names or addresses) and never names the billing software.
 */
final class AlertMail
{
    const TABLE = 'mod_pasargadcdn_alert_mail';
    const EMAIL_ALERT = 'Pasargad CDN Alert';
    const EMAIL_ABUSE = 'Pasargad CDN Abuse Notice';
    /** sha1 of earlier shipped bodies that may be upgraded in place (none yet — same mechanism as Shares::LEGACY_BODIES) */
    const LEGACY_BODIES = [];
    const PAGE = 200;
    const MAX_PAGES = 5;
    const BACKOFF = 21600;
    const CATEGORY = ['phishing' => ['فیشینگ', 'phishing'], 'malware' => ['بدافزار', 'malware'], 'illegal' => ['محتوای غیرقانونی', 'illegal content'],
        'spam' => ['هرزنامه', 'spam'], 'copyright' => ['نقض حق نشر', 'copyright infringement'], 'other' => ['سایر', 'other']];

    /** @var callable|null tests: fn(): int */
    public static $clock = null;
    /** @var array report of the last run */
    public static $report = [];

    private static function now(): int
    {
        return self::$clock ? (int) (self::$clock)() : time();
    }

    /** AfterCronJob entry. Never throws. */
    public static function onCron(): void
    {
        try {
            if (!Env::loadServerModule() || !TunnelAlerts::on(\pasargadcdn_addon_settings(), 'alert_email', true) || !Env::cdnProductIds()) {
                return;
            }
            self::run();
        } catch (\Throwable $e) {
            Env::log('alert e-mail cron error: ' . $e->getMessage());
        }
    }

    /** Creates the claim table when missing (activation / 1.7.0 upgrade / first run). */
    public static function ensure(): void
    {
        $schema = Capsule::schema();
        if (!$schema->hasTable(self::TABLE)) {
            $schema->create(self::TABLE, function ($t) {
                $t->increments('id');
                $t->integer('server_id');
                $t->string('item_id', 64);                   // controller outbox id
                $t->integer('client_id')->default(0);
                $t->string('event', 32)->default('');
                $t->string('status', 16)->default('new');    // sent | failed | skipped
                $t->dateTime('created_at')->nullable();
                $t->dateTime('updated_at')->nullable();
                $t->unique(['server_id', 'item_id'], 'mod_pcdn_alertmail_once');
            });
        }
    }

    public static function run(): array
    {
        self::$report = ['polled' => 0, 'sent' => 0, 'failed' => 0, 'skipped' => 0, 'acked' => 0, 'errors' => []];
        if (!Env::cdnProductIds()) {
            return self::$report;
        }
        self::ensure();
        try {
            self::ensureTemplates();
        } catch (\Throwable $e) {
            self::$report['errors'][] = 'templates: ' . $e->getMessage();
        }
        foreach (Env::servers() as $server) {
            if (!empty($server->disabled)) {
                continue;
            }
            $sid = (int) $server->id;
            if ((int) Env::kvGet('alertmail_unsupported:' . $sid, 0) > self::now()) {
                continue;
            }
            try {
                self::pollServer($server);
            } catch (\Throwable $e) {
                self::$report['errors'][] = 'server #' . $sid . ': ' . $e->getMessage();
            }
        }
        Env::kvSet('alertmail_last', ['at' => self::now(), 'sent' => self::$report['sent'], 'failed' => self::$report['failed'], 'skipped' => self::$report['skipped']]);
        return self::$report;
    }

    private static function pollServer($server): void
    {
        $sid = (int) $server->id;
        $after = '0';   // every run starts at the beginning (un-acked rows reappear after 30 min) and follows `next`
        for ($page = 0; $page < self::MAX_PAGES; $page++) {
            $path = '/api/v1/notifications/outbox?channel=email&after=' . rawurlencode((string) $after) . '&limit=' . self::PAGE;
            try {
                [$code, $data] = Env::api(10, $server)->raw('GET', $path);
            } catch (\Throwable $e) {
                self::$report['errors'][] = 'outbox #' . $sid . ': ' . $e->getMessage();
                return;
            }
            if ($code === 404) {
                // older controller: no outbox — look again in 6 hours, one log line
                Env::kvSet('alertmail_unsupported:' . $sid, self::now() + self::BACKOFF);
                self::$report['errors'][] = 'unsupported #' . $sid;
                return;
            }
            if ($code !== 200 || !is_array($data)) {
                self::$report['errors'][] = 'outbox #' . $sid . ': HTTP ' . $code;
                return;
            }
            self::$report['polled']++;
            $items = array_values(array_filter((array) ($data['items'] ?? []), 'is_array'));
            $results = [];
            foreach ($items as $it) {
                $id = $it['id'] ?? null;
                if (!is_scalar($id) || !preg_match('/^[A-Za-z0-9_-]{1,64}$/D', (string) $id)) {
                    continue;
                }
                $results[(string) $id] = self::handle($sid, $it);
            }
            if ($results) {
                try {
                    [$ac] = Env::api(10, $server)->raw('POST', '/api/v1/notifications/outbox/ack',
                        (string) json_encode(['results' => $results], JSON_UNESCAPED_SLASHES));
                    if ($ac >= 200 && $ac < 300) {
                        self::$report['acked'] += count($results);
                    } else {
                        self::$report['errors'][] = 'ack #' . $sid . ': HTTP ' . $ac;
                    }
                } catch (\Throwable $e) {
                    self::$report['errors'][] = 'ack #' . $sid . ': ' . $e->getMessage();
                }
            }
            $next = $data['next'] ?? null;
            if ($next === null || $next === '' || !is_scalar($next) || (string) $next === (string) $after || !$items) {
                return;
            }
            $after = (string) $next;
        }
    }

    /** sent | failed | skipped for one outbox item (claims it first). */
    private static function handle(int $sid, array $it): string
    {
        $iid = (string) $it['id'];
        $cid = is_scalar($it['client_id'] ?? null) && ctype_digit((string) $it['client_id']) ? (int) $it['client_id'] : 0;
        $event = substr(is_string($it['event'] ?? null) ? $it['event'] : '', 0, 32);
        $now = date('Y-m-d H:i:s');
        $prev = Capsule::table(self::TABLE)->where('server_id', $sid)->where('item_id', $iid)->first(['id', 'status']);
        if ($prev && in_array($prev->status, ['sent', 'skipped'], true)) {
            return (string) $prev->status;   // offered again (lost ack): never e-mailed twice
        }
        if ($prev) {
            $rowId = (int) $prev->id;
        } else {
            try {
                $rowId = (int) Capsule::table(self::TABLE)->insertGetId(['server_id' => $sid, 'item_id' => $iid, 'client_id' => $cid, 'event' => $event,
                    'status' => 'new', 'created_at' => $now, 'updated_at' => $now]);
            } catch (\Throwable $e) {
                return 'failed';   // a parallel cron claimed it; its own run acknowledges
            }
        }
        $done = function (string $st) use ($rowId) {
            Capsule::table(self::TABLE)->where('id', $rowId)->update(['status' => $st, 'updated_at' => date('Y-m-d H:i:s')]);
            self::$report[$st]++;
            return $st;
        };
        if ($event === '' || strpos($event, 'tunnel.origin_') === 0) {
            return $done('skipped');
        }
        $client = $cid > 0 ? Capsule::table('tblclients')->where('id', $cid)->first(['id', 'status', 'email']) : null;
        if (!$client || strcasecmp((string) $client->status, 'Closed') === 0 || trim((string) $client->email) === '') {
            return $done('skipped');
        }
        $svc = is_scalar($it['service_id'] ?? null) && ctype_digit((string) $it['service_id']) ? (int) $it['service_id'] : 0;
        if ($svc > 0 && !Capsule::table('tblhosting')->where('id', $svc)->where('userid', $cid)->exists()) {
            return $done('skipped');   // a service id that is not this client's: never mix accounts
        }
        $abuse = $event === 'abuse.notice';
        $r = Env::localApi('SendEmail', ['messagename' => $abuse ? self::EMAIL_ABUSE : self::EMAIL_ALERT, 'id' => $cid,
            'customvars' => base64_encode(serialize(self::vars($it)))]);
        $ok = ($r['result'] ?? '') === 'success';
        Env::log('alert e-mail «' . ($abuse ? self::EMAIL_ABUSE : self::EMAIL_ALERT) . '» (' . $event . ', outbox ' . $iid . ') to client #' . $cid . ' — '
            . ($ok ? 'sent' : 'failed: ' . ($r['message'] ?? '')), $cid);
        return $done($ok ? 'sent' : 'failed');
    }

    private static function clip($v, int $max): string
    {
        $s = is_scalar($v) ? trim((string) $v) : '';
        $s = (string) preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/u', '', $s);
        return mb_strlen($s) > $max ? mb_substr($s, 0, $max - 1) . '…' : $s;
    }

    /** Template variables: the controller's subject / text (HTML-escaped) and, for abuse notices, the report facts. */
    public static function vars(array $it): array
    {
        $lang = ($it['lang'] ?? 'fa') === 'en' ? 'en' : 'fa';
        $text = self::clip($it['text'] ?? '', 4000);
        $site = self::clip($it['site'] ?? '', 253);
        $v = ['alert_subject' => self::clip($it['subject'] ?? '', 200), 'alert_text' => $text,
            'alert_body_html' => nl2br(htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')), 'alert_event' => self::clip($it['event'] ?? '', 32),
            'alert_severity' => self::clip($it['severity'] ?? '', 16), 'alert_site' => preg_match('/^[a-z0-9.-]{1,253}$/D', $site) ? $site : '', 'alert_lang' => $lang];
        if (($it['event'] ?? '') === 'abuse.notice') {
            $x = is_array($it['vars'] ?? null) ? $it['vars'] : [];
            $cat = (string) ($x['category'] ?? '');
            $urls = [];
            foreach (array_slice((array) ($x['urls'] ?? []), 0, 10) as $u) {
                if (is_string($u) && preg_match('#^https?://#i', $u)) {
                    $urls[] = htmlspecialchars(self::clip($u, 2048), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                }
            }
            $v += ['abuse_domain' => preg_match('/^[a-z0-9.-]{1,253}$/D', (string) ($x['domain'] ?? $site)) ? (string) ($x['domain'] ?? $site) : $site,
                'abuse_category' => self::CATEGORY[$cat][$lang === 'en' ? 1 : 0] ?? self::clip($cat, 32),
                'abuse_urls_html' => $urls ? '<ul><li dir="ltr">' . implode('</li><li dir="ltr">', $urls) . '</li></ul>' : '',
                'abuse_deadline' => self::clip($x['deadline'] ?? $x['deadline_at'] ?? '', 40), 'abuse_ticket' => preg_match('/^AB-[0-9A-Z]{8}$/D', (string) ($x['ticket'] ?? '')) ? (string) $x['ticket'] : ''];
        }
        return $v;
    }

    /** Subjects / bodies: [name => [fa subject, fa body, en subject, en body]]. Plain, theme-neutral HTML; no node or software names. */
    public static function templates(): array
    {
        $fa = function (string $b) {
            return '<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;text-align:right;line-height:1.8">' . $b . '<p>{$signature}</p></div>';
        };
        $en = function (string $b) {
            return '<div style="font-family:Arial,sans-serif;line-height:1.6">' . $b . '<p>{$signature}</p></div>';
        };
        return [
            self::EMAIL_ALERT => ['{$alert_subject}',
                $fa('<p>{$client_name} گرامی،</p><p style="background:#f4f6f8;padding:10px 14px;border-radius:6px">{$alert_body_html}</p>'
                    . '{if $alert_site}<p>سرویس: <strong dir="ltr">{$alert_site}</strong></p>{/if}'
                    . '<p>جزئیات در پنل CDN همین سرویس در ناحیهٔ کاربری شما آمده است. برای تغییر یا لغو این هشدارها به صفحهٔ «هشدارها» در پنل CDN بروید.</p>'),
                '{$alert_subject}',
                $en('<p>Dear {$client_name},</p><p style="background:#f4f6f8;padding:10px 14px;border-radius:6px">{$alert_body_html}</p>'
                    . '{if $alert_site}<p>Service: <strong>{$alert_site}</strong></p>{/if}'
                    . '<p>Details are in the CDN panel of this service in your client area. To change or stop these alerts, open the “Alerts” page of the CDN panel.</p>')],
            self::EMAIL_ABUSE => ['اطلاعیهٔ تخلف دربارهٔ {$abuse_domain} ({$abuse_ticket})',
                $fa('<p>{$client_name} گرامی،</p><p>گزارشی دربارهٔ محتوای سایت <strong dir="ltr">{$abuse_domain}</strong> که از سرویس CDN شما استفاده می‌کند دریافت شده است '
                    . '(دسته: {$abuse_category}، شناسهٔ گزارش: <strong dir="ltr">{$abuse_ticket}</strong>).</p>'
                    . '{if $abuse_urls_html}<p>نشانی‌های گزارش‌شده:</p>{$abuse_urls_html}{/if}'
                    . '{if $alert_body_html}<p style="background:#f4f6f8;padding:10px 14px;border-radius:6px">{$alert_body_html}</p>{/if}'
                    . '<p>لطفاً موضوع را بررسی کنید و اگر محتوا ناقض قوانین است، تا <strong dir="ltr">{$abuse_deadline}</strong> آن را حذف کنید؛ در غیر این صورت ممکن است سرویس این دامنه معلق شود. '
                    . 'برای پاسخ یا اعتراض، یک تیکت پشتیبانی با ذکر شناسهٔ گزارش ثبت کنید.</p>'),
                'Abuse notice about {$abuse_domain} ({$abuse_ticket})',
                $en('<p>Dear {$client_name},</p><p>We received a report about content on <strong>{$abuse_domain}</strong>, which uses your CDN service '
                    . '(category: {$abuse_category}, report ID: <strong>{$abuse_ticket}</strong>).</p>'
                    . '{if $abuse_urls_html}<p>Reported addresses:</p>{$abuse_urls_html}{/if}'
                    . '{if $alert_body_html}<p style="background:#f4f6f8;padding:10px 14px;border-radius:6px">{$alert_body_html}</p>{/if}'
                    . '<p>Please review it and, if the content breaks the rules, remove it by <strong>{$abuse_deadline}</strong>; otherwise the service of this domain may be suspended. '
                    . 'To answer or object, open a support ticket quoting the report ID.</p>')],
        ];
    }

    /**
     * Creates the templates when missing (activation, 1.7.0 upgrade, first cron); an unedited earlier default body (sha1 in
     * LEGACY_BODIES) is upgraded in place, an edited one is never touched. Idempotent.
     */
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
}
