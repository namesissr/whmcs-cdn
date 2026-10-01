<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiException;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\TunnelAlerts', false)) {
    return;
}

/**
 * Wave 7 (SPEC §15.4 / §15.7) — origin-down e-mails for tunnel services.
 *
 * On every WHMCS cron run (AfterCronJob) each Pasargad CDN server is polled once:
 *   GET /api/v1/events?type=tunnel&since=<cursor>&limit=500
 * The controller returns tunnel.origin_down / tunnel.origin_up events oldest first, `since` inclusive.
 *  - cursor: the newest `created_at` seen, per server, in mod_pasargadcdn_settings
 *    (`tunnel_events_cursor:<server id>`); the first run only looks 30 minutes back;
 *  - dedupe: every event id is claimed once in mod_pasargadcdn_tunnel_events (unique server + id)
 *    BEFORE any e-mail goes out, so overlapping polls or parallel crons never send twice;
 *  - mapping: the event's external_id (WHMCS service id) when it matches the domain, else the
 *    domain → the live CDN service on that server;
 *  - «اتصال دوباره برقرار شد» is only sent after a «قطعی سرور پشت تونل» e-mail for that service;
 *    events older than STALE_AFTER (cron was stopped) are recorded but not e-mailed;
 *  - fail-safe: any controller error (unreachable, 5xx, an older controller that 404s/422s the
 *    tunnel type) leaves the cursor untouched, sends nothing and never throws into the cron.
 */
final class TunnelAlerts
{
    const DOWN = 'tunnel.origin_down';
    const UP = 'tunnel.origin_up';
    const PAGE = 500;
    const MAX_PAGES = 5;
    const FIRST_LOOKBACK = 1800;
    const STALE_AFTER = 21600;

    /** @var callable|null tests: fn(): int (unix time) */
    public static $clock = null;
    /** @var array report of the last run (tests / admin) */
    public static $report = [];

    private static function now(): int
    {
        return self::$clock ? (int) (self::$clock)() : time();
    }

    /** AfterCronJob entry. Never throws. */
    public static function onCron(): void
    {
        try {
            // the setting comes from the memoised addon settings; no CDN product → one memoised query, no HTTP
            if (!Env::loadServerModule() || !self::on(\pasargadcdn_addon_settings(), 'tunnel_email', true) || !Env::cdnProductIds()) {
                return;
            }
            self::run();
        } catch (\Throwable $e) {
            Env::log('tunnel alerts cron error: ' . $e->getMessage());
        }
    }

    /** yes/no addon setting from the server module's memoised settings read (the prepaid cron already did it). */
    public static function on(array $settings, string $key, bool $default): bool
    {
        if (!array_key_exists($key, $settings)) {
            return $default;
        }
        return in_array(strtolower(trim((string) $settings[$key])), ['on', '1', 'yes', 'true'], true);
    }

    public static function run(): array
    {
        self::$report = ['polled' => 0, 'sent' => [], 'skipped' => [], 'errors' => []];
        if (!Env::cdnProductIds()) {
            return self::$report; // nothing to notify
        }
        if (!Env::hasTable(Env::TUNNEL_EVENTS)) {
            Env::ensureTable();
        }
        foreach (Env::servers() as $server) {
            if (!empty($server->disabled)) {
                continue;
            }
            try {
                self::pollServer($server);
            } catch (\Throwable $e) {
                self::$report['errors'][] = 'server #' . (int) $server->id . ': ' . $e->getMessage();
                self::logOnce('tevents-err:' . (int) $server->id, 'tunnel alerts: server #' . (int) $server->id . ' failed: ' . $e->getMessage());
            }
        }
        return self::$report;
    }

    private static function iso(int $ts): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $ts);
    }

    private static function ts($iso): ?int
    {
        if (!is_string($iso) || $iso === '') {
            return null;
        }
        $t = strtotime($iso);
        return $t === false ? null : $t;
    }

    private static function pollServer($server): void
    {
        $sid = (int) $server->id;
        $key = 'tunnel_events_cursor:' . $sid;
        $cursor = Env::kvGet($key);
        if (!is_string($cursor) || self::ts($cursor) === null) {
            $cursor = self::iso(self::now() - self::FIRST_LOOKBACK);
        }
        for ($page = 0; $page < self::MAX_PAGES; $page++) {
            try {
                $data = Env::api(10, $server)->get('/api/v1/events?type=tunnel&since=' . rawurlencode($cursor) . '&limit=' . self::PAGE);
            } catch (ApiException $e) {
                $code = (int) $e->getCode();
                if ($code === 404 || $code === 422) {
                    // older controller (no tunnel events): quiet, one line a day
                    self::logOnce('tevents-old:' . $sid, 'tunnel alerts: controller of server #' . $sid . ' has no tunnel events (HTTP ' . $code . ') — origin-down e-mails need controller Wave 7', 86400);
                    self::$report['errors'][] = 'unsupported #' . $sid;
                    return;
                }
                self::$report['errors'][] = 'events #' . $sid . ': ' . $e->getMessage();
                self::logOnce('tevents-err:' . $sid, 'tunnel alerts: controller events unavailable for server #' . $sid . ' (' . $e->getMessage() . ') — retried next cron');
                return;
            }
            self::$report['polled']++;
            $items = self::items($data);
            $max = $cursor;
            foreach ($items as $ev) {
                $type = (string) ($ev['type'] ?? '');
                if ($type !== self::DOWN && $type !== self::UP) {
                    continue; // never act on anything but the two tunnel events (an old controller may ignore ?type=)
                }
                $at = (string) ($ev['created_at'] ?? $ev['t'] ?? '');
                $t = self::ts($at);
                if ($t !== null && $t > (int) self::ts($max)) {
                    $max = self::iso($t);
                }
                self::handle($server, $ev, $t);
            }
            if ($max !== $cursor) {
                Env::kvSet($key, $max);
            }
            if (count($items) < self::PAGE || $max === $cursor) {
                return;
            }
            $cursor = $max;
        }
    }

    /** Event list from the response (a JSON list; tolerant of {events: [...]} / {items: [...]}). */
    private static function items($data): array
    {
        if (!is_array($data)) {
            return [];
        }
        if (isset($data['events']) && is_array($data['events'])) {
            $data = $data['events'];
        } elseif (isset($data['items']) && is_array($data['items'])) {
            $data = $data['items'];
        }
        return array_values(array_filter($data, 'is_array'));
    }

    private static function handle($server, array $ev, ?int $t): void
    {
        $sid = (int) $server->id;
        $type = (string) $ev['type'];
        $domain = Env::domain((string) ($ev['domain'] ?? ''));
        $eid = (string) ($ev['id'] ?? '');
        if ($eid === '' || strlen($eid) > 64) {
            $eid = 'h_' . substr(sha1($domain . '|' . $type . '|' . ($ev['created_at'] ?? '') . '|' . ($ev['seq'] ?? '')), 0, 40);
        }
        // claim the event first: a duplicate (inclusive `since`, a parallel cron) stops here
        try {
            $rowId = (int) Capsule::table(Env::TUNNEL_EVENTS)->insertGetId(['server_id' => $sid, 'event_id' => $eid, 'type' => $type,
                'domain' => substr($domain, 0, 253), 'event_at' => $t !== null ? gmdate('Y-m-d H:i:s', $t) : null,
                'status' => 'new', 'created_at' => date('Y-m-d H:i:s')]);
        } catch (\Throwable $e) {
            return;
        }
        $done = function (string $status, ?int $service = null) use ($rowId, $eid) {
            Capsule::table(Env::TUNNEL_EVENTS)->where('id', $rowId)->update(['status' => $status, 'service_id' => $service]);
            self::$report[$status === 'sent' ? 'sent' : 'skipped'][] = ['event' => $eid, 'status' => $status, 'service' => $service];
        };
        $svc = self::service($server, $domain, $ev['external_id'] ?? null);
        if (!$svc) {
            $done('nomatch');
            return;
        }
        if ($t !== null && self::now() - $t > self::STALE_AFTER) {
            $done('stale', (int) $svc->id);
            return;
        }
        if ($type === self::UP) {
            // only after a «down» e-mail for this service that no «up» e-mail followed yet
            $lastDown = (int) Capsule::table(Env::TUNNEL_EVENTS)->where('service_id', (int) $svc->id)->where('type', self::DOWN)->where('status', 'sent')->max('id');
            $lastUp = (int) Capsule::table(Env::TUNNEL_EVENTS)->where('service_id', (int) $svc->id)->where('type', self::UP)->where('status', 'sent')->max('id');
            if ($lastDown === 0 || $lastUp > $lastDown) {
                $done('skipped', (int) $svc->id);
                return;
            }
        }
        $tpl = $type === self::DOWN ? Wizard::EMAIL_TUNNEL_DOWN : Wizard::EMAIL_TUNNEL_UP;
        $r = Env::localApi('SendEmail', ['messagename' => $tpl, 'id' => (int) $svc->id, 'customvars' => base64_encode(serialize(self::vars($ev, $t)))]);
        $ok = ($r['result'] ?? '') === 'success';
        $done($ok ? 'sent' : 'failed', (int) $svc->id);
        Env::log('tunnel alerts: «' . $tpl . '» for service #' . (int) $svc->id . ' (' . $domain . ', event ' . $eid . ') — '
            . ($ok ? 'sent' : 'failed: ' . ($r['message'] ?? '')), (int) $svc->userid);
    }

    /** The live CDN service of this event: external_id when it agrees with the domain, else by domain. */
    private static function service($server, string $domain, $externalId)
    {
        if (!Env::validHostname($domain)) {
            return null;
        }
        $pids = Env::cdnProductIds();
        $base = function () use ($pids) {
            return Capsule::table('tblhosting')->whereIn('packageid', $pids)->whereIn('domainstatus', ['Active', 'Suspended']);
        };
        if (is_scalar($externalId) && ctype_digit((string) $externalId) && (int) $externalId > 0) {
            $r = $base()->where('id', (int) $externalId)->first(['id', 'userid', 'domain', 'server', 'domainstatus']);
            if ($r && Env::domain((string) $r->domain) === $domain) {
                return $r;
            }
        }
        $rows = $base()->where('server', (int) $server->id)->where('domain', 'like', '%' . $domain . '%')
            ->orderBy('id')->get(['id', 'userid', 'domain', 'server', 'domainstatus'])->all();
        $best = null;
        foreach ($rows as $r) {
            if (Env::domain((string) $r->domain) !== $domain) {
                continue;
            }
            if (!$best || ($r->domainstatus === 'Active' && $best->domainstatus !== 'Active')) {
                $best = $r;
            }
        }
        return $best;
    }

    /** Template variables (Persian digits / dates). Path ids come from the controller's own config ids. */
    private static function vars(array $ev, ?int $t): array
    {
        $d = is_array($ev['data'] ?? null) ? $ev['data'] : [];
        $paths = [];
        foreach ((array) ($d['paths'] ?? []) as $p) {
            if (is_scalar($p) && preg_match('/^[A-Za-z0-9_-]{1,32}$/', (string) $p)) {
                $paths[] = (string) $p;
            }
        }
        $attempts = max(0, (int) ($d['attempts'] ?? 0));
        $errors = max(0, (int) ($d['origin_errors'] ?? 0));
        $since = self::ts($d['since'] ?? null) ?? $t ?? self::now();
        $downFor = '';
        $ds = self::ts($d['down_since'] ?? null);
        if ($ds !== null && $since > $ds) {
            $min = (int) round(($since - $ds) / 60);
            $downFor = $min < 60 ? View::n(max(1, $min)) . ' دقیقه'
                : ($min < 1440 ? View::n(round($min / 60, 1), 1) . ' ساعت' : View::n(round($min / 1440, 1), 1) . ' روز');
        }
        return [
            'cdn_tunnel_paths' => implode('، ', array_slice($paths, 0, 20)),
            'cdn_tunnel_attempts' => View::n($attempts),
            'cdn_tunnel_origin_errors' => View::n($errors),
            'cdn_tunnel_error_pct' => $attempts > 0 ? View::n(round($errors * 100 / $attempts)) . '٪' : '',
            'cdn_tunnel_since' => self::when($since),
            'cdn_tunnel_down_for' => $downFor,
        ];
    }

    /** «۹ مهر ۱۴۰۵، ساعت ۱۴:۰۵» (Tehran time) or a plain UTC stamp without intl. */
    private static function when(int $ts): string
    {
        if (class_exists('\\IntlDateFormatter')) {
            $f = new \IntlDateFormatter('fa_IR@calendar=persian', \IntlDateFormatter::NONE, \IntlDateFormatter::NONE,
                'Asia/Tehran', \IntlDateFormatter::TRADITIONAL, "d MMMM yyyy، 'ساعت' HH:mm");
            $s = $f->format($ts);
            if (is_string($s) && $s !== '') {
                return $s;
            }
        }
        return View::digits(gmdate('Y-m-d H:i', $ts)) . ' UTC';
    }

    /** Activity-log line at most once per $every seconds per key (a down controller must not flood the log). */
    private static function logOnce(string $key, string $msg, int $every = 3600): void
    {
        $last = (int) Env::kvGet('logonce:' . $key, 0);
        if (self::now() - $last < $every) {
            return;
        }
        Env::kvSet('logonce:' . $key, self::now());
        Env::log($msg);
    }
}
