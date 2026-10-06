<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;

if (class_exists(__NAMESPACE__ . '\\OwnerSync', false)) {
    return;
}

/**
 * Security review C1 — owners of existing sites («همگام‌سازی مالکیت دامنه‌ها»).
 *
 * The controller refuses a site that is the parent or the child of a site with a different owner, and the
 * owner of a site is the WHMCS client (`client_id`, sent by CreateAccount since the security review) or the
 * reseller (`reseller_client_id`). Sites created by an older module have NO owner: they never match anyone,
 * so a customer cannot add a subdomain of their own older site, and the protection only knows who a site
 * belongs to once it has an owner. This pass sets it: for every Active / Suspended CDN service whose site
 * (GET /api/v1/sites, one call per server; matched like the sync report: external id, then domain) has no
 * client_id, PATCH /api/v1/sites/{domain}/owner {"client_id": <service userid>}.
 *
 *  - idempotent: a site that has an owner is never touched again (a different owner is only reported);
 *  - bounded: at most $limit PATCH calls per run (the rest is counted as `remaining`, done by the next run);
 *  - fail-safe: an unreachable controller / 5xx stops that server's pass and is logged; a refusal (422: the
 *    owner would put the site next to another owner's parent/child, legacy data) is logged and retried once a
 *    day; a controller from before the security review (no `client_id` in the list) is skipped;
 *  - cron: AfterCronJob runs it every cron while work remains, then every INTERVAL seconds (a new service gets
 *    its owner at creation, so later passes only catch services moved by hand).
 */
final class OwnerSync
{
    const MAX_PER_RUN = 100;
    const INTERVAL = 21600;
    const RETRY_AFTER_ERROR = 3600;
    const RETRY_REFUSED = 86400;
    const KV = 'owner_sync';
    const KV_REFUSED = 'owner_sync_refused';
    const LIVE = ['Active', 'Suspended'];

    /** @var callable|null tests: fn(): int (unix time) */
    public static $clock = null;
    /** @var array report of the last run (tests / admin page) */
    public static $report = [];

    private static function now(): int
    {
        return self::$clock ? (int) (self::$clock)() : time();
    }

    /** AfterCronJob entry: throttled, never throws. No CDN product → one memoised query, no HTTP. */
    public static function onCron(): void
    {
        try {
            // the setting comes from the memoised addon settings; no CDN product → one memoised query, no HTTP
            if (!Env::loadServerModule() || !self::enabled() || !Env::cdnProductIds()) {
                return;
            }
            $state = (array) Env::kvGet(self::KV, []);
            if ((int) ($state['next_at'] ?? 0) > self::now()) {
                return;
            }
            $r = self::run(self::MAX_PER_RUN, false);
            $wait = $r['remaining'] > 0 ? 0 : ($r['errors'] ? self::RETRY_AFTER_ERROR : self::INTERVAL);
            Env::kvSet(self::KV, ['at' => self::now(), 'next_at' => self::now() + $wait, 'fixed' => count($r['fixed']),
                'refused' => count($r['refused']), 'remaining' => $r['remaining'], 'errors' => count($r['errors'])]);
        } catch (\Throwable $e) {
            Env::log('owner sync cron error: ' . $e->getMessage());
        }
    }

    /** Addon setting «همگام‌سازی مالکیت دامنه‌ها» (yes/no, default yes) from the memoised settings read. */
    private static function enabled(): bool
    {
        $s = \pasargadcdn_addon_settings();
        return !array_key_exists('owner_sync', $s) || in_array(strtolower(trim((string) $s['owner_sync'])), ['on', '1', 'yes', 'true'], true);
    }

    /**
     * One pass over every CDN server. $retryRefused: also retry sites refused less than a day ago (the admin
     * button). Returns (and keeps in $report) checked / fixed / refused / mismatch / remaining / unsupported / errors.
     */
    public static function run(int $limit = self::MAX_PER_RUN, bool $retryRefused = true): array
    {
        $r = self::$report = ['checked' => 0, 'fixed' => [], 'refused' => [], 'mismatch' => [], 'remaining' => 0,
            'unsupported' => [], 'errors' => []];
        if (!Env::cdnProductIds()) {
            return $r;
        }
        $byServer = [];
        foreach (self::services() as $svc) {
            $server = self::serverOf($svc);
            if ($server) {
                $byServer[(int) $server->id][] = $svc;
            }
        }
        $refused = (array) Env::kvGet(self::KV_REFUSED, []);
        $budget = max(0, $limit);
        $now = self::now();
        foreach ($byServer as $sid => $services) {
            $server = Env::serverById($sid);
            try {
                $api = Env::api(15, $server);
                $sites = $api->get('/api/v1/sites');
            } catch (\Throwable $e) {
                $r['errors'][] = 'server #' . $sid . ': ' . $e->getMessage();
                continue;
            }
            $rows = array_values(array_filter($sites, 'is_array'));
            if ($rows && !array_key_exists('client_id', $rows[0])) {
                $r['unsupported'][] = $sid; // a controller from before the security review: no owners to set
                continue;
            }
            $ix = Data::siteIndex($rows);
            foreach ($services as $svc) {
                $site = Data::siteFor($svc, $ix);
                $uid = (int) $svc->userid;
                if (!$site || $uid <= 0 || !array_key_exists('client_id', $site)) {
                    continue;
                }
                $r['checked']++;
                $domain = strtolower((string) $site['domain']);
                if (!empty($site['client_id'])) {
                    if ((int) $site['client_id'] !== $uid) {
                        $r['mismatch'][] = ['service' => (int) $svc->id, 'domain' => $domain, 'client_id' => (int) $site['client_id'], 'userid' => $uid];
                    }
                    continue;
                }
                if (!empty($site['reseller_client_id'])) {
                    continue; // owned through the reseller tag
                }
                if (!$retryRefused && isset($refused[$domain]) && $now - (int) $refused[$domain] < self::RETRY_REFUSED) {
                    continue;
                }
                if ($budget <= 0) {
                    $r['remaining']++;
                    continue;
                }
                $budget--;
                try {
                    $api->patch(ApiClient::site($domain) . '/owner', ['client_id' => $uid]);
                } catch (ApiException $e) {
                    $code = (int) $e->getCode();
                    if ($code === 422 || $code === 404 || $code === 409) {
                        $refused[$domain] = $now;
                        $r['refused'][] = ['service' => (int) $svc->id, 'domain' => $domain, 'error' => $e->getMessage()];
                        Env::log('owner sync: ' . $domain . ' (service #' . (int) $svc->id . ') refused by the controller: ' . $e->getMessage(), $uid);
                        continue;
                    }
                    // unreachable / 5xx / auth: stop this server, the next run retries
                    $r['errors'][] = 'server #' . $sid . ': ' . $e->getMessage();
                    break;
                }
                unset($refused[$domain]);
                $r['fixed'][] = ['service' => (int) $svc->id, 'domain' => $domain, 'client_id' => $uid];
                Env::log('owner sync: site ' . $domain . ' (service #' . (int) $svc->id . ') now owned by client #' . $uid, $uid);
            }
        }
        // forget refusals of sites that are gone or owned now (keeps the setting small)
        $refused = array_filter($refused, function ($ts) use ($now) {
            return $now - (int) $ts < 7 * self::RETRY_REFUSED;
        });
        Env::kvSet(self::KV_REFUSED, $refused);
        if ($r['fixed'] || $r['refused'] || $r['errors'] || $r['remaining']) {
            Env::log(sprintf('owner sync: %d set, %d refused, %d remaining, %d errors%s', count($r['fixed']), count($r['refused']),
                $r['remaining'], count($r['errors']), $r['errors'] ? ' (' . implode('; ', $r['errors']) . ')' : ''));
        }
        foreach ($r['mismatch'] as $m) {
            self::logOnce('owner-mismatch:' . $m['domain'] . ':' . $m['client_id'] . ':' . $m['userid'], 'owner sync: site ' . $m['domain']
                . ' is owned by client #' . $m['client_id'] . ' on the controller but service #' . $m['service'] . ' belongs to client #'
                . $m['userid'] . ' in WHMCS — not changed; check it and set the owner (PATCH /api/v1/sites/{domain}/owner) if the service was moved');
        }
        return self::$report = $r;
    }

    /**
     * Count of live services whose site has no owner, from an already fetched GET /api/v1/sites list
     * (the sync report page). null when the controller predates owners.
     */
    public static function unowned(array $sites): ?int
    {
        $rows = array_values(array_filter($sites, 'is_array'));
        if ($rows && !array_key_exists('client_id', $rows[0])) {
            return null;
        }
        $ix = Data::siteIndex($rows);
        $n = 0;
        foreach (self::services() as $svc) {
            $site = Data::siteFor($svc, $ix);
            if ($site && (int) $svc->userid > 0 && array_key_exists('client_id', $site) && empty($site['client_id'])
                && empty($site['reseller_client_id'])) {
                $n++;
            }
        }
        return $n;
    }

    /** Active / Suspended CDN services. */
    private static function services(): array
    {
        try {
            return Data::serviceQuery()->whereIn('h.domainstatus', self::LIVE)->orderBy('h.id')
                ->get(['h.id', 'h.userid', 'h.domain', 'h.domainstatus', 'h.server'])->all();
        } catch (\Throwable $e) {
            return [];
        }
    }

    /** The service's own Pasargad CDN server, else the addon's server. */
    private static function serverOf($svc)
    {
        return Env::serverById((int) $svc->server) ?: Env::server();
    }

    private static function logOnce(string $key, string $msg): void
    {
        $seen = (array) Env::kvGet('owner_sync_logged', []);
        if (isset($seen[$key])) {
            return;
        }
        $seen[$key] = self::now();
        if (count($seen) > 500) {
            $seen = array_slice($seen, -500, null, true);
        }
        Env::kvSet('owner_sync_logged', $seen);
        Env::log($msg);
    }
}
