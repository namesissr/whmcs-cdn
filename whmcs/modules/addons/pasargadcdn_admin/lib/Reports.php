<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\ApiException;
use PasargadCdn\I18n;
use PasargadCdn\ServiceState;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Reports', false)) {
    return;
}

/**
 * Growth — scheduled e-mail reports (per-service opt-in in the client app: weekly | monthly).
 *
 * On every WHMCS cron run (AfterCronJob): no opted-in service → one query, nothing else. Otherwise, for at
 * most BATCH services per run, the report of the period that just closed (previous ISO week, Monday 00:00
 * UTC; previous month) is built from the controller's existing per-site endpoints through ApiClient —
 *   GET /api/v1/sites/{d}                        status, plan, month usage
 *   GET …/analytics?period=7d|30d                requests, traffic, cache hits, security totals, top countries/paths
 *   GET …/sla?month=YYYY-MM                      availability vs target (Wave 6D; omitted when 404 / older)
 *   GET …/tunnel/usage?days=7|30                 tunnel traffic + sessions (Wave 7; only with the tunnel feature)
 * — and e-mailed with the «Pasargad CDN Usage Report» template (Persian default + English translation; WHMCS
 * picks the client's language, the merge fields are written in the same language).
 *
 * Dedupe: one row per (service, period) in mod_pasargadcdn_reports, claimed BEFORE anything is sent; a
 * failed build (controller unreachable, site missing) is retried at most MAX_ATTEMPTS times, an hour apart.
 * The first report only covers a period that ended after the client opted in. Never throws into the cron.
 */
final class Reports
{
    const EMAIL = 'Pasargad CDN Usage Report';
    const BATCH = 25;
    const MAX_ATTEMPTS = 3;
    const RETRY_AFTER = 3600;

    /** @var callable|null tests: fn(): int */
    public static $clock = null;
    /** @var array report of the last run */
    public static $report = [];

    const COUNTRIES = [
        'IR' => ['ایران', 'Iran'], 'DE' => ['آلمان', 'Germany'], 'US' => ['آمریکا', 'United States'], 'NL' => ['هلند', 'Netherlands'],
        'TR' => ['ترکیه', 'Turkey'], 'AE' => ['امارات', 'UAE'], 'GB' => ['انگلستان', 'United Kingdom'], 'FR' => ['فرانسه', 'France'],
        'RU' => ['روسیه', 'Russia'], 'CN' => ['چین', 'China'], 'CA' => ['کانادا', 'Canada'], 'IQ' => ['عراق', 'Iraq'],
        'AF' => ['افغانستان', 'Afghanistan'], 'SE' => ['سوئد', 'Sweden'], 'FI' => ['فنلاند', 'Finland'],
    ];
    const SECURITY = ['waf' => ['WAF', 'WAF'], 'firewall' => ['فایروال', 'firewall'], 'ratelimit' => ['محدودیت نرخ', 'rate limit'],
        'challenge' => ['چالش', 'challenge'], 'ddos' => ['DDoS', 'DDoS'], 'hotlink' => ['هات‌لینک', 'hotlink'], 'bots' => ['ربات', 'bots']];

    public static function now(): int
    {
        return self::$clock ? (int) (self::$clock)() : time();
    }

    public static function onCron(): void
    {
        try {
            // gate: the wizard created the report template (addon setting report_tpl_on) — else no query at all
            if (!Env::loadServerModule() || (\pasargadcdn_addon_settings()['report_tpl_on'] ?? '') !== 'on'
                || !Env::hasTable('mod_pasargadcdn_service_state')) {
                return;
            }
            if (!Capsule::table('mod_pasargadcdn_service_state')->where('report_freq', '!=', '')->exists()) {
                return;
            }
            self::run();
        } catch (\Throwable $e) {
            Env::log('e-mail report cron error: ' . $e->getMessage());
        }
    }

    /** [period key, start ts, end ts (exclusive)] of the last closed period for $freq at $now. */
    public static function period(string $freq, int $now): array
    {
        if ($freq === 'weekly') {
            $dow = (int) gmdate('N', $now);                           // 1 = Monday
            $end = gmmktime(0, 0, 0, (int) gmdate('n', $now), (int) gmdate('j', $now) - ($dow - 1), (int) gmdate('Y', $now));
            $start = $end - 7 * 86400;
            return ['W' . gmdate('o-W', $start), $start, $end];
        }
        $end = gmmktime(0, 0, 0, (int) gmdate('n', $now), 1, (int) gmdate('Y', $now));
        $start = gmmktime(0, 0, 0, (int) gmdate('n', $end - 86400), 1, (int) gmdate('Y', $end - 86400));
        return ['M' . gmdate('Y-m', $start), $start, $end];
    }

    public static function run(): array
    {
        self::$report = ['sent' => [], 'failed' => [], 'skipped' => []];
        if (!Env::hasTable(Env::REPORTS)) {
            Env::ensureTable();
        }
        $pids = Env::cdnProductIds();
        if (!$pids) {
            return self::$report;
        }
        $now = self::now();
        $rows = Capsule::table('mod_pasargadcdn_service_state as s')->join('tblhosting as h', 'h.id', '=', 's.service_id')
            ->where('s.report_freq', '!=', '')->where('h.domainstatus', 'Active')->whereIn('h.packageid', $pids)
            ->orderBy('s.service_id')->get(['s.service_id', 's.report_freq', 's.report_since', 'h.userid', 'h.domain', 'h.server'])->all();
        $done = 0;
        foreach ($rows as $r) {
            if ($done >= self::BATCH) {
                break;
            }
            $freq = (string) $r->report_freq;
            if (!in_array($freq, ['weekly', 'monthly'], true)) {
                continue;
            }
            [$key, $start, $end] = self::period($freq, $now);
            $since = $r->report_since ? strtotime((string) $r->report_since . ' UTC') : false;
            if ($since !== false && $since > $end) {
                continue; // opted in after this period closed: the first report is the next one
            }
            $sid = (int) $r->service_id;
            if (!self::claim($sid, $key, $freq, $now)) {
                continue;
            }
            $done++;
            $lang = self::clientLang((int) $r->userid);
            try {
                $vars = self::build($r, $freq, $key, $start, $end, $lang);
                $res = Env::localApi('SendEmail', ['messagename' => self::EMAIL, 'id' => $sid, 'customvars' => base64_encode(serialize($vars))]);
                if (($res['result'] ?? '') !== 'success') {
                    throw new \RuntimeException('SendEmail: ' . ($res['message'] ?? 'error'));
                }
                self::finish($sid, $key, 'sent', null, $lang);
                self::$report['sent'][] = [$sid, $key, $lang];
            } catch (\Throwable $e) {
                self::finish($sid, $key, 'failed', $e->getMessage(), $lang);
                self::$report['failed'][] = [$sid, $key, $e->getMessage()];
                Env::log('e-mail report ' . $key . ' for service #' . $sid . ' failed (retried later): ' . $e->getMessage(), (int) $r->userid);
            }
        }
        return self::$report;
    }

    /** Claims (service, period): a new row, or a failed one due for a retry. False when someone else has it. */
    private static function claim(int $sid, string $key, string $freq, int $now): bool
    {
        $ts = date('Y-m-d H:i:s', $now);
        try {
            Capsule::table(Env::REPORTS)->insert(['service_id' => $sid, 'period' => $key, 'freq' => $freq, 'status' => 'sending',
                'attempts' => 1, 'created_at' => $ts, 'updated_at' => $ts]);
            return true;
        } catch (\Throwable $e) {
            // exists: retry a failed one (at most MAX_ATTEMPTS, an hour apart)
        }
        $row = Capsule::table(Env::REPORTS)->where('service_id', $sid)->where('period', $key)->first();
        if (!$row || (string) $row->status !== 'failed' || (int) $row->attempts >= self::MAX_ATTEMPTS
            || (strtotime((string) $row->updated_at) ?: 0) > $now - self::RETRY_AFTER) {
            self::$report['skipped'][] = [$sid, $key];
            return false;
        }
        return Capsule::table(Env::REPORTS)->where('id', (int) $row->id)->where('status', 'failed')->where('attempts', (int) $row->attempts)
            ->update(['status' => 'sending', 'attempts' => (int) $row->attempts + 1, 'updated_at' => $ts]) === 1;
    }

    private static function finish(int $sid, string $key, string $status, ?string $err, string $lang): void
    {
        Capsule::table(Env::REPORTS)->where('service_id', $sid)->where('period', $key)->update(['status' => $status, 'lang' => $lang,
            'error' => $err === null ? null : mb_substr($err, 0, 191), 'updated_at' => date('Y-m-d H:i:s', self::now())]);
    }

    /** fa | en of a WHMCS client (its saved language, else the system default). */
    public static function clientLang(int $uid): string
    {
        try {
            if (Env::hasColumn('tblclients', 'language')) {
                $l = (string) Capsule::table('tblclients')->where('id', $uid)->value('language');
                if (trim($l) !== '') {
                    return I18n::map($l);
                }
            }
            $d = (string) Capsule::table('tblconfiguration')->where('setting', 'Language')->value('value');
            return trim($d) !== '' ? I18n::map($d) : 'fa';
        } catch (\Throwable $e) {
            return 'fa';
        }
    }

    public static function n($v, string $lang, int $dec = 0): string
    {
        $s = number_format((float) $v, $dec, '.', ',');
        return $lang === 'en' ? $s : View::n((float) $v, $dec);
    }

    public static function date(int $ts, string $lang): string
    {
        return $lang === 'en' ? gmdate('j M Y', $ts) : View::digits(gmdate('Y-m-d', $ts));
    }

    public static function bytes(float $b, string $lang): string
    {
        $u = $lang === 'en' ? ['B', 'KB', 'MB', 'GB', 'TB'] : ['بایت', 'کیلوبایت', 'مگابایت', 'گیگابایت', 'ترابایت'];
        $i = 0;
        while ($b >= 1024 && $i < 4) {
            $b /= 1024;
            $i++;
        }
        return self::n($b, $lang, $i >= 3 ? 1 : 0) . ' ' . $u[$i];
    }

    private static function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Merge fields of one report. Throws when the core data (site + analytics) is unavailable, so the
     * claim is retried; SLA and tunnel sections are optional (older controller / no tunnel → empty).
     */
    public static function build($r, string $freq, string $key, int $start, int $end, string $lang): array
    {
        $en = $lang === 'en';
        $server = Env::serverById((int) $r->server) ?: Env::server();
        $domain = Env::domain((string) $r->domain);
        if (!$server || !Env::validHostname($domain)) {
            throw new \RuntimeException('no CDN server / invalid domain');
        }
        $api = Env::api(10, $server);
        $base = ApiClient::site($domain);
        $site = $api->get($base);
        $features = (array) ($site['plan']['features'] ?? []);
        $slaMonth = gmdate('Y-m', $end - 86400);
        $paths = ['a' => $base . '/analytics?period=' . ($freq === 'weekly' ? '7d' : '30d'), 's' => $base . '/sla?month=' . $slaMonth];
        if (!empty($features['tunnel'])) {
            $paths['t'] = $base . '/tunnel/usage?days=' . ($freq === 'weekly' ? '7' : '30');
        }
        $res = $api->getMany(array_values($paths));
        $a = $res[$paths['a']] ?? null;
        if (!$a || $a['code'] !== 200 || !is_array($a['data'])) {
            throw new ApiException('analytics unavailable (HTTP ' . (int) ($a['code'] ?? 0) . ')');
        }
        $ad = $a['data'];
        $tot = (array) ($ad['totals'] ?? []);
        $req = (int) ($tot['requests'] ?? 0);
        $hits = (int) ($tot['cache_hits'] ?? 0);
        $sec = array_map('intval', array_filter((array) ($tot['security'] ?? []), 'is_numeric'));
        arsort($sec);
        $secTotal = array_sum($sec);
        $secParts = [];
        foreach ($sec as $k => $v) {
            if ($v > 0) {
                $secParts[] = (self::SECURITY[$k][$en ? 1 : 0] ?? $k) . ': ' . self::n($v, $lang);
            }
        }
        $countries = array_slice(array_values(array_filter((array) ($ad['countries'] ?? []), 'is_array')), 0, 5);
        $cLines = [];
        foreach ($countries as $c) {
            $code = strtoupper((string) ($c['code'] ?? ''));
            $name = self::COUNTRIES[$code][$en ? 1 : 0] ?? $code;
            $cLines[] = $name . ' — ' . ($req > 0 ? self::n(round((int) ($c['requests'] ?? 0) * 100 / $req, 1), $lang, 1) . ($en ? '%' : '٪') : self::n((int) ($c['requests'] ?? 0), $lang));
        }
        $pLines = [];
        foreach (array_slice(array_values(array_filter((array) ($ad['paths'] ?? []), 'is_array')), 0, 5) as $p) {
            $path = mb_substr((string) ($p['path'] ?? ''), 0, 80);
            $pLines[] = $path . ' — ' . self::n((int) ($p['requests'] ?? 0), $lang);
        }
        $ul = function (array $lines, bool $ltr = false) {
            if (!$lines) {
                return '';
            }
            $h = '<ul style="margin:4px 0;padding-' . ($ltr ? 'left' : 'right') . ':18px">';
            foreach ($lines as $l) {
                $h .= '<li' . ($ltr ? ' dir="ltr" style="text-align:left"' : '') . '>' . self::e($l) . '</li>';
            }
            return $h . '</ul>';
        };
        $vars = [
            'cdn_report_kind' => $freq === 'weekly' ? ($en ? 'weekly' : 'هفتگی') : ($en ? 'monthly' : 'ماهانه'),
            'cdn_report_period' => self::date($start, $lang) . ' – ' . self::date($end - 86400, $lang),
            'cdn_report_requests' => self::n($req, $lang),
            'cdn_report_traffic' => self::bytes((float) ($tot['bytes'] ?? 0), $lang),
            'cdn_report_cache_ratio' => $req > 0 ? self::n(round($hits * 100 / $req, 1), $lang, 1) . ($en ? '%' : '٪') : '—',
            'cdn_report_threats' => self::n($secTotal, $lang),
            'cdn_report_threats_detail' => self::e(implode($en ? ', ' : '، ', $secParts)),
            'cdn_report_countries_html' => $ul($cLines),
            'cdn_report_paths_html' => $ul($pLines, true),
            'cdn_report_month_traffic' => self::bytes((float) ($site['usage_month']['bytes'] ?? 0), $lang),
            'cdn_report_sla' => '', 'cdn_report_sla_target' => '', 'cdn_report_sla_met' => 0,
            'cdn_report_tunnel' => '', 'cdn_report_tunnel_sessions' => '',
            'cdn_report_status' => (string) ($site['status'] ?? ''),
            'cdn_report_period_key' => $key,
        ];
        $s = isset($paths['s']) ? ($res[$paths['s']] ?? null) : null;
        if ($s && $s['code'] === 200 && is_array($s['data']) && isset($s['data']['availability_pct']) && is_numeric($s['data']['availability_pct'])) {
            $vars['cdn_report_sla'] = self::n((float) $s['data']['availability_pct'], $lang, 2) . ($en ? '%' : '٪');
            $vars['cdn_report_sla_target'] = is_numeric($s['data']['target_pct'] ?? null) ? self::n((float) $s['data']['target_pct'], $lang, 1) . ($en ? '%' : '٪') : '';
            $vars['cdn_report_sla_met'] = !empty($s['data']['met']) ? 1 : 0;
        }
        $t = isset($paths['t']) ? ($res[$paths['t']] ?? null) : null;
        if ($t && $t['code'] === 200 && is_array($t['data']['days'] ?? null)) {
            $bytes = 0;
            $sess = 0;
            foreach ($t['data']['days'] as $d) {
                $bytes += (int) ($d['bytes_up'] ?? 0) + (int) ($d['bytes_down'] ?? 0);
                $sess += (int) ($d['sessions'] ?? 0);
            }
            if ($bytes > 0 || $sess > 0) {
                $vars['cdn_report_tunnel'] = self::bytes((float) $bytes, $lang);
                $vars['cdn_report_tunnel_sessions'] = self::n($sess, $lang);
            }
        }
        return $vars;
    }
}
