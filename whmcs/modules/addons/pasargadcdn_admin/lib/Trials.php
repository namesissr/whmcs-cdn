<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use PasargadCdn\Trial;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Trials', false)) {
    return;
}

/**
 * Growth — free trial lifecycle on the WHMCS cron (AfterCronJob). Cheap when no trial product exists
 * (one memoised settings read). Otherwise:
 *  1. backfill: every Active/Suspended service on the trial product without a registry row is registered
 *     with its WHMCS regdate as the start (e.g. created before the addon upgrade or by an admin);
 *  2. reminder: once per trial, `remind` days before the end, e-mail «Pasargad CDN Trial Ending»;
 *  3. end: once the end passes — pause on the CDN (WHMCS stays Active, in-place upgrade still possible),
 *     ModuleSuspend or ModuleTerminate per the wizard's end action — and e-mail «Pasargad CDN Trial Ended»;
 *  4. after `terminate_after` days paused/suspended: ModuleTerminate.
 * Services already moved to another product are marked upgraded; terminated/cancelled ones closed.
 * Every state change is claimed with a conditional UPDATE (status = old) first, so parallel crons never
 * act twice. Errors are logged and never thrown into WHMCS's cron.
 */
final class Trials
{
    const EMAIL_ENDING = 'Pasargad CDN Trial Ending';
    const EMAIL_ENDED = 'Pasargad CDN Trial Ended';
    const BATCH = 100;

    /** @var array report of the last run (tests / admin) */
    public static $report = [];

    public static function onCron(): void
    {
        try {
            // the wizard mirrors the trial product id into the addon settings: no trial → no query beyond the
            // settings read the prepaid pass already memoised
            if (!Env::loadServerModule() || (int) (\pasargadcdn_addon_settings()['trial_pid'] ?? 0) <= 0 || !Trial::config()) {
                return;
            }
            self::run();
        } catch (\Throwable $e) {
            Env::log('trial cron error: ' . $e->getMessage());
        }
    }

    public static function run(): array
    {
        self::$report = ['registered' => [], 'reminded' => [], 'ended' => [], 'terminated' => [], 'upgraded' => [], 'closed' => [], 'errors' => []];
        $c = Trial::config();
        if (!$c || !Trial::ensure()) {
            return self::$report;
        }
        $now = Trial::now();
        // 1. backfill
        $known = Capsule::table(Trial::TABLE)->pluck('service_id')->all();
        $rows = Capsule::table('tblhosting')->where('packageid', $c['pid'])->whereIn('domainstatus', ['Active', 'Suspended'])
            ->whereNotIn('id', $known ?: [0])->limit(self::BATCH)->get(['id', 'userid', 'domain', 'regdate'])->all();
        foreach ($rows as $h) {
            $start = $h->regdate ? strtotime((string) $h->regdate) : false;
            if (Trial::register((int) $h->id, (int) $h->userid, (string) $h->domain, $start ?: $now)) {
                self::$report['registered'][] = (int) $h->id;
            }
        }
        // 2–4
        $live = Capsule::table(Trial::TABLE)->whereIn('status', ['active', 'reminded', 'paused', 'suspended'])
            ->orderBy('ends_at')->limit(self::BATCH * 5)->get()->all();
        foreach ($live as $t) {
            try {
                self::one($t, $c, $now);
            } catch (\Throwable $e) {
                self::$report['errors'][] = '#' . (int) $t->service_id . ': ' . $e->getMessage();
                Env::log('trial cron: service #' . (int) $t->service_id . ' failed: ' . $e->getMessage());
            }
        }
        return self::$report;
    }

    /** Moves one trial from $from to $to; false when another run already did. */
    private static function claim(int $sid, string $from, array $set): bool
    {
        return Capsule::table(Trial::TABLE)->where('service_id', $sid)->where('status', $from)
            ->update($set + ['updated_at' => date('Y-m-d H:i:s', Trial::now())]) === 1;
    }

    private static function one($t, array $c, int $now): void
    {
        $sid = (int) $t->service_id;
        $status = (string) $t->status;
        $h = Capsule::table('tblhosting')->where('id', $sid)->first(['id', 'userid', 'packageid', 'domain', 'domainstatus', 'server']);
        if (!$h || in_array((string) $h->domainstatus, ['Terminated', 'Cancelled', 'Fraud'], true)) {
            if (self::claim($sid, $status, ['status' => $h && $h->domainstatus === 'Terminated' && in_array($status, ['paused', 'suspended'], true) ? 'terminated' : 'closed'])) {
                self::$report['closed'][] = $sid;
            }
            return;
        }
        if ((int) $h->packageid !== (int) $c['pid']) {
            // upgraded through WHMCS (ChangePackage normally marks it already)
            if (self::claim($sid, $status, ['status' => 'upgraded', 'pid' => (int) $h->packageid])) {
                self::$report['upgraded'][] = $sid;
                if ($status === 'paused') {
                    self::controller($h, 'unsuspend');
                }
            }
            return;
        }
        $end = strtotime((string) $t->ends_at) ?: $now;
        if (in_array($status, ['active', 'reminded'], true) && $now >= $end) {
            $action = $c['end'];
            $to = ['pause' => 'paused', 'suspend' => 'suspended', 'terminate' => 'terminated'][$action];
            if (!self::claim($sid, $status, ['status' => $to, 'ended_at' => date('Y-m-d H:i:s', $now)])) {
                return;
            }
            $ok = $action === 'pause' ? self::controller($h, 'suspend')
                : self::module($action === 'suspend' ? 'ModuleSuspend' : 'ModuleTerminate', $sid);
            if (!$ok) {
                // put it back: retried on the next cron run
                Capsule::table(Trial::TABLE)->where('service_id', $sid)->update(['status' => $status, 'ended_at' => null]);
                self::$report['errors'][] = '#' . $sid . ': end action ' . $action . ' failed';
                return;
            }
            self::$report['ended'][] = [$sid, $action];
            self::mail(self::EMAIL_ENDED, $sid, $c, $end, $action);
            Env::log('free trial of service #' . $sid . ' ended (' . $action . ')', (int) $h->userid);
            return;
        }
        if ($status === 'active' && $c['remind'] > 0 && $now >= $end - $c['remind'] * 86400) {
            if (self::claim($sid, 'active', ['status' => 'reminded', 'reminded_at' => date('Y-m-d H:i:s', $now)])) {
                self::$report['reminded'][] = $sid;
                self::mail(self::EMAIL_ENDING, $sid, $c, $end, $c['end']);
            }
            return;
        }
        if (in_array($status, ['paused', 'suspended'], true) && $c['terminate_after'] > 0) {
            $ended = strtotime((string) $t->ended_at) ?: $end;
            if ($now >= $ended + $c['terminate_after'] * 86400 && self::claim($sid, $status, ['status' => 'terminated'])) {
                if (self::module('ModuleTerminate', $sid)) {
                    self::$report['terminated'][] = $sid;
                    Env::log('free trial service #' . $sid . ' terminated ' . $c['terminate_after'] . ' days after the trial ended', (int) $h->userid);
                } else {
                    Capsule::table(Trial::TABLE)->where('service_id', $sid)->update(['status' => $status]);
                    self::$report['errors'][] = '#' . $sid . ': terminate failed';
                }
            }
        }
    }

    /** Suspend / unsuspend the site on the CDN only (end action «pause»). */
    private static function controller($h, string $op): bool
    {
        try {
            $server = Env::serverById((int) $h->server) ?: Env::server();
            $domain = Env::domain((string) $h->domain);
            if (!$server || !Env::validHostname($domain)) {
                return false;
            }
            Env::api(15, $server)->post(ApiClient::site($domain) . '/' . $op);
            return true;
        } catch (\Throwable $e) {
            self::$report['errors'][] = $op . ' ' . (string) $h->domain . ': ' . $e->getMessage();
            return false;
        }
    }

    private static function module(string $cmd, int $sid): bool
    {
        $args = ['serviceid' => $sid];
        if ($cmd === 'ModuleSuspend') {
            $args['suspendreason'] = 'Free CDN trial ended';
        }
        $r = Env::localApi($cmd, $args);
        if (($r['result'] ?? '') !== 'success') {
            self::$report['errors'][] = $cmd . ' #' . $sid . ': ' . ($r['message'] ?? '');
            return false;
        }
        return true;
    }

    /** E-mail with the trial merge fields (the client's language picks the template translation in WHMCS). */
    private static function mail(string $tpl, int $sid, array $c, int $end, string $action): void
    {
        $uid = (int) Capsule::table('tblhosting')->where('id', $sid)->value('userid');
        $lang = Reports::clientLang($uid);
        $left = max(0, (int) ceil(($end - Trial::now()) / 86400));
        $vars = [
            'cdn_trial_days' => Reports::n($c['days'], $lang),
            'cdn_trial_days_left' => Reports::n($left, $lang),
            'cdn_trial_end_date' => Reports::date($end, $lang),
            'cdn_trial_gb' => Reports::n($c['gb'], $lang),
            'cdn_trial_action' => $action,
            'cdn_trial_paused' => $action === 'pause' ? 1 : 0,
            'cdn_trial_upgrade_path' => Trial::upgradeUrl($sid),
        ];
        $r = Env::localApi('SendEmail', ['messagename' => $tpl, 'id' => $sid, 'customvars' => base64_encode(serialize($vars))]);
        if (($r['result'] ?? '') !== 'success') {
            Env::log('trial e-mail «' . $tpl . '» for service #' . $sid . ' failed: ' . ($r['message'] ?? ''), $uid);
        }
    }
}
