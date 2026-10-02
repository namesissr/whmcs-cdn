<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

require_once __DIR__ . '/I18n.php';

if (class_exists(__NAMESPACE__ . '\\ServiceState', false)) {
    return;
}

/**
 * Per-service client-app state kept in WHMCS (growth features, docs/WHMCS.md «رشد»):
 *
 *  - onboarding: the first-run guide of the overview («راه‌اندازی CDN»). Steps the app can compute from
 *    the site (records, NS, SSL, security, tunnel) are never stored; only what the client said — a manual
 *    «انجام دادم» (realip), skipped optional steps and whether the guide was dismissed.
 *  - report: the opt-in of the scheduled e-mail report (off | weekly | monthly) and when it was chosen,
 *    so the first report only covers a period that ended after the opt-in (addon Reports cron).
 *
 * One row per service in mod_pasargadcdn_service_state (created lazily here and by the addon's
 * Env::ensureTable()). Every read degrades to the defaults when the table cannot be read (the app then
 * keeps its in-browser fallback); every write is validated against fixed whitelists.
 */
class ServiceState
{
    const TABLE = 'mod_pasargadcdn_service_state';
    /** Steps the client may mark done by hand (the app cannot observe them). */
    const MANUAL = ['realip'];
    /** Optional steps the client may skip. */
    const SKIPPABLE = ['security', 'tunnel', 'realip'];
    const FREQS = ['off', 'weekly', 'monthly'];

    /** @var bool|null memo: table present */
    private static $ready = null;

    public static function reset(): void
    {
        self::$ready = null;
    }

    /** Creates the table when missing. Never throws; false when the database refuses. */
    public static function ensure(): bool
    {
        if (self::$ready === true) {
            return true;
        }
        try {
            $schema = Capsule::schema();
            if (!$schema->hasTable(self::TABLE)) {
                $schema->create(self::TABLE, function ($t) {
                    $t->integer('service_id')->primary();
                    $t->text('onboarding')->nullable();          // JSON {done:[], skipped:[], dismissed:bool}
                    $t->string('report_freq', 8)->default('');    // '' | weekly | monthly
                    $t->dateTime('report_since')->nullable();     // opt-in time (first period must end after it)
                    $t->dateTime('updated_at')->nullable();
                    $t->index('report_freq', 'mod_pcdn_sstate_freq');
                });
            }
            return self::$ready = true;
        } catch (\Throwable $e) {
            self::$ready = false;
            return false;
        }
    }

    private static function row(int $sid)
    {
        if ($sid <= 0 || !self::ensure()) {
            return null;
        }
        try {
            return Capsule::table(self::TABLE)->where('service_id', $sid)->first();
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** Normalised onboarding state (defaults when nothing is stored). */
    public static function onboarding(int $sid): array
    {
        $r = self::row($sid);
        $d = $r && is_string($r->onboarding ?? null) ? json_decode((string) $r->onboarding, true) : null;
        return self::cleanOnboarding(is_array($d) ? $d : []);
    }

    public static function cleanOnboarding(array $d): array
    {
        $list = function ($v, array $allowed) {
            $out = [];
            foreach (is_array($v) ? $v : [] as $x) {
                if (is_string($x) && in_array($x, $allowed, true) && !in_array($x, $out, true)) {
                    $out[] = $x;
                }
            }
            return $out;
        };
        return [
            'done' => $list($d['done'] ?? [], self::MANUAL),
            'skipped' => $list($d['skipped'] ?? [], self::SKIPPABLE),
            'dismissed' => !empty($d['dismissed']),
        ];
    }

    /**
     * Applies a client change ({done?: [], skipped?: [], dismissed?: bool}; omitted keys keep their value).
     * @return array|null the stored state, or null when it could not be saved
     */
    public static function saveOnboarding(int $sid, array $patch): ?array
    {
        $cur = self::onboarding($sid);
        foreach (['done', 'skipped', 'dismissed'] as $k) {
            if (array_key_exists($k, $patch)) {
                $cur[$k] = $patch[$k];
            }
        }
        $cur = self::cleanOnboarding($cur);
        return self::upsert($sid, ['onboarding' => json_encode($cur)]) ? $cur : null;
    }

    /** Report opt-in: ['freq' => off|weekly|monthly, 'since' => ?string]. */
    public static function report(int $sid): array
    {
        $r = self::row($sid);
        $f = $r ? (string) ($r->report_freq ?? '') : '';
        return ['freq' => in_array($f, ['weekly', 'monthly'], true) ? $f : 'off', 'since' => $r && $r->report_since ? (string) $r->report_since : null];
    }

    /** @return array|null the stored opt-in, or null when invalid / not saved */
    public static function setReport(int $sid, string $freq): ?array
    {
        if (!in_array($freq, self::FREQS, true)) {
            return null;
        }
        $cur = self::report($sid);
        $row = ['report_freq' => $freq === 'off' ? '' : $freq];
        // a new opt-in (or a changed frequency) restarts the clock: no report for a period that ended before
        if ($freq !== 'off' && $cur['freq'] !== $freq) {
            $row['report_since'] = gmdate('Y-m-d H:i:s'); // UTC, like the report periods
        }
        return self::upsert($sid, $row) ? self::report($sid) : null;
    }

    private static function upsert(int $sid, array $cols): bool
    {
        if ($sid <= 0 || !self::ensure()) {
            return false;
        }
        try {
            Capsule::table(self::TABLE)->updateOrInsert(['service_id' => $sid], $cols + ['updated_at' => date('Y-m-d H:i:s')]);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Last report sent for a service (from the addon's mod_pasargadcdn_reports), or null. */
    public static function lastReport(int $sid): ?array
    {
        try {
            if (!Capsule::schema()->hasTable('mod_pasargadcdn_reports')) {
                return null;
            }
            $r = Capsule::table('mod_pasargadcdn_reports')->where('service_id', $sid)->where('status', 'sent')
                ->orderBy('id', 'desc')->first(['period', 'updated_at']);
            return $r ? ['period' => (string) $r->period, 'at' => (string) $r->updated_at] : null;
        } catch (\Throwable $e) {
            return null;
        }
    }
}
