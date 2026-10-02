<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

require_once __DIR__ . '/I18n.php';

if (class_exists(__NAMESPACE__ . '\\Trial', false)) {
    return;
}

/**
 * Free trial (growth features, docs/WHMCS.md «پلن آزمایشی»): one «CDN آزمایشی» product created by the
 * admin wizard (free, N days, small bandwidth cap, tunnel off). Shared by the provisioning module
 * (CreateAccount registers the trial, ChangePackage notices the upgrade, the client app shows the
 * upgrade CTA) and the admin addon (checkout rules, reminder / end-of-trial cron).
 *
 * Config: mod_pasargadcdn_settings k='trial' (written by the wizard):
 *   {pid, days, gb, remind (days before the end), end: pause|suspend|terminate, terminate_after (days, 0 = never)}
 * Registry: mod_pasargadcdn_trials — one row per trial service: who (userid, e-mail), which domain,
 *   when it started/ends and its state (active → reminded → paused|suspended → terminated, or upgraded/closed).
 *   A client, an e-mail address and a domain get ONE trial ever: hadTrial() checks the registry and every
 *   tblhosting row on the trial product (also for services created before the registry existed).
 *
 * End actions: «pause» suspends the site on the CDN only (the WHMCS service stays Active, so the client can
 * still upgrade it in place and keep its configuration — ChangePackage unpauses it); «suspend» runs WHMCS's
 * ModuleSuspend; «terminate» runs ModuleTerminate. Everything here is best effort and never throws.
 */
class Trial
{
    const TABLE = 'mod_pasargadcdn_trials';
    const ENDS = ['pause', 'suspend', 'terminate'];
    const DEFAULTS = ['pid' => 0, 'days' => 7, 'gb' => 5, 'remind' => 2, 'end' => 'pause', 'terminate_after' => 14];
    const LIVE = ['active', 'reminded'];

    /** @var array|null|false memo of the config (false = not loaded) */
    private static $cfg = false;
    /** @var bool|null */
    private static $ready = null;
    /** @var callable|null tests: fn(): int */
    public static $clock = null;

    public static function now(): int
    {
        return self::$clock ? (int) (self::$clock)() : time();
    }

    public static function reset(): void
    {
        self::$cfg = false;
        self::$ready = null;
    }

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
                    $t->integer('userid');
                    $t->string('email', 191)->default('');
                    $t->string('domain', 253)->default('');
                    $t->integer('pid')->default(0);
                    $t->dateTime('started_at')->nullable();
                    $t->dateTime('ends_at')->nullable();
                    $t->string('status', 16)->default('active'); // active|reminded|paused|suspended|terminated|upgraded|closed
                    $t->dateTime('reminded_at')->nullable();
                    $t->dateTime('ended_at')->nullable();
                    $t->dateTime('created_at')->nullable();
                    $t->dateTime('updated_at')->nullable();
                    $t->index('userid', 'mod_pcdn_trial_user');
                    $t->index('email', 'mod_pcdn_trial_email');
                    $t->index('domain', 'mod_pcdn_trial_domain');
                    $t->index('status', 'mod_pcdn_trial_status');
                });
            }
            return self::$ready = true;
        } catch (\Throwable $e) {
            self::$ready = false;
            return false;
        }
    }

    /** Trial config, or null when the wizard has not created a trial product. */
    public static function config(): ?array
    {
        if (self::$cfg !== false) {
            return self::$cfg;
        }
        self::$cfg = null;
        try {
            $v = Capsule::table('mod_pasargadcdn_settings')->where('k', 'trial')->value('v');
            $d = is_string($v) ? json_decode($v, true) : null;
            if (is_array($d) && (int) ($d['pid'] ?? 0) > 0) {
                self::$cfg = self::clean($d);
            }
        } catch (\Throwable $e) {
            self::$cfg = null;
        }
        return self::$cfg;
    }

    /** Validated config values (wizard input and stored value alike). */
    public static function clean(array $d): array
    {
        $c = self::DEFAULTS;
        $c['pid'] = max(0, (int) ($d['pid'] ?? 0));
        $c['days'] = min(90, max(1, (int) ($d['days'] ?? $c['days'])));
        $c['gb'] = min(1000, max(1, (int) ($d['gb'] ?? $c['gb'])));
        $c['remind'] = min($c['days'], max(0, (int) ($d['remind'] ?? $c['remind'])));
        $c['end'] = in_array($d['end'] ?? '', self::ENDS, true) ? (string) $d['end'] : 'pause';
        $c['terminate_after'] = min(365, max(0, (int) ($d['terminate_after'] ?? $c['terminate_after'])));
        return $c;
    }

    public static function pid(): int
    {
        $c = self::config();
        return $c ? (int) $c['pid'] : 0;
    }

    public static function isTrialPid(int $pid): bool
    {
        return $pid > 0 && $pid === self::pid();
    }

    public static function normDomain(string $d): string
    {
        $d = strtolower(trim($d));
        $d = (string) preg_replace('#^[a-z][a-z0-9+.-]*://#', '', $d);
        $d = (string) preg_replace('#[/?\#:].*$#', '', $d);
        return (string) preg_replace('/^www\./', '', rtrim($d, '.'));
    }

    /** Registry row of a service, or null. */
    public static function row(int $sid)
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

    /**
     * Registers a trial service (idempotent). $start: unix time the trial started (default now);
     * the end is start + config days. Returns the row or null.
     */
    public static function register(int $sid, int $userid, string $domain, ?int $start = null)
    {
        $c = self::config();
        if (!$c || $sid <= 0 || !self::ensure()) {
            return null;
        }
        $row = self::row($sid);
        if ($row) {
            return $row;
        }
        $start = $start ?? self::now();
        $email = '';
        try {
            $email = strtolower(trim((string) Capsule::table('tblclients')->where('id', $userid)->value('email')));
        } catch (\Throwable $e) {
            $email = '';
        }
        $now = date('Y-m-d H:i:s', self::now());
        try {
            Capsule::table(self::TABLE)->insert(['service_id' => $sid, 'userid' => $userid, 'email' => substr($email, 0, 191),
                'domain' => substr(self::normDomain($domain), 0, 253), 'pid' => $c['pid'],
                'started_at' => date('Y-m-d H:i:s', $start), 'ends_at' => date('Y-m-d H:i:s', $start + $c['days'] * 86400),
                'status' => 'active', 'created_at' => $now, 'updated_at' => $now]);
        } catch (\Throwable $e) {
            // a parallel run inserted it first
        }
        return self::row($sid);
    }

    /**
     * Has this client / e-mail / domain had a trial before (any state)? Checks the registry and the
     * services on the trial product. Returns the reason ('client' | 'email' | 'domain') or null.
     * $exceptService: the service being checked itself (never counts against itself).
     */
    public static function hadTrial(int $userid, string $email, string $domain, int $exceptService = 0): ?string
    {
        $c = self::config();
        if (!$c) {
            return null;
        }
        $email = strtolower(trim($email));
        $domain = self::normDomain($domain);
        try {
            if (self::ensure()) {
                $q = function () use ($exceptService) {
                    return Capsule::table(self::TABLE)->where('service_id', '!=', $exceptService);
                };
                if ($userid > 0 && $q()->where('userid', $userid)->exists()) {
                    return 'client';
                }
                if ($email !== '' && $q()->where('email', $email)->exists()) {
                    return 'email';
                }
                if ($domain !== '' && $q()->where('domain', $domain)->exists()) {
                    return 'domain';
                }
            }
            // services on the trial product (also those older than the registry), any status
            $svc = function () use ($c, $exceptService) {
                return Capsule::table('tblhosting')->where('packageid', $c['pid'])->where('id', '!=', $exceptService);
            };
            if ($userid > 0 && $svc()->where('userid', $userid)->exists()) {
                return 'client';
            }
            if ($email !== '') {
                $uids = Capsule::table('tblclients')->whereRaw('LOWER(email) = ?', [$email])->pluck('id')->all();
                if ($uids && $svc()->whereIn('userid', array_map('intval', $uids))->exists()) {
                    return 'email';
                }
            }
            if ($domain !== '') {
                foreach ($svc()->where('domain', 'like', '%' . $domain . '%')->pluck('domain')->all() as $d) {
                    if (self::normDomain((string) $d) === $domain) {
                        return 'domain';
                    }
                }
            }
        } catch (\Throwable $e) {
            return null; // never block a sale on a database hiccup
        }
        return null;
    }

    /**
     * Client-app view of a trial service (boot.trial), or null for any other service.
     * $svc: ['serviceid', 'pid', 'userid', 'regdate'?, 'currency'?]
     */
    public static function boot(array $svc): ?array
    {
        $c = self::config();
        $sid = (int) ($svc['serviceid'] ?? 0);
        $pid = (int) ($svc['pid'] ?? 0);
        if (!$c || $sid <= 0 || $pid !== (int) $c['pid']) {
            return null;
        }
        $row = self::row($sid);
        if ($row) {
            $start = strtotime((string) $row->started_at) ?: self::now();
            $end = strtotime((string) $row->ends_at) ?: ($start + $c['days'] * 86400);
            $status = (string) $row->status;
        } else {
            if (!isset($svc['regdate'])) {
                try {
                    $svc['regdate'] = (string) Capsule::table('tblhosting')->where('id', $sid)->value('regdate');
                } catch (\Throwable $e) {
                    $svc['regdate'] = '';
                }
            }
            $reg = $svc['regdate'] !== '' ? strtotime((string) $svc['regdate']) : false;
            $start = $reg ?: self::now();
            $end = $start + $c['days'] * 86400;
            $status = 'active';
        }
        $left = max(0, (int) ceil(($end - self::now()) / 86400));
        return [
            'days' => (int) $c['days'], 'days_left' => $left, 'ends_at' => gmdate('Y-m-d\TH:i:s\Z', $end),
            'ended' => $end <= self::now() || !in_array($status, self::LIVE, true), 'status' => $status,
            'gb' => (int) $c['gb'], 'end' => $c['end'],
            'paid' => self::paidProducts($pid, $sid, (int) ($svc['currency'] ?? 0)),
        ];
    }

    /**
     * Paid products the trial upgrades to (the trial product's upgrade paths, else the wizard's plans),
     * with the monthly (else first enabled) price in the client's currency and the WHMCS upgrade URL.
     */
    public static function paidProducts(int $trialPid, int $sid, int $currency = 0): array
    {
        $out = [];
        try {
            $ids = [];
            if (Capsule::schema()->hasTable('tblproduct_upgrade_products')) {
                $ids = array_map('intval', Capsule::table('tblproduct_upgrade_products')->where('product_id', $trialPid)->pluck('upgrade_product_id')->all());
            }
            if (!$ids) {
                $v = Capsule::table('mod_pasargadcdn_settings')->where('k', 'wizard_pids')->value('v');
                $map = is_string($v) ? json_decode($v, true) : [];
                $ids = is_array($map) ? array_values(array_map('intval', $map)) : [];
            }
            $ids = array_values(array_unique(array_filter($ids, function ($id) use ($trialPid) {
                return $id > 0 && $id !== $trialPid;
            })));
            if (!$ids) {
                return [];
            }
            $cur = $currency > 0 ? Capsule::table('tblcurrencies')->where('id', $currency)->first(['id', 'code', 'prefix', 'suffix']) : null;
            if (!$cur) {
                $cur = Capsule::table('tblcurrencies')->orderBy('default', 'desc')->orderBy('id')->first(['id', 'code', 'prefix', 'suffix']);
            }
            $rows = Capsule::table('tblproducts')->whereIn('id', $ids)->where('servertype', 'pasargadcdn')
                ->where('retired', 0)->orderBy('order')->orderBy('id')->get(['id', 'name', 'configoption1'])->all();
            foreach ($rows as $p) {
                $price = null;
                $cycle = null;
                if ($cur) {
                    $pr = Capsule::table('tblpricing')->where('type', 'product')->where('relid', (int) $p->id)->where('currency', (int) $cur->id)->first();
                    if ($pr) {
                        foreach (['monthly', 'quarterly', 'semiannually', 'annually'] as $cy) {
                            if (isset($pr->{$cy}) && (float) $pr->{$cy} >= 0) {
                                $price = (float) $pr->{$cy};
                                $cycle = $cy;
                                break;
                            }
                        }
                    }
                }
                $out[] = ['pid' => (int) $p->id, 'name' => (string) $p->name, 'gb' => (int) $p->configoption1, 'price' => $price,
                    'cycle' => $cycle, 'currency' => $cur ? (trim((string) $cur->suffix) !== '' ? trim((string) $cur->suffix) : (string) $cur->code) : '',
                    'url' => self::upgradeUrl($sid, (int) $p->id, $cycle ?: 'monthly')];
            }
        } catch (\Throwable $e) {
            return $out;
        }
        return array_slice($out, 0, 6);
    }

    /** WHMCS package-upgrade URL (relative to the WHMCS root) preselecting the new product and cycle. */
    public static function upgradeUrl(int $sid, int $pid = 0, string $cycle = 'monthly'): string
    {
        $u = 'upgrade.php?type=package&id=' . $sid;
        return $pid > 0 ? $u . '&step=2&pid=' . $pid . '&billingcycle=' . rawurlencode($cycle) : $u;
    }

    /**
     * ChangePackage of a trial service: once it moved to another product it is no longer a trial —
     * mark it upgraded and, when the trial had been paused on the CDN, report that it must be unpaused.
     * @return bool true when the caller should POST /unsuspend
     */
    public static function onChangePackage(int $sid, int $newPid): bool
    {
        $c = self::config();
        if (!$c || $sid <= 0 || $newPid <= 0 || $newPid === (int) $c['pid']) {
            return false;
        }
        $row = self::row($sid);
        if (!$row || in_array((string) $row->status, ['upgraded', 'terminated', 'closed'], true)) {
            return false;
        }
        $paused = (string) $row->status === 'paused';
        try {
            Capsule::table(self::TABLE)->where('service_id', $sid)->update(['status' => 'upgraded', 'pid' => $newPid,
                'updated_at' => date('Y-m-d H:i:s', self::now())]);
        } catch (\Throwable $e) {
            return false;
        }
        return $paused;
    }
}
