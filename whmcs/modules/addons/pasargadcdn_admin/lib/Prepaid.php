<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Prepaid', false)) {
    return;
}

/**
 * Prepaid (wallet) traffic billing — the default billing mode.
 *
 *  - Each prepaid service's controller cap = plan GB + traffic blocks bought this month.
 *  - Plan GB = the same effective bandwidth pasargadcdn_plan() sends (a «Bandwidth» configurable
 *    option wins; read for all services with one query per run).
 *  - Margin = max(max(1 GB, min(5 % of the cap, one block)), recent rate × 15 min), the rate part
 *    capped at the blocks still allowed this month; rates are tracked for services ≥ 70 % of cap.
 *  - When month usage comes within the margin of the cap and the
 *    client's credit balance covers a block, blocks are bought: an invoice «ترافیک اضافه CDN …»
 *    is created and paid from credit, recorded in mod_pasargadcdn_topups, and the cap is raised.
 *  - Credit too low → nothing is bought; the controller cuts the site at the cap and the
 *    client gets ONE «Traffic Exhausted» email per service per month (and optionally one
 *    early «Traffic Warning» at 90 %).
 *  - After an Add Funds payment (InvoicePaid) or any credit change (cron) the same logic runs
 *    again, so the site reconnects as soon as the wallet covers a block; unpaid CDN-only
 *    invoices of that client are paid from credit (oldest first, only when fully covered).
 *  - First run of a new month: every prepaid cap goes back to plan GB.
 */
final class Prepaid
{
    const ITEM_TYPE = 'PasargadCdnTopup';
    /** = StorageBilling::ITEM_TYPE (kept here so renewals() needs no other class) */
    const STORAGE_ITEM_TYPE = 'PasargadCdnStorage';
    const RESELLER_ITEM_TYPE = 'PasargadCdnResellerTopup';
    const TPL_RESELLER_EXHAUSTED = 'Pasargad CDN Reseller Traffic Exhausted';
    const TPL_EXHAUSTED = 'Pasargad CDN Traffic Exhausted';
    const TPL_WARNING = 'Pasargad CDN Traffic Warning';
    const TPL_FORECAST = 'Pasargad CDN Traffic Forecast';
    const WARN_RATIO = 0.9;
    /** services at ≥ 70 % of their cap (or cut) have their usage rate tracked */
    const OBSERVE_RATIO = 0.7;
    /** buy far enough ahead to cover this many seconds at the recent usage rate (≈ 3 cron runs) */
    const LOOKAHEAD = 900;
    /** a previous observation older than this (or younger than MIN_DT) gives no usable rate */
    const MAX_DT = 7200;
    const MIN_DT = 60;

    /** @var callable|null tests: fn(): int (unix time) */
    public static $clock = null;
    /** @var array|null configurable option values of the run's services [sid => [name => value]] */
    private static $co = null;

    /** @var bool re-entrancy guard (CreateInvoice/ApplyCredit fire InvoicePaid inside a run) */
    private static $running = false;
    /** @var array report of the last run (tests / admin) */
    public static $report = [];

    // ------------------------------------------------------------------ entry points

    /** AfterCronJob: every service, month rollover, renewals. Never throws. */
    public static function onCron(): void
    {
        try {
            if (!self::enabled()) {
                return;
            }
            self::run(null);
        } catch (\Throwable $e) {
            Env::log('prepaid cron error: ' . $e->getMessage());
        }
        // §10.5 reseller wholesale billing — a fully independent, additive pass over the
        // reseller ledger. It never touches the per-service engine above.
        try {
            if (self::enabled()) {
                self::processResellers(null);
            }
        } catch (\Throwable $e) {
            Env::log('reseller prepaid cron error: ' . $e->getMessage());
        }
    }

    /** InvoicePaid: top-up invoices raise the cap; Add Funds invoices re-run the client's services. Never throws. */
    public static function onInvoicePaid(int $invoiceId): void
    {
        if ($invoiceId <= 0) {
            return;
        }
        try {
            $items = Capsule::table('tblinvoiceitems')->where('invoiceid', $invoiceId)->get(['id', 'type', 'userid', 'relid', 'amount'])->all();
            $types = array_map(function ($i) {
                return (string) $i->type;
            }, $items);
            $topup = in_array(self::ITEM_TYPE, $types, true);
            $rtopup = in_array(self::RESELLER_ITEM_TYPE, $types, true);
            $funds = in_array('AddFunds', $types, true);
            // Wave 7 (SPEC §15.7): «بسته‌ی ترافیک افزوده» add-on lines raise the cap in every billing mode
            $addons = array_values(array_filter($items, function ($i) {
                return (string) $i->type === 'Addon';
            }));
            if ($addons && class_exists(__NAMESPACE__ . '\\AddonTraffic')) {
                AddonTraffic::applyItems($invoiceId, $addons);
            }
            if (!$topup && !$rtopup && !$funds) {
                return; // ordinary invoice: one query, nothing else
            }
            if (!self::enabled()) {
                return;
            }
            self::tables();
            if ($topup) {
                self::markInvoicePaid($invoiceId);
            }
            if ($rtopup) {
                self::markResellerInvoicePaid($invoiceId);
            }
            if ($funds && !self::$running && $items) {
                self::run((int) $items[0]->userid);
                // A wallet top-up may also reconnect the client's reseller sub-sites.
                try {
                    self::processResellers((int) $items[0]->userid);
                } catch (\Throwable $e) {
                    Env::log('reseller InvoicePaid #' . $invoiceId . ' error: ' . $e->getMessage());
                }
            }
        } catch (\Throwable $e) {
            Env::log('prepaid InvoicePaid #' . $invoiceId . ' error: ' . $e->getMessage());
        }
    }

    /** Server module loaded, prepaid mode on, tables present (created on demand). */
    public static function enabled(): bool
    {
        return Env::loadServerModule() && \pasargadcdn_billing_mode() === 'prepaid';
    }

    private static function tables(): void
    {
        if (!Env::hasTable(Env::TOPUPS) || !Env::hasTable(Env::NOTICES) || !Env::hasTable(Env::USAGE)
            || !Env::hasTable(Env::RESELLER_TOPUPS) || !Env::hasTable(Env::RESELLER_SITES)) {
            Env::ensureTable();
        }
    }

    // ------------------------------------------------------------------ the run

    /**
     * @param int|null $userId only this client's services (Add Funds), or all (cron)
     * @return array report
     */
    public static function run(?int $userId): array
    {
        self::$report = ['purchases' => [], 'notices' => [], 'renewals' => [], 'patched' => [], 'errors' => [], 'rollover' => 0, 'rates' => []];
        if (self::$running) {
            return self::$report;
        }
        self::$running = true;
        try {
            $pids = Env::cdnProductIds();
            if (!$pids) {
                return self::$report;
            }
            self::tables();
            // configurable options («Bandwidth» etc.) of every live CDN service in scope: ONE query per run
            self::$co = \pasargadcdn_config_options(function ($q) use ($pids, $userId) {
                $q->select('id')->from('tblhosting')->whereIn('packageid', $pids)->whereIn('domainstatus', ['Active', 'Suspended']);
                if ($userId !== null) {
                    $q->where('userid', $userId);
                }
            });
            if ($userId === null) {
                self::$report['rollover'] = self::rollover($pids);
                Env::kvSet('prepaid_last_run', time());
            }
            // renewals first: a suspended service comes back before any traffic is bought
            self::$report['renewals'] = self::renewals($pids, $userId);
            $cands = self::candidates($pids, $userId);
            if ($cands) {
                self::process($cands);
            }
        } finally {
            self::$running = false;
            self::$co = null;
        }
        return self::$report;
    }

    /** Configurable option values of one service (batched during a run). */
    private static function co(int $sid): array
    {
        if (self::$co !== null) {
            return self::$co[$sid] ?? [];
        }
        return \pasargadcdn_config_options([$sid])[$sid] ?? [];
    }

    private static function now(): int
    {
        return self::$clock ? (int) (self::$clock)() : time();
    }

    /** Active prepaid CDN services (optionally of one client) with product + client facts. */
    private static function candidates(array $pids, ?int $userId): array
    {
        $q = Capsule::table('tblhosting as h')->join('tblproducts as p', 'p.id', '=', 'h.packageid')
            ->join('tblclients as c', 'c.id', '=', 'h.userid')
            ->whereIn('h.packageid', $pids)->where('h.domainstatus', 'Active');
        if ($userId !== null) {
            $q->where('h.userid', $userId);
        }
        $out = [];
        foreach ($q->get(['h.id', 'h.userid', 'h.server', 'h.domain', 'p.id as pid', 'p.configoption1', 'p.overagesenabled',
            'p.overagesbwlimit', 'p.overagesbwprice', 'p.tax', 'c.currency'])->all() as $r) {
            $pp = \pasargadcdn_prepaid(['id' => $r->pid] + (array) $r, self::co((int) $r->id));
            if ($pp !== null) {
                $r->pp = $pp;
                $out[(int) $r->id] = $r;
            }
        }
        return $out;
    }

    private static function process(array $cands): void
    {
        $month = \pasargadcdn_month();
        // controller usage: one GET per server
        $usage = [];
        $byServer = [];
        foreach ($cands as $c) {
            $byServer[(int) $c->server][] = (int) $c->id;
        }
        foreach (array_keys($byServer) as $sid) {
            $server = Capsule::table('tblservers')->where('id', $sid)->first();
            if (!$server || $server->type !== 'pasargadcdn') {
                continue;
            }
            try {
                $data = Env::api(10, $server)->get('/api/v1/usage?month=' . $month);
            } catch (\Throwable $e) {
                self::$report['errors'][] = 'usage: ' . $e->getMessage();
                Env::log('prepaid: controller usage unavailable (' . $e->getMessage() . ') — nothing bought this run');
                continue;
            }
            foreach ((array) ($data['sites'] ?? []) as $s) {
                $ext = (string) ($s['external_id'] ?? '');
                if ($ext !== '' && ctype_digit($ext) && isset($cands[(int) $ext])
                    && strtolower((string) ($s['domain'] ?? '')) === Env::domain((string) $cands[(int) $ext]->domain)) {
                    $usage[(int) $ext] = $s + ['_server' => $server];
                }
            }
        }
        if (!$usage) {
            return;
        }
        $tops = self::monthTopups(array_keys($usage), $month);
        // services near their cap: usage-rate history (one read query; one upsert per observed service)
        $observe = [];
        foreach ($usage as $sid => $site) {
            $t = $tops[$sid] ?? ['paid_gb' => 0, 'blocks' => 0];
            $cap = $cands[$sid]->pp['plan_gb'] + $t['paid_gb'];
            $used = (float) ($site['bytes'] ?? 0) / 1073741824;
            if ($used >= $cap * self::OBSERVE_RATIO || ($site['status'] ?? '') === 'over_quota') {
                $observe[] = $sid;
            }
        }
        $prev = $observe ? self::observations($observe) : [];
        foreach ($usage as $sid => $site) {
            $c = $cands[$sid];
            $pp = $c->pp;
            $t = $tops[$sid] ?? ['paid_gb' => 0, 'blocks' => 0];
            $cap = $pp['plan_gb'] + $t['paid_gb'];
            $used = (float) ($site['bytes'] ?? 0) / 1073741824;
            $left = max(0, $pp['max_blocks'] - $t['blocks']);
            // rate-aware margin: cover LOOKAHEAD seconds at the recent rate, never more than the blocks still allowed
            $extra = 0.0;
            if (in_array($sid, $observe, true)) {
                $rate = self::observe($sid, $used, $month, $prev[$sid] ?? null);
                $extra = min($rate * self::LOOKAHEAD, (float) ($left * $pp['block_gb']));
                self::$report['rates'][$sid] = round($rate * 3600, 3);
            }
            // repair a cap that drifted (failed PATCH, month rollover, admin edit)
            if ((int) ($site['bandwidth_limit_gb'] ?? -1) !== $cap) {
                self::patchCap($c, $cap, $site['_server']);
            }
            $margin = max(self::margin($cap, $pp['block_gb']), $extra);
            $cut = ($site['status'] ?? '') === 'over_quota' || $used >= $cap;
            if ($used < $cap - $margin && !$cut) {
                if ($used >= $cap * self::WARN_RATIO) {
                    self::maybeWarn($c, $used, $cap, $t);
                }
                continue;
            }
            // needs traffic: enough blocks that usage is back below the new cap's margin
            $need = self::blocksNeeded($used, $cap, $pp['block_gb'], $extra);
            $bought = 0;
            $reason = '';
            if ($pp['price_per_gb'] === null) {
                $reason = 'noprice';
                self::notice($c, 'noprice', [], false);
            } elseif ($left === 0) {
                $reason = 'limit';
            } else {
                [$credit, $rate] = self::credit((int) $c->userid, (int) $c->currency);
                $blockPrice = round($pp['price_per_gb'] * $pp['block_gb'] * $rate, 2);
                $afford = $blockPrice > 0 ? (int) floor(($credit + 0.00001) / $blockPrice) : 0;
                $buy = min($need, $left, $afford);
                if ($buy > 0) {
                    $bought = self::purchase($c, $buy, $blockPrice, $site['_server'], $month) ? $buy : 0;
                }
                if ($bought < $need) {
                    $reason = $afford < $need && $left >= $need ? 'credit' : ($left < $need ? 'limit' : 'credit');
                }
            }
            $newCap = $cap + $bought * $pp['block_gb'];
            if ($used >= $newCap && $reason !== '') {
                self::exhausted($c, $used, $newCap, $reason);
            } elseif ($reason !== '' && $used >= $newCap * self::WARN_RATIO) {
                self::maybeWarn($c, $used, $newCap, $t);
            }
        }
        // §10.2 smart usage: forecast alert + upgrade suggestion. Read-only w.r.t. billing:
        // runs after all buy/cut decisions and only writes deduped notice markers + emails.
        self::suggest($cands, $usage, $tops, $month);
    }

    // ------------------------------------------------------------------ §10.2 smart usage alerts

    /** Addon setting as a bounded integer. */
    private static function cfgInt(string $key, int $default, int $min, int $max): int
    {
        $v = Env::setting($key, '');
        if ($v === '' || !is_numeric($v)) {
            return $default;
        }
        return max($min, min($max, (int) $v));
    }

    /** Addon setting as a bounded float. */
    private static function cfgFloat(string $key, float $default, float $min, float $max): float
    {
        $v = Env::setting($key, '');
        if ($v === '' || !is_numeric($v)) {
            return $default;
        }
        return max($min, min($max, (float) $v));
    }

    /**
     * Per-service usage forecast + upgrade suggestion. Never touches the cap or the wallet.
     *  - forecast: from the month's average daily rate so far, project the day the plan's
     *    INCLUDED traffic runs out; if that lands ≥ forecast_margin_days before month end,
     *    send ONE «پیش‌بینی اتمام ترافیک» email (deduped per service/month) and flag the banner.
     *  - upgrade: when the service bought more than upgrade_topups blocks this month, or its
     *    usage exceeds included traffic by upgrade_over_ratio, set a deduped marker (no email).
     */
    private static function suggest(array $cands, array $usage, array $tops, string $month): void
    {
        try {
            $ts = self::now();
            if (gmdate('Y-m', $ts) !== $month) {
                return; // only forecast the running month
            }
            $elapsed = (int) gmdate('j', $ts);
            $daysInMonth = (int) gmdate('t', $ts);
            $marginDays = self::cfgInt('forecast_margin_days', 5, 1, 28);
            $kTop = self::cfgInt('upgrade_topups', 3, 0, 1000);
            $overRatio = self::cfgFloat('upgrade_over_ratio', 1.5, 1.0, 100.0);
            $forecastEmail = Env::enabled('forecast_email', true);
            foreach ($usage as $sid => $site) {
                if (!isset($cands[$sid])) {
                    continue;
                }
                $c = $cands[$sid];
                $plan = (float) $c->pp['plan_gb'];
                $used = (float) ($site['bytes'] ?? 0) / 1073741824;
                $t = $tops[$sid] ?? ['paid_gb' => 0, 'blocks' => 0];
                // upgrade suggestion (marker only) — repeated top-ups or well over the included plan
                if ($plan > 0 && ((int) $t['blocks'] > $kTop || $used >= $plan * $overRatio)) {
                    self::notice($c, 'upgrade', [], false);
                }
                // forecast (email + banner) — projected to exhaust the INCLUDED plan early
                if ($forecastEmail && $plan > 0 && $used > 0 && $used < $plan && $elapsed >= 2) {
                    $projDay = $elapsed * $plan / $used; // day of month the included traffic hits zero
                    if ($projDay <= $daysInMonth - $marginDays && $projDay > $elapsed) {
                        $daysLeft = max(1, (int) ceil($projDay - $elapsed));
                        self::notice($c, 'forecast', self::forecastVars($c, $used, $plan, $daysLeft), true);
                    }
                }
            }
        } catch (\Throwable $e) {
            self::$report['errors'][] = 'suggest: ' . $e->getMessage();
            Env::log('prepaid: usage forecast pass failed: ' . $e->getMessage());
        }
    }

    /** Template variables for the «پیش‌بینی اتمام ترافیک» email. */
    private static function forecastVars($c, float $used, float $plan, int $daysLeft): array
    {
        return [
            'cdn_used_gb' => View::n($used, 1),
            'cdn_plan_gb' => View::n($plan),
            'cdn_remaining_gb' => View::n(max(0.0, $plan - $used), 1),
            'cdn_days_left' => View::n($daysLeft),
        ];
    }

    /**
     * Margin before the cap at which blocks are bought: max(1 GB, min(5 % of the cap, one block)).
     * Capped at one block so big plans do not buy many blocks at once.
     */
    public static function margin(float $cap, int $block = 10): float
    {
        return max(1.0, min($cap * 0.05, (float) $block));
    }

    /** Smallest number of blocks after which usage is below (new cap − margin); $extra = rate-aware margin in GB. */
    public static function blocksNeeded(float $used, int $cap, int $block, float $extra = 0.0): int
    {
        $n = 0;
        $c = $cap;
        while ($used >= $c - max(self::margin($c, $block), $extra) && $n < 100000) {
            $n++;
            $c += $block;
        }
        return max(1, $n);
    }

    /** Last usage observation per service: [sid => row(month, gb, observed_at, rate)]. */
    private static function observations(array $sids): array
    {
        $out = [];
        foreach (Capsule::table(Env::USAGE)->whereIn('service_id', $sids)->get() as $r) {
            $out[(int) $r->service_id] = $r;
        }
        return $out;
    }

    /**
     * Records this observation and returns the recent usage rate in GB/s (0 when unknown:
     * first observation, new month, counter went down, or the previous one is older than MAX_DT).
     * Observations closer than MIN_DT to the previous one keep the old baseline and rate.
     */
    private static function observe(int $sid, float $used, string $month, $prev): float
    {
        $now = self::now();
        if ($prev && $prev->month === $month) {
            $dt = $now - (int) $prev->observed_at;
            if ($dt >= 0 && $dt < self::MIN_DT) {
                return max(0.0, (float) $prev->rate);
            }
            $rate = ($dt <= self::MAX_DT && $used >= (float) $prev->gb) ? ($used - (float) $prev->gb) / max(1, $dt) : 0.0;
        } else {
            $rate = 0.0;
        }
        Capsule::table(Env::USAGE)->updateOrInsert(['service_id' => $sid],
            ['month' => $month, 'gb' => round($used, 3), 'observed_at' => $now, 'rate' => round($rate, 9)]);
        return $rate;
    }

    /** service id => ['paid_gb', 'blocks' (paid + pending)] for $month. */
    private static function monthTopups(array $sids, string $month): array
    {
        $out = [];
        foreach (Capsule::table(Env::TOPUPS)->whereIn('service_id', $sids)->where('month', $month)
                     ->whereIn('status', ['paid', 'pending'])->get(['service_id', 'gb', 'blocks', 'status']) as $r) {
            $o = $out[(int) $r->service_id] ?? ['paid_gb' => 0, 'blocks' => 0];
            if ($r->status === 'paid') {
                $o['paid_gb'] += (int) $r->gb;
            }
            $o['blocks'] += (int) $r->blocks;
            $out[(int) $r->service_id] = $o;
        }
        return $out;
    }

    /** [credit in client currency, rate of client currency to default]. */
    private static function credit(int $userId, int $currencyId): array
    {
        $credit = (float) Capsule::table('tblclients')->where('id', $userId)->value('credit');
        $rate = (float) Capsule::table('tblcurrencies')->where('id', $currencyId)->value('rate');
        return [round($credit, 2), $rate > 0 ? $rate : 1.0];
    }

    // ------------------------------------------------------------------ purchase

    private static function purchase($c, int $blocks, float $blockPrice, $server, string $month): bool
    {
        $sid = (int) $c->id;
        $gb = $blocks * $c->pp['block_gb'];
        $amount = round($blocks * $blockPrice, 2);
        $now = date('Y-m-d H:i:s');
        // claim the next purchase slot; a concurrent run claiming the same slot fails on the unique key
        $seq = (int) Capsule::table(Env::TOPUPS)->where('service_id', $sid)->where('month', $month)->max('seq') + 1;
        try {
            $rowId = (int) Capsule::table(Env::TOPUPS)->insertGetId(['service_id' => $sid, 'userid' => (int) $c->userid, 'month' => $month,
                'seq' => $seq, 'blocks' => $blocks, 'gb' => $gb, 'amount' => $amount, 'currency' => (int) $c->currency,
                'status' => 'pending', 'created_at' => $now, 'updated_at' => $now]);
        } catch (\Throwable $e) {
            self::$report['errors'][] = 'slot taken for #' . $sid;
            return false;
        }
        $domain = Env::domain((string) $c->domain);
        // Per-GB rate in the client's currency, derived from the (unchanged) amount so the text can never
        // disagree with the invoiced total: amount = blocks × blockPrice, gb = blocks × block_gb.
        $unit = self::currencyUnit((int) $c->currency);
        $perGb = $gb > 0 ? round($amount / $gb, ($amount / $gb) >= 100 ? 0 : 2) : 0.0;
        $rateTxt = View::n($perGb, $perGb >= 100 ? 0 : 2) . ($unit !== '' ? ' ' . $unit : '');
        // Explicit, human-readable Persian line item: GB purchased, per-GB rate, service domain, covered
        // period and purchase date. Only the description text changes — never the amount, rate or math.
        $desc = 'ترافیک اضافه CDN — ' . View::n($gb) . ' گیگابایت — ' . $domain
            . ' — هر گیگابایت ' . $rateTxt
            . ' — دوره ' . self::monthLabel($month)
            . ' — تاریخ خرید ' . self::dateLabel();
        $r = Env::localApi('CreateInvoice', [
            'userid' => (int) $c->userid, 'status' => 'Unpaid', 'sendinvoice' => false, 'autoapplycredit' => true,
            'date' => date('Y-m-d'), 'duedate' => date('Y-m-d'),
            'itemdescription1' => $desc, 'itemamount1' => $amount, 'itemtaxed1' => !empty($c->tax),
            'notes' => 'Pasargad CDN prepaid traffic — service #' . $sid . ' — ' . $gb . ' GB @ ' . View::digits((string) $perGb)
                . ($unit !== '' ? ' ' . $unit : '') . '/GB — ' . $domain . ' — ' . $month,
        ]);
        $inv = (int) ($r['invoiceid'] ?? 0);
        if (($r['result'] ?? '') !== 'success' || $inv <= 0) {
            Capsule::table(Env::TOPUPS)->where('id', $rowId)->update(['status' => 'failed', 'updated_at' => $now]);
            Env::log('prepaid: CreateInvoice failed for service #' . $sid . ': ' . ($r['message'] ?? ''), (int) $c->userid);
            return false;
        }
        Capsule::table(Env::TOPUPS)->where('id', $rowId)->update(['invoice_id' => $inv]);
        // mark the line as ours and link it to the service (never type Hosting: that would extend the due date)
        Capsule::table('tblinvoiceitems')->where('invoiceid', $inv)->where('type', '')
            ->update(['type' => self::ITEM_TYPE, 'relid' => $sid]);
        // autoapplycredit normally pays it already (then InvoicePaid marked the row paid)
        if (self::invoiceStatus($inv) !== 'Paid') {
            $bal = self::balance($inv);
            [$credit] = self::credit((int) $c->userid, (int) $c->currency);
            if ($bal > 0 && $credit + 0.00001 >= $bal) {
                Env::localApi('ApplyCredit', ['invoiceid' => $inv, 'amount' => $bal, 'noemail' => true]);
            }
        }
        if (self::invoiceStatus($inv) !== 'Paid') {
            Env::localApi('UpdateInvoice', ['invoiceid' => $inv, 'status' => 'Cancelled']);
            Capsule::table(Env::TOPUPS)->where('id', $rowId)->where('status', 'pending')->update(['status' => 'failed', 'updated_at' => date('Y-m-d H:i:s')]);
            Env::log('prepaid: invoice #' . $inv . ' for service #' . $sid . ' could not be paid from credit — cancelled', (int) $c->userid);
            return false;
        }
        self::markRowPaid($rowId, $server);
        Env::log('prepaid: bought ' . $gb . ' GB for service #' . $sid . ' (' . $domain . ') — invoice #' . $inv . ', ' . $amount, (int) $c->userid);
        self::$report['purchases'][] = ['service' => $sid, 'gb' => $gb, 'invoice' => $inv, 'amount' => $amount];
        return true;
    }

    private static function invoiceStatus(int $inv): string
    {
        return (string) Capsule::table('tblinvoices')->where('id', $inv)->value('status');
    }

    private static function balance(int $inv): float
    {
        $r = Env::localApi('GetInvoice', ['invoiceid' => $inv]);
        if (isset($r['balance'])) {
            return round((float) $r['balance'], 2);
        }
        $i = Capsule::table('tblinvoices')->where('id', $inv)->first(['total', 'credit']);
        $paid = (float) Capsule::table('tblaccounts')->where('invoiceid', $inv)->sum('amountin');
        return $i ? round((float) $i->total - (float) $i->credit - $paid, 2) : 0.0;
    }

    /** Top-up invoice paid (by us, by autoapplycredit, or later by the client/admin). */
    public static function markInvoicePaid(int $inv): void
    {
        foreach (Capsule::table(Env::TOPUPS)->where('invoice_id', $inv)->whereIn('status', ['pending', 'failed'])->pluck('id')->all() as $id) {
            self::markRowPaid((int) $id, null);
        }
    }

    /** pending → paid exactly once, then raise the cap. */
    private static function markRowPaid(int $rowId, $server): void
    {
        $n = Capsule::table(Env::TOPUPS)->where('id', $rowId)->whereIn('status', ['pending', 'failed'])
            ->update(['status' => 'paid', 'updated_at' => date('Y-m-d H:i:s')]);
        if ($n !== 1) {
            return;
        }
        $row = Capsule::table(Env::TOPUPS)->where('id', $rowId)->first();
        $c = self::service((int) $row->service_id);
        if ($c && $row->month === \pasargadcdn_month()) {
            self::patchCap($c, $c->pp['plan_gb'] + \pasargadcdn_topup_gb((int) $c->id), $server);
        }
    }

    /** Service facts for one id (prepaid products only). */
    private static function service(int $sid)
    {
        $r = Capsule::table('tblhosting as h')->join('tblproducts as p', 'p.id', '=', 'h.packageid')
            ->join('tblclients as c', 'c.id', '=', 'h.userid')->where('h.id', $sid)
            ->first(['h.id', 'h.userid', 'h.server', 'h.domain', 'h.domainstatus', 'p.id as pid', 'p.configoption1', 'p.overagesenabled',
                'p.overagesbwlimit', 'p.overagesbwprice', 'p.tax', 'c.currency']);
        if (!$r || !Env::isCdnProduct((int) $r->pid)) {
            return null;
        }
        $pp = \pasargadcdn_prepaid(['id' => $r->pid] + (array) $r, self::co((int) $r->id));
        if ($pp === null) {
            return null;
        }
        $r->pp = $pp;
        return $r;
    }

    private static function patchCap($c, int $cap, $server = null): bool
    {
        $server = $server ?: Capsule::table('tblservers')->where('id', (int) $c->server)->first();
        $domain = Env::domain((string) $c->domain);
        if (!$server || $server->type !== 'pasargadcdn' || !Env::validHostname($domain)) {
            return false;
        }
        try {
            Env::api(10, $server)->patch(ApiClient::site($domain) . '/plan', ['bandwidth_limit_gb' => $cap]);
            self::$report['patched'][] = ['service' => (int) $c->id, 'cap' => $cap];
            return true;
        } catch (\Throwable $e) {
            self::$report['errors'][] = 'patch #' . (int) $c->id . ': ' . $e->getMessage();
            Env::log('prepaid: could not set the traffic cap of ' . $domain . ' to ' . $cap . ' GB: ' . $e->getMessage() . ' (retried next cron)', (int) $c->userid);
            return false;
        }
    }

    // ------------------------------------------------------------------ month rollover

    /** First run of a new month: prepaid caps back to plan GB (+ any top-ups already bought this month). */
    public static function rollover(array $pids): int
    {
        $month = \pasargadcdn_month();
        if (Env::kvGet('prepaid_month') === $month) {
            return 0;
        }
        $n = 0;
        $rows = Capsule::table('tblhosting as h')->join('tblproducts as p', 'p.id', '=', 'h.packageid')
            ->join('tblclients as c', 'c.id', '=', 'h.userid')
            ->whereIn('h.packageid', $pids)->whereIn('h.domainstatus', ['Active', 'Suspended'])
            ->get(['h.id', 'h.userid', 'h.server', 'h.domain', 'p.id as pid', 'p.configoption1', 'p.overagesenabled',
                'p.overagesbwlimit', 'p.overagesbwprice', 'p.tax', 'c.currency'])->all();
        foreach ($rows as $r) {
            $pp = \pasargadcdn_prepaid(['id' => $r->pid] + (array) $r, self::co((int) $r->id));
            if ($pp === null) {
                continue;
            }
            $r->pp = $pp;
            if (self::patchCap($r, $pp['plan_gb'] + \pasargadcdn_topup_gb((int) $r->id, $month))) {
                $n++;
            }
        }
        Env::kvSet('prepaid_month', $month);
        if ($n) {
            Env::log('prepaid: new month ' . $month . ' — traffic caps of ' . $n . ' services reset to their plans');
        }
        return $n;
    }

    // ------------------------------------------------------------------ renewals from the wallet

    /**
     * Pays unpaid invoices that contain ONLY this addon's items (CDN service renewals,
     * traffic top-ups and §16.8 storage charges) from the client's credit, oldest first, only when fully covered.
     * Invoices with any other product are never touched.
     */
    public static function renewals(array $pids, ?int $userId): array
    {
        $cq = Capsule::table('tblclients')->where('credit', '>', 0)
            ->whereIn('id', function ($q) use ($pids) {
                $q->select('userid')->from('tblhosting')->whereIn('packageid', $pids);
            });
        if ($userId !== null) {
            $cq->where('id', $userId);
        }
        $clients = $cq->limit(500)->pluck('id')->all();
        if (!$clients) {
            return [];
        }
        $invoices = Capsule::table('tblinvoices')->whereIn('userid', $clients)->where('status', 'Unpaid')
            ->orderBy('duedate')->orderBy('id')->limit(1000)->get(['id', 'userid'])->all();
        if (!$invoices) {
            return [];
        }
        $ids = array_map(function ($i) {
            return (int) $i->id;
        }, $invoices);
        $items = [];
        foreach (Capsule::table('tblinvoiceitems')->whereIn('invoiceid', $ids)->get(['invoiceid', 'type', 'relid']) as $it) {
            $items[(int) $it->invoiceid][] = $it;
        }
        $hostingIds = [];
        foreach ($items as $list) {
            foreach ($list as $it) {
                if (in_array((string) $it->type, ['Hosting', 'PromoHosting'], true)) {
                    $hostingIds[(int) $it->relid] = true;
                }
            }
        }
        $cdnServices = $hostingIds ? array_flip(array_map('intval', Capsule::table('tblhosting')->whereIn('id', array_keys($hostingIds))
            ->whereIn('packageid', $pids)->pluck('id')->all())) : [];
        $paid = [];
        foreach ($invoices as $inv) {
            $list = $items[(int) $inv->id] ?? [];
            if (!$list || !self::cdnOnly($list, $cdnServices)) {
                continue;
            }
            $bal = self::balance((int) $inv->id);
            $credit = (float) Capsule::table('tblclients')->where('id', (int) $inv->userid)->value('credit');
            if ($bal <= 0 || $credit + 0.00001 < $bal) {
                continue;
            }
            $r = Env::localApi('ApplyCredit', ['invoiceid' => (int) $inv->id, 'amount' => $bal]);
            if (($r['result'] ?? '') === 'success') {
                $paid[] = (int) $inv->id;
                Env::log('prepaid: invoice #' . (int) $inv->id . ' paid from credit (' . $bal . ')', (int) $inv->userid);
            }
        }
        return $paid;
    }

    private static function cdnOnly(array $items, array $cdnServices): bool
    {
        $core = false;
        foreach ($items as $it) {
            $t = (string) $it->type;
            // SPEC §16.8: a month's object-storage charge (StorageBilling, prepaid mode) is a CDN-only line too
            if ($t === self::ITEM_TYPE || $t === self::STORAGE_ITEM_TYPE) {
                $core = true;
            } elseif (($t === 'Hosting' || $t === 'PromoHosting') && isset($cdnServices[(int) $it->relid])) {
                $core = $core || $t === 'Hosting';
            } elseif ($t !== 'LateFee') {
                return false;
            }
        }
        return $core;
    }

    // ------------------------------------------------------------------ emails

    private static function maybeWarn($c, float $used, int $cap, array $t): void
    {
        if (!$c->pp['warn'] || $c->pp['price_per_gb'] === null) {
            return;
        }
        [$credit, $rate] = self::credit((int) $c->userid, (int) $c->currency);
        $blockPrice = round($c->pp['price_per_gb'] * $c->pp['block_gb'] * $rate, 2);
        $limit = $c->pp['max_blocks'] - $t['blocks'] <= 0;
        if ($credit + 0.00001 >= $blockPrice && !$limit) {
            return; // the wallet covers the next block: no reason to warn
        }
        self::notice($c, 'warning', self::vars($c, $used, $cap, $credit, $blockPrice, $limit ? 'limit' : 'credit'));
    }

    private static function exhausted($c, float $used, int $cap, string $reason): void
    {
        [$credit, $rate] = self::credit((int) $c->userid, (int) $c->currency);
        $blockPrice = $c->pp['price_per_gb'] !== null ? round($c->pp['price_per_gb'] * $c->pp['block_gb'] * $rate, 2) : 0.0;
        self::notice($c, 'exhausted', self::vars($c, $used, $cap, $credit, $blockPrice, $reason));
    }

    private static function vars($c, float $used, int $cap, float $credit, float $blockPrice, string $reason): array
    {
        $cur = Capsule::table('tblcurrencies')->where('id', (int) $c->currency)->first(['code', 'suffix']);
        $unit = $cur ? (trim((string) $cur->suffix) !== '' ? trim((string) $cur->suffix) : (string) $cur->code) : '';
        $needed = max(0.0, round($blockPrice - $credit, 2));
        return [
            'cdn_used_gb' => View::n($used, 1),
            'cdn_cap_gb' => View::n($cap),
            'cdn_block_gb' => View::n($c->pp['block_gb']),
            'cdn_block_price' => View::n($blockPrice, $blockPrice >= 100 ? 0 : 2) . ' ' . $unit,
            'cdn_credit' => View::n($credit, $credit >= 100 ? 0 : 2) . ' ' . $unit,
            'cdn_needed' => View::n($needed, $needed >= 100 ? 0 : 2) . ' ' . $unit,
            'cdn_limit_reached' => $reason === 'limit' ? 1 : 0,
        ];
    }

    /** One notice per service, month and kind (unique row), then the email. */
    private static function notice($c, string $kind, array $vars, bool $email = true): void
    {
        try {
            Capsule::table(Env::NOTICES)->insert(['service_id' => (int) $c->id, 'month' => \pasargadcdn_month(), 'kind' => $kind,
                'created_at' => date('Y-m-d H:i:s')]);
        } catch (\Throwable $e) {
            return; // already sent this month
        }
        self::$report['notices'][] = ['service' => (int) $c->id, 'kind' => $kind];
        if ($kind === 'noprice') {
            Env::log('prepaid: no per-GB price for product #' . (int) $c->pid . ' — service #' . (int) $c->id . ' cannot buy traffic (set it in the product wizard or the addon settings)', (int) $c->userid);
            return;
        }
        if (!$email) {
            return;
        }
        $tpl = ['exhausted' => self::TPL_EXHAUSTED, 'forecast' => self::TPL_FORECAST][$kind] ?? self::TPL_WARNING;
        $r = Env::localApi('SendEmail', ['messagename' => $tpl, 'id' => (int) $c->id, 'customvars' => base64_encode(serialize($vars))]);
        Env::log('prepaid: «' . $tpl . '» email for service #' . (int) $c->id . ' — ' . (($r['result'] ?? '') === 'success' ? 'sent' : 'failed: ' . ($r['message'] ?? '')), (int) $c->userid);
    }

    /** Client-currency unit (suffix, else code) for the invoice line item. */
    private static function currencyUnit(int $currencyId): string
    {
        $cur = Capsule::table('tblcurrencies')->where('id', $currencyId)->first(['code', 'suffix']);
        if (!$cur) {
            return '';
        }
        $s = trim((string) $cur->suffix);
        return $s !== '' ? $s : (string) $cur->code;
    }

    /** Persian (Jalali) purchase date for the invoice line item, e.g. «۹ مهر ۱۴۰۵». */
    public static function dateLabel(?int $ts = null): string
    {
        $ts = $ts ?? self::now();
        if (class_exists('\\IntlDateFormatter')) {
            $f = new \IntlDateFormatter('fa_IR@calendar=persian', \IntlDateFormatter::NONE, \IntlDateFormatter::NONE,
                'UTC', \IntlDateFormatter::TRADITIONAL, 'd MMMM yyyy');
            $s = $f->format($ts);
            if (is_string($s) && $s !== '') {
                return $s;
            }
        }
        return View::digits(gmdate('Y-m-d', $ts));
    }

    public static function monthLabel(string $month): string
    {
        if (class_exists('\\IntlDateFormatter')) {
            $f = new \IntlDateFormatter('fa_IR@calendar=persian', \IntlDateFormatter::NONE, \IntlDateFormatter::NONE,
                'UTC', \IntlDateFormatter::TRADITIONAL, 'MMMM yyyy');
            $s = $f->format(strtotime($month . '-15 12:00:00 UTC'));
            if (is_string($s) && $s !== '') {
                return $s;
            }
        }
        return $month;
    }

    // ==================================================================
    // §10.5 RESELLER WHOLESALE BILLING — a fully separate, additive ledger.
    //
    // Mirrors the per-service buy-traffic / cut-at-cap behaviour above, but
    // against each reseller's aggregate wallet (no per-site plan): every GB is
    // billed at the reseller's effective wholesale rate, purchases are recorded
    // in mod_pasargadcdn_reseller_topups (unique (userid,month,seq) slot so
    // concurrent runs are idempotent), and when the wallet can't cover usage the
    // reseller's sub-sites are cut (suspended on the controller + suspended=1
    // locally) with ONE Persian notice, reconnecting when the wallet is topped up.
    // None of the code above is touched.
    // ==================================================================

    /** @var array report of the last reseller run (tests / admin) */
    public static $rReport = [];
    /** @var bool re-entrancy guard for the reseller pass */
    private static $rRunning = false;

    /**
     * @param int|null $userId only this reseller (Add Funds), or all enabled resellers (cron).
     * @return array report
     */
    public static function processResellers(?int $userId): array
    {
        self::$rReport = ['purchases' => [], 'notices' => [], 'cuts' => [], 'reconnects' => [], 'errors' => []];
        if (self::$rRunning) {
            return self::$rReport;
        }
        if (!Env::loadServerModule()) {
            return self::$rReport;
        }
        self::$rRunning = true;
        try {
            // Cheap early-out when the feature is unused: one schema check + one id query, no HTTP.
            if (!Env::hasTable(Env::RESELLERS)) {
                return self::$rReport;
            }
            $q = Capsule::table(Env::RESELLERS)->where('enabled', 1);
            if ($userId !== null) {
                $q->where('userid', $userId);
            }
            $ids = array_map('intval', $q->pluck('userid')->all());
            if (!$ids) {
                return self::$rReport;
            }
            self::tables();
            $month = \pasargadcdn_month();
            // one controller usage read for the whole pass: domain => GB
            $server = \PasargadCdn\Reseller::server();
            if (!$server) {
                self::$rReport['errors'][] = 'no server';
                return self::$rReport;
            }
            try {
                $data = Env::api(15, $server)->get('/api/v1/usage?month=' . $month);
            } catch (\Throwable $e) {
                self::$rReport['errors'][] = 'usage: ' . $e->getMessage();
                Env::log('reseller prepaid: controller usage unavailable (' . $e->getMessage() . ') — nothing bought this run');
                return self::$rReport;
            }
            $usageMap = [];
            foreach ((array) ($data['sites'] ?? []) as $s) {
                $d = strtolower((string) ($s['domain'] ?? ''));
                if ($d !== '') {
                    $usageMap[$d] = (float) ($s['bytes'] ?? 0) / 1073741824;
                }
            }
            foreach ($ids as $uid) {
                try {
                    self::processReseller($uid, $usageMap, $month, $server);
                } catch (\Throwable $e) {
                    self::$rReport['errors'][] = 'reseller #' . $uid . ': ' . $e->getMessage();
                    Env::log('reseller prepaid: client #' . $uid . ' failed: ' . $e->getMessage(), $uid);
                }
            }
        } finally {
            self::$rRunning = false;
        }
        return self::$rReport;
    }

    private static function processReseller(int $uid, array $usageMap, string $month, $server): void
    {
        $cfg = \PasargadCdn\Reseller::config($uid);
        if (!$cfg['enabled']) {
            return;
        }
        $sites = \PasargadCdn\Reseller::sites($uid);
        $block = \PasargadCdn\Reseller::blockGb();
        $maxBlocks = \PasargadCdn\Reseller::maxBlocks();
        // aggregate current-month usage across the reseller's sub-sites
        $used = 0.0;
        foreach ($sites as $s) {
            $d = strtolower(Env::domain((string) $s->domain));
            $used += $usageMap[$d] ?? 0.0;
        }
        $t = self::resellerMonthTopups($uid, $month);
        $cap = $t['paid_gb']; // no included plan: cap = traffic bought this month
        $left = max(0, $maxBlocks - $t['blocks']);
        $margin = self::margin(max(1.0, (float) $cap), $block);
        $needCut = $used >= $cap;
        if ($used < $cap - $margin && !$needCut) {
            self::reconnectReseller($uid, $sites, $month, $server);
            return;
        }
        $client = Capsule::table('tblclients')->where('id', $uid)->first(['currency']);
        $currencyId = $client ? (int) $client->currency : 0;
        $rate = $cfg['rate'];
        $need = self::blocksNeeded($used, (int) $cap, $block);
        $bought = 0;
        $reason = '';
        $credit = 0.0;
        $blockPrice = 0.0;
        if ($rate === null || $rate <= 0) {
            $reason = 'noprice';
            self::resellerNotice($uid, 'noprice', [], false);
        } elseif ($left === 0) {
            $reason = 'limit';
        } else {
            [$credit, $crate] = self::credit($uid, $currencyId);
            $blockPrice = round($rate * $block * $crate, 2);
            $afford = $blockPrice > 0 ? (int) floor(($credit + 0.00001) / $blockPrice) : 0;
            $buy = min($need, $left, $afford);
            if ($buy > 0) {
                $bought = self::purchaseReseller($uid, $buy, $blockPrice, $block, $month, $currencyId) ? $buy : 0;
            }
            if ($bought < $need) {
                $reason = ($afford < $need && $left >= $need) ? 'credit' : ($left < $need ? 'limit' : 'credit');
            }
        }
        $newCap = $cap + $bought * $block;
        if ($used >= $newCap && $reason !== '') {
            self::cutReseller($uid, $sites, $month, $server, $reason, $used, $newCap, $block, $credit, $blockPrice, $currencyId);
        } else {
            self::reconnectReseller($uid, $sites, $month, $server);
        }
    }

    /** userid => ['paid_gb', 'blocks'] for the reseller ledger in $month (paid + pending). */
    private static function resellerMonthTopups(int $uid, string $month): array
    {
        $out = ['paid_gb' => 0, 'blocks' => 0];
        foreach (Capsule::table(Env::RESELLER_TOPUPS)->where('userid', $uid)->where('month', $month)
                     ->whereIn('status', ['paid', 'pending'])->get(['gb', 'blocks', 'status']) as $r) {
            if ($r->status === 'paid') {
                $out['paid_gb'] += (int) $r->gb;
            }
            $out['blocks'] += (int) $r->blocks;
        }
        return $out;
    }

    /** GB of paid reseller top-ups for $month. */
    public static function resellerTopupGb(int $uid, ?string $month = null): int
    {
        try {
            return (int) Capsule::table(Env::RESELLER_TOPUPS)->where('userid', $uid)
                ->where('month', $month ?: \pasargadcdn_month())->where('status', 'paid')->sum('gb');
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** Buy $blocks of wholesale traffic for a reseller from their wallet. Mirrors purchase(). */
    private static function purchaseReseller(int $uid, int $blocks, float $blockPrice, int $block, string $month, int $currencyId): bool
    {
        $gb = $blocks * $block;
        $amount = round($blocks * $blockPrice, 2);
        $now = date('Y-m-d H:i:s');
        // claim the next slot; a concurrent run claiming the same slot fails on the unique key
        $seq = (int) Capsule::table(Env::RESELLER_TOPUPS)->where('userid', $uid)->where('month', $month)->max('seq') + 1;
        try {
            $rowId = (int) Capsule::table(Env::RESELLER_TOPUPS)->insertGetId(['userid' => $uid, 'month' => $month,
                'seq' => $seq, 'blocks' => $blocks, 'gb' => $gb, 'amount' => $amount, 'currency' => $currencyId,
                'status' => 'pending', 'created_at' => $now, 'updated_at' => $now]);
        } catch (\Throwable $e) {
            self::$rReport['errors'][] = 'slot taken for reseller #' . $uid;
            return false;
        }
        $unit = self::currencyUnit($currencyId);
        $perGb = $gb > 0 ? round($amount / $gb, ($amount / $gb) >= 100 ? 0 : 2) : 0.0;
        $rateTxt = View::n($perGb, $perGb >= 100 ? 0 : 2) . ($unit !== '' ? ' ' . $unit : '');
        $desc = 'ترافیک عمده نمایندگی CDN — ' . View::n($gb) . ' گیگابایت — هر گیگابایت ' . $rateTxt
            . ' — دوره ' . self::monthLabel($month) . ' — تاریخ خرید ' . self::dateLabel();
        $r = Env::localApi('CreateInvoice', [
            'userid' => $uid, 'status' => 'Unpaid', 'sendinvoice' => false, 'autoapplycredit' => true,
            'date' => date('Y-m-d'), 'duedate' => date('Y-m-d'),
            'itemdescription1' => $desc, 'itemamount1' => $amount, 'itemtaxed1' => false,
            'notes' => 'Pasargad CDN reseller wholesale traffic — reseller #' . $uid . ' — ' . $gb . ' GB @ ' . View::digits((string) $perGb)
                . ($unit !== '' ? ' ' . $unit : '') . '/GB — ' . $month,
        ]);
        $inv = (int) ($r['invoiceid'] ?? 0);
        if (($r['result'] ?? '') !== 'success' || $inv <= 0) {
            Capsule::table(Env::RESELLER_TOPUPS)->where('id', $rowId)->update(['status' => 'failed', 'updated_at' => $now]);
            Env::log('reseller prepaid: CreateInvoice failed for reseller #' . $uid . ': ' . ($r['message'] ?? ''), $uid);
            return false;
        }
        Capsule::table(Env::RESELLER_TOPUPS)->where('id', $rowId)->update(['invoice_id' => $inv]);
        Capsule::table('tblinvoiceitems')->where('invoiceid', $inv)->where('type', '')
            ->update(['type' => self::RESELLER_ITEM_TYPE, 'relid' => $uid]);
        if (self::invoiceStatus($inv) !== 'Paid') {
            $bal = self::balance($inv);
            [$credit] = self::credit($uid, $currencyId);
            if ($bal > 0 && $credit + 0.00001 >= $bal) {
                Env::localApi('ApplyCredit', ['invoiceid' => $inv, 'amount' => $bal, 'noemail' => true]);
            }
        }
        if (self::invoiceStatus($inv) !== 'Paid') {
            Env::localApi('UpdateInvoice', ['invoiceid' => $inv, 'status' => 'Cancelled']);
            Capsule::table(Env::RESELLER_TOPUPS)->where('id', $rowId)->where('status', 'pending')->update(['status' => 'failed', 'updated_at' => date('Y-m-d H:i:s')]);
            Env::log('reseller prepaid: invoice #' . $inv . ' for reseller #' . $uid . ' could not be paid from credit — cancelled', $uid);
            return false;
        }
        Capsule::table(Env::RESELLER_TOPUPS)->where('id', $rowId)->whereIn('status', ['pending', 'failed'])
            ->update(['status' => 'paid', 'updated_at' => date('Y-m-d H:i:s')]);
        Env::log('reseller prepaid: bought ' . $gb . ' GB for reseller #' . $uid . ' — invoice #' . $inv . ', ' . $amount, $uid);
        self::$rReport['purchases'][] = ['reseller' => $uid, 'gb' => $gb, 'invoice' => $inv, 'amount' => $amount];
        return true;
    }

    /** Reseller top-up invoice paid (by us, autoapplycredit, or later by the client/admin). */
    public static function markResellerInvoicePaid(int $inv): void
    {
        foreach (Capsule::table(Env::RESELLER_TOPUPS)->where('invoice_id', $inv)->whereIn('status', ['pending', 'failed'])->pluck('id')->all() as $id) {
            Capsule::table(Env::RESELLER_TOPUPS)->where('id', (int) $id)->whereIn('status', ['pending', 'failed'])
                ->update(['status' => 'paid', 'updated_at' => date('Y-m-d H:i:s')]);
        }
    }

    /** Cut a reseller's sub-sites: suspend on the controller + local suspended=1, ONE Persian notice. */
    private static function cutReseller(int $uid, array $sites, string $month, $server, string $reason,
                                        float $used, int $cap, int $block, float $credit, float $blockPrice, int $currencyId): void
    {
        foreach ($sites as $s) {
            if ((int) $s->suspended === 1) {
                continue;
            }
            $domain = Env::domain((string) $s->domain);
            $ok = false;
            try {
                if ($server && Env::validHostname($domain)) {
                    Env::api(15, $server)->post(ApiClient::site($domain) . '/suspend');
                    $ok = true;
                }
            } catch (\Throwable $e) {
                self::$rReport['errors'][] = 'suspend ' . $domain . ': ' . $e->getMessage();
                Env::log('reseller prepaid: could not suspend ' . $domain . ' on the controller: ' . $e->getMessage() . ' (retried next cron)', $uid);
            }
            if ($ok) {
                Capsule::table(Env::RESELLER_SITES)->where('id', (int) $s->id)->update(['suspended' => 1, 'updated_at' => date('Y-m-d H:i:s')]);
                self::$rReport['cuts'][] = ['reseller' => $uid, 'site' => (int) $s->id, 'domain' => $domain];
            }
        }
        self::resellerNotice($uid, 'exhausted', self::resellerVars($uid, $used, $cap, $credit, $blockPrice, $block, $reason, $currencyId));
    }

    /** Reconnect any locally-suspended sub-sites of a reseller whose wallet now covers usage. */
    private static function reconnectReseller(int $uid, array $sites, string $month, $server): void
    {
        $any = false;
        foreach ($sites as $s) {
            if ((int) $s->suspended !== 1) {
                continue;
            }
            $domain = Env::domain((string) $s->domain);
            try {
                // Growth: a sub-site the reseller paused by hand (bulk pause) stays paused on the controller;
                // only the wallet's own cut flag is cleared.
                $held = class_exists('\\PasargadCdn\\Reseller') && \PasargadCdn\Reseller::isHeld((int) $s->id);
                if (!$held && $server && Env::validHostname($domain)) {
                    Env::api(15, $server)->post(ApiClient::site($domain) . '/unsuspend');
                }
                Capsule::table(Env::RESELLER_SITES)->where('id', (int) $s->id)->update(['suspended' => 0, 'updated_at' => date('Y-m-d H:i:s')]);
                self::$rReport['reconnects'][] = ['reseller' => $uid, 'site' => (int) $s->id, 'domain' => $domain];
                $any = true;
            } catch (\Throwable $e) {
                self::$rReport['errors'][] = 'unsuspend ' . $domain . ': ' . $e->getMessage();
                Env::log('reseller prepaid: could not reconnect ' . $domain . ' on the controller: ' . $e->getMessage() . ' (retried next cron)', $uid);
            }
        }
        if ($any) {
            // allow a fresh notice on the next cut this month
            Env::kvSet('rnotice:' . $uid . ':' . $month . ':exhausted', 0);
            Env::log('reseller prepaid: reseller #' . $uid . ' sub-sites reconnected after wallet top-up', $uid);
        }
    }

    private static function resellerVars(int $uid, float $used, int $cap, float $credit, float $blockPrice, int $block, string $reason, int $currencyId): array
    {
        $unit = self::currencyUnit($currencyId);
        $needed = max(0.0, round($blockPrice - $credit, 2));
        return [
            'cdn_reseller_used_gb' => View::n($used, 1),
            'cdn_reseller_cap_gb' => View::n($cap),
            'cdn_reseller_block_gb' => View::n($block),
            'cdn_reseller_block_price' => View::n($blockPrice, $blockPrice >= 100 ? 0 : 2) . ' ' . $unit,
            'cdn_reseller_credit' => View::n($credit, $credit >= 100 ? 0 : 2) . ' ' . $unit,
            'cdn_reseller_needed' => View::n($needed, $needed >= 100 ? 0 : 2) . ' ' . $unit,
            'cdn_reseller_limit_reached' => $reason === 'limit' ? 1 : 0,
        ];
    }

    /** One reseller notice per client, month and kind (kv-deduped), then a best-effort email. */
    private static function resellerNotice(int $uid, string $kind, array $vars, bool $email = true): void
    {
        $month = \pasargadcdn_month();
        $key = 'rnotice:' . $uid . ':' . $month . ':' . $kind;
        if ((int) Env::kvGet($key, 0) === 1) {
            return; // already notified this month
        }
        Env::kvSet($key, 1);
        self::$rReport['notices'][] = ['reseller' => $uid, 'kind' => $kind];
        if ($kind === 'noprice') {
            Env::log('reseller prepaid: no wholesale per-GB rate for reseller #' . $uid . ' — traffic cannot be billed (set a rate in «نمایندگان» or the global reseller rate)', $uid);
            return;
        }
        if (!$email) {
            return;
        }
        // Best-effort: send a Persian email through the WHMCS mail path if the template exists.
        $r = Env::localApi('SendEmail', ['messagename' => self::TPL_RESELLER_EXHAUSTED, 'id' => $uid, 'customvars' => base64_encode(serialize($vars))]);
        Env::log('reseller prepaid: «' . self::TPL_RESELLER_EXHAUSTED . '» notice for reseller #' . $uid . ' — '
            . (($r['result'] ?? '') === 'success' ? 'sent' : 'email skipped/failed: ' . ($r['message'] ?? '')), $uid);
    }
}
