<?php

namespace PasargadCdn\Admin;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\StorageBilling', false)) {
    return;
}

/**
 * SPEC §16.8 — monthly object-storage charges (docs/WHMCS.md «فضای ذخیره‌سازی»).
 *
 * The controller samples every site's stored bytes hourly and reports, per closed month, gb_month =
 * GB-hours ÷ hours of the month (the average GB stored) — GET /api/v1/storage/usage?month=YYYY-MM.
 * Once per month, after the month has closed (UTC, + GRACE for the last hourly sample), the
 * AfterCronJob pass fetches that report from every Pasargad CDN server and charges each service
 *
 *     amount = gb_month × «قیمت هر گیگابایت-ماه ذخیره‌سازی» (addon setting, default currency)
 *              × the client's currency rate, rounded to 2 decimals
 *
 * The whole stored average is billed (storage_gb of the plan is the quota, not an included amount);
 * a price of 0 / empty turns this pass off (e.g. when the «Storage GB» configurable option is priced
 * per month instead). How the charge reaches the client follows the traffic billing mode:
 *
 *  - prepaid: an invoice «فضای ذخیره‌سازی ابری CDN …» created with autoapplycredit, so the wallet
 *    pays it at once when it can; otherwise it stays Unpaid (the storage was already used — unlike a
 *    traffic block it is never cancelled), the client gets the invoice e-mail, and Prepaid::renewals()
 *    pays it from credit after the next Add Funds (the line type counts as a CDN-only item);
 *  - overage / cut: a WHMCS billable item (invoice action «next cron»), i.e. a post-paid month-end
 *    charge like WHMCS's own overage billing.
 *
 * Idempotent: mod_pasargadcdn_storage_bills has one row per (service, month) — claimed BEFORE the
 * invoice / billable item is created (unique key), so parallel or repeated runs never charge twice;
 * a failed WHMCS call marks the row «failed» and the next run retries only that row.
 * Fail-safe: a controller that cannot be reached or answers 5xx stops nothing else — the month is
 * marked done only when every server answered, and the pass is retried at most once an hour; an
 * older controller (404, no storage) has nothing to bill. Never throws into WHMCS's cron.
 */
final class StorageBilling
{
    const ITEM_TYPE = 'PasargadCdnStorage';
    const KV_DONE = 'storage_billed_month';
    const KV_TRY = 'storage_billing_try';
    /** seconds after the month closes (UTC) before it is billed: the controller's last hourly sample is in */
    const GRACE = 7200;
    /** a failed run (controller down) is retried at most this often */
    const RETRY = 3600;

    /** @var callable|null tests: fn(): int (unix time) */
    public static $clock = null;
    /** @var array report of the last run (tests / admin) */
    public static $report = [];

    /**
     * Price per GB-month in the default currency (addon setting), 0 = storage is not billed. Read from the
     * provisioning module's memoised addon settings (the same read the billing mode uses: no extra query per cron run).
     */
    public static function price(): float
    {
        $raw = function_exists('pasargadcdn_addon_settings') ? (string) (\pasargadcdn_addon_settings()['storage_price'] ?? '') : Env::setting('storage_price', '');
        $v = trim(str_replace([',', '٬', ' '], '', strtr($raw, ['۰' => '0', '۱' => '1', '۲' => '2',
            '۳' => '3', '۴' => '4', '۵' => '5', '۶' => '6', '۷' => '7', '۸' => '8', '۹' => '9', '٫' => '.'])));
        return $v !== '' && is_numeric($v) && (float) $v > 0 ? round((float) $v, 4) : 0.0;
    }

    private static function now(): int
    {
        return self::$clock ? (int) (self::$clock)() : time();
    }

    /** The month before the one containing $ts (UTC), YYYY-MM. */
    public static function previousMonth(int $ts): string
    {
        return gmdate('Y-m', gmmktime(12, 0, 0, (int) gmdate('n', $ts) - 1, 15, (int) gmdate('Y', $ts)));
    }

    /** AfterCronJob entry. Cheap when there is nothing to do (memoised settings + one key/value read). Never throws. */
    public static function onCron(): void
    {
        try {
            self::run(false);
        } catch (\Throwable $e) {
            Env::log('storage billing cron error: ' . $e->getMessage());
        }
    }

    /**
     * Bills the previous month (or $month) once.
     * @param bool $force ignore the done / retry markers (admin «run now» and tests); the per-service
     *                    rows still make a second charge impossible
     */
    public static function run(bool $force = false, ?string $month = null): array
    {
        $now = self::now();
        $month = $month ?: self::previousMonth($now);
        self::$report = ['month' => $month, 'billed' => [], 'skipped' => [], 'errors' => [], 'done' => false, 'ran' => false];
        if (!Env::loadServerModule()) {
            return self::$report;
        }
        $price = self::price();
        if ($price <= 0) {
            self::$report['skipped'][] = 'no price';
            return self::$report;
        }
        // the month must be closed (+ grace) — never bill a month that is still running
        $monthEnd = gmmktime(0, 0, 0, (int) substr($month, 5, 2) + 1, 1, (int) substr($month, 0, 4));
        if ($now < $monthEnd + self::GRACE) {
            self::$report['skipped'][] = 'month not closed';
            return self::$report;
        }
        if (!$force) {
            if (Env::kvGet(self::KV_DONE) === $month) {
                return self::$report;
            }
            if ($now - (int) Env::kvGet(self::KV_TRY, 0) < self::RETRY) {
                self::$report['skipped'][] = 'retry later';
                return self::$report;
            }
        }
        if (!Env::hasTable(Env::STORAGE_BILLS)) {
            Env::ensureTable();
        }
        Env::kvSet(self::KV_TRY, $now);
        self::$report['ran'] = true;
        $failed = false;
        if (Env::cdnProductIds()) {
            foreach (Env::servers() as $server) {
                try {
                    $data = Env::api(15, $server)->get('/api/v1/storage/usage?month=' . rawurlencode($month));
                } catch (\Throwable $e) {
                    if ((int) $e->getCode() === 404) {
                        continue; // controller without object storage (older build): nothing to bill there
                    }
                    $failed = true;
                    self::$report['errors'][] = 'server #' . (int) $server->id . ': ' . $e->getMessage();
                    Env::log('storage billing: usage of ' . $month . ' unavailable from server #' . (int) $server->id . ' ('
                        . $e->getMessage() . ') — retried next hour');
                    continue;
                }
                foreach ((array) ($data['sites'] ?? []) as $site) {
                    if (is_array($site) && !self::bill($site, $month, $price)) {
                        $failed = true;
                    }
                }
            }
        }
        if (!$failed) {
            Env::kvSet(self::KV_DONE, $month);
            self::$report['done'] = true;
            if (self::$report['billed']) {
                Env::log('storage billing: ' . $month . ' — ' . count(self::$report['billed']) . ' services charged');
            }
        }
        return self::$report;
    }

    /** One site of the report. false = a failure that must be retried (the month is not done). */
    private static function bill(array $site, string $month, float $price): bool
    {
        $ext = (string) ($site['external_id'] ?? '');
        $gbm = round((float) ($site['gb_month'] ?? 0), 4);
        $domain = strtolower((string) ($site['domain'] ?? ''));
        if ($gbm <= 0) {
            return true;
        }
        if (($site['complete'] ?? true) === false) {
            self::$report['errors'][] = $domain . ': month not complete on the controller';
            return false;
        }
        if ($ext === '' || !ctype_digit($ext)) {
            self::$report['skipped'][] = $domain . ': not a WHMCS service';
            return true; // reseller sub-sites etc. — the reseller ledger is separate
        }
        $sid = (int) $ext;
        $svc = Capsule::table('tblhosting as h')->join('tblclients as c', 'c.id', '=', 'h.userid')->where('h.id', $sid)
            ->first(['h.id', 'h.userid', 'h.packageid', 'h.domain', 'h.domainstatus', 'c.currency']);
        if (!$svc || !Env::isCdnProduct((int) $svc->packageid) || Env::domain((string) $svc->domain) !== $domain) {
            self::$report['skipped'][] = $domain . ': no matching CDN service #' . $sid;
            return true;
        }
        if ((string) $svc->domainstatus === 'Fraud') {
            self::$report['skipped'][] = $domain . ': fraud';
            return true;
        }
        $tax = (int) Capsule::table('tblproducts')->where('id', (int) $svc->packageid)->value('tax');
        $rate = (float) Capsule::table('tblcurrencies')->where('id', (int) $svc->currency)->value('rate');
        $rate = $rate > 0 ? $rate : 1.0;
        $amount = round($gbm * $price * $rate, 2);
        $now = date('Y-m-d H:i:s');
        $mode = \pasargadcdn_billing_mode() === 'prepaid' ? 'invoice' : 'billable';

        // claim (service, month) — the unique key makes a second charge impossible; only a failed row is retried
        $row = Capsule::table(Env::STORAGE_BILLS)->where('service_id', $sid)->where('month', $month)->first();
        if ($row) {
            if ((string) $row->status !== 'failed' || Capsule::table(Env::STORAGE_BILLS)->where('id', (int) $row->id)
                    ->where('status', 'failed')->update(['status' => 'pending', 'updated_at' => $now]) !== 1) {
                return true; // already charged (or being charged by a parallel run)
            }
            $rowId = (int) $row->id;
            Capsule::table(Env::STORAGE_BILLS)->where('id', $rowId)->update(['gb_month' => $gbm, 'amount' => $amount,
                'currency' => (int) $svc->currency, 'mode' => $mode]);
        } else {
            try {
                $rowId = (int) Capsule::table(Env::STORAGE_BILLS)->insertGetId(['service_id' => $sid, 'userid' => (int) $svc->userid,
                    'month' => $month, 'gb_month' => $gbm, 'amount' => $amount, 'currency' => (int) $svc->currency, 'mode' => $mode,
                    'status' => 'pending', 'created_at' => $now, 'updated_at' => $now]);
            } catch (\Throwable $e) {
                return true; // claimed by a parallel run
            }
        }
        if ($amount < 0.01) {
            Capsule::table(Env::STORAGE_BILLS)->where('id', $rowId)->update(['status' => 'skipped', 'note' => 'amount below 0.01', 'updated_at' => $now]);
            self::$report['skipped'][] = $domain . ': amount below 0.01';
            return true;
        }
        $unit = self::currencyUnit((int) $svc->currency);
        $perGb = round($price * $rate, $price * $rate >= 100 ? 0 : 4);
        $desc = 'فضای ذخیره‌سازی ابری CDN — ' . View::n($gbm, 2) . ' گیگابایت-ماه — ' . $domain
            . ' — هر گیگابایت-ماه ' . View::n($perGb, $perGb >= 100 ? 0 : 4) . ($unit !== '' ? ' ' . $unit : '')
            . ' — دوره ' . Prepaid::monthLabel($month);
        $notes = 'Pasargad CDN object storage — service #' . $sid . ' — ' . $gbm . ' GB-month @ ' . $perGb
            . ($unit !== '' ? ' ' . $unit : '') . ' — ' . $domain . ' — ' . $month;

        if ($mode === 'invoice') {
            $r = Env::localApi('CreateInvoice', [
                'userid' => (int) $svc->userid, 'status' => 'Unpaid', 'sendinvoice' => true, 'autoapplycredit' => true,
                'date' => date('Y-m-d'), 'duedate' => date('Y-m-d'),
                'itemdescription1' => $desc, 'itemamount1' => $amount, 'itemtaxed1' => $tax > 0, 'notes' => $notes,
            ]);
            $inv = (int) ($r['invoiceid'] ?? 0);
            if (($r['result'] ?? '') !== 'success' || $inv <= 0) {
                return self::failed($rowId, $sid, (int) $svc->userid, 'CreateInvoice: ' . ($r['message'] ?? ''));
            }
            // mark the line as ours, linked to the service (never type Hosting: that would extend the due date)
            Capsule::table('tblinvoiceitems')->where('invoiceid', $inv)->where('type', '')->update(['type' => self::ITEM_TYPE, 'relid' => $sid]);
            Capsule::table(Env::STORAGE_BILLS)->where('id', $rowId)->update(['status' => 'invoiced', 'invoice_id' => $inv, 'updated_at' => date('Y-m-d H:i:s')]);
            Env::log('storage billing: ' . $gbm . ' GB-month of ' . $month . ' for service #' . $sid . ' (' . $domain . ') — invoice #' . $inv
                . ', ' . $amount, (int) $svc->userid);
            self::$report['billed'][] = ['service' => $sid, 'gb_month' => $gbm, 'amount' => $amount, 'invoice' => $inv];
            return true;
        }
        $r = Env::localApi('AddBillableItem', [
            'clientid' => (int) $svc->userid, 'description' => $desc, 'amount' => $amount,
            'invoiceaction' => 'nextcron', 'recur' => 0, 'duedate' => date('Y-m-d'),
        ]);
        $bid = (int) ($r['billableid'] ?? 0);
        if (($r['result'] ?? '') !== 'success' || $bid <= 0) {
            return self::failed($rowId, $sid, (int) $svc->userid, 'AddBillableItem: ' . ($r['message'] ?? ''));
        }
        Capsule::table(Env::STORAGE_BILLS)->where('id', $rowId)->update(['status' => 'billable', 'billable_id' => $bid, 'updated_at' => date('Y-m-d H:i:s')]);
        Env::log('storage billing: ' . $gbm . ' GB-month of ' . $month . ' for service #' . $sid . ' (' . $domain . ') — billable item #' . $bid
            . ', ' . $amount, (int) $svc->userid);
        self::$report['billed'][] = ['service' => $sid, 'gb_month' => $gbm, 'amount' => $amount, 'billable' => $bid];
        return true;
    }

    private static function failed(int $rowId, int $sid, int $userId, string $why): bool
    {
        Capsule::table(Env::STORAGE_BILLS)->where('id', $rowId)->update(['status' => 'failed', 'note' => substr($why, 0, 190), 'updated_at' => date('Y-m-d H:i:s')]);
        self::$report['errors'][] = 'service #' . $sid . ': ' . $why;
        Env::log('storage billing: charging service #' . $sid . ' failed (' . $why . ') — retried next hour', $userId);
        return false;
    }

    private static function currencyUnit(int $currencyId): string
    {
        $cur = Capsule::table('tblcurrencies')->where('id', $currencyId)->first(['code', 'suffix']);
        if (!$cur) {
            return '';
        }
        $s = trim((string) $cur->suffix);
        return $s !== '' ? $s : (string) $cur->code;
    }

    /** Last charges (admin settings page): newest first. */
    public static function recent(int $limit = 10): array
    {
        try {
            if (!Env::hasTable(Env::STORAGE_BILLS)) {
                return [];
            }
            return Capsule::table(Env::STORAGE_BILLS)->orderBy('id', 'desc')->limit($limit)->get()->all();
        } catch (\Throwable $e) {
            return [];
        }
    }
}
