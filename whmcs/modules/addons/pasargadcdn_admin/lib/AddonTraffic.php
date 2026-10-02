<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\AddonTraffic', false)) {
    return;
}

/**
 * Wave 7 (SPEC §15.7) — «بسته‌ی ترافیک افزوده» product add-ons.
 *
 * The wizard creates one one-time add-on per size (10 / 50 / 100 GB by default) and remembers
 * id → GB in mod_pasargadcdn_settings (`traffic_addons`); a renamed add-on is still recognised
 * by the GB number in its name. When an invoice with such an add-on line is paid (InvoicePaid):
 *  - each invoice item is claimed once in mod_pasargadcdn_addon_items (primary key = item id),
 *    so a re-fired hook, a second payment or a parallel cron never applies it twice;
 *  - a paid row with blocks = 0 is written to mod_pasargadcdn_topups for the CURRENT month — the
 *    same ledger as prepaid top-ups, so the wallet card, the statement, pasargadcdn_cap_plan() and
 *    the prepaid cron's cap repair all include it, while the monthly auto-purchase limit does not;
 *  - the controller cap is PATCHed to plan GB + this month's traffic (prepaid: + all top-ups);
 *    a failed PATCH is retried by the cron (cap_ok = 0), and every step is logged.
 * Non-prepaid services get their cap back to the plan on the first cron run of a new month.
 */
final class AddonTraffic
{
    const KV_MAP = 'traffic_addons';

    /** @var array report of the last call (tests / admin) */
    public static $report = [];

    /** Standalone entry (reads the invoice's add-on lines itself). Never throws. */
    public static function onInvoicePaid(int $invoiceId): void
    {
        if ($invoiceId <= 0) {
            return;
        }
        try {
            $items = Capsule::table('tblinvoiceitems')->where('invoiceid', $invoiceId)->where('type', 'Addon')
                ->get(['id', 'type', 'relid', 'amount', 'userid'])->all();
        } catch (\Throwable $e) {
            return;
        }
        self::applyItems($invoiceId, $items);
    }

    /**
     * The hook path: Prepaid::onInvoicePaid() reads the paid invoice's lines ONCE and hands the
     * «Addon» lines over here (an ordinary invoice therefore still costs one query). Never throws.
     */
    public static function applyItems(int $invoiceId, array $items): void
    {
        self::$report = ['applied' => [], 'skipped' => [], 'errors' => []];
        try {
            if (!$items || !Env::hasTable('tblhostingaddons') || !Env::loadServerModule()) {
                return;
            }
            $sizes = self::sizes();
            if (!$sizes) {
                return;
            }
            $cols = ['id', 'hostingid', 'addonid'];
            if (Env::hasColumn('tblhostingaddons', 'qty')) {
                $cols[] = 'qty';
            }
            $ha = [];
            foreach (Capsule::table('tblhostingaddons')->whereIn('id', array_map(function ($i) {
                return (int) $i->relid;
            }, $items))->get($cols) as $r) {
                $ha[(int) $r->id] = $r;
            }
            foreach ($items as $it) {
                $h = $ha[(int) $it->relid] ?? null;
                if (!$h || !isset($sizes[(int) $h->addonid])) {
                    continue; // some other add-on
                }
                $qty = isset($h->qty) && (int) $h->qty > 1 ? (int) $h->qty : 1;
                self::apply($invoiceId, $it, $h, $sizes[(int) $h->addonid] * $qty);
            }
        } catch (\Throwable $e) {
            self::$report['errors'][] = $e->getMessage();
            Env::log('add-on traffic: InvoicePaid #' . $invoiceId . ' error: ' . $e->getMessage());
        }
    }

    /** addon id => GB of every «بسته‌ی ترافیک افزوده» add-on (remembered map + name fallback). */
    public static function sizes(): array
    {
        $out = [];
        foreach ((array) Env::kvGet(self::KV_MAP, []) as $id => $gb) {
            if ((int) $id > 0 && (int) $gb > 0) {
                $out[(int) $id] = (int) $gb;
            }
        }
        if (Env::hasTable('tbladdons')) {
            foreach (Capsule::table('tbladdons')->where('name', 'like', '%' . Wizard::ADDON_NAME . '%')->get(['id', 'name']) as $a) {
                if (isset($out[(int) $a->id])) {
                    continue;
                }
                $name = strtr((string) $a->name, ['۰' => '0', '۱' => '1', '۲' => '2', '۳' => '3', '۴' => '4', '۵' => '5', '۶' => '6', '۷' => '7', '۸' => '8', '۹' => '9', '٬' => '', ',' => '']);
                if (preg_match('/(\d{1,6})\s*(?:GB|G\b|گیگ)/iu', $name, $m) && (int) $m[1] > 0) {
                    $out[(int) $a->id] = (int) $m[1];
                }
            }
        }
        return $out;
    }

    private static function apply(int $invoiceId, $item, $ha, int $gb): void
    {
        if (!Env::hasTable(Env::ADDON_ITEMS) || !Env::hasTable(Env::TOPUPS)) {
            Env::ensureTable();
        }
        $month = \pasargadcdn_month();
        $now = date('Y-m-d H:i:s');
        // claim this invoice line exactly once
        try {
            Capsule::table(Env::ADDON_ITEMS)->insert(['invoice_item_id' => (int) $item->id, 'invoice_id' => $invoiceId,
                'service_id' => (int) $ha->hostingid, 'hostingaddon_id' => (int) $ha->id, 'gb' => $gb, 'month' => $month,
                'status' => 'pending', 'cap_ok' => 0, 'created_at' => $now]);
        } catch (\Throwable $e) {
            self::$report['skipped'][] = ['item' => (int) $item->id, 'why' => 'already applied'];
            return;
        }
        $svc = self::service((int) $ha->hostingid);
        if (!$svc) {
            Capsule::table(Env::ADDON_ITEMS)->where('invoice_item_id', (int) $item->id)->update(['status' => 'skipped']);
            self::$report['skipped'][] = ['item' => (int) $item->id, 'why' => 'not a CDN service'];
            Env::log('add-on traffic: invoice #' . $invoiceId . ' item #' . (int) $item->id . ' — service #' . (int) $ha->hostingid . ' is not a live CDN service; nothing applied');
            return;
        }
        $currency = (int) Capsule::table('tblclients')->where('id', (int) $svc->userid)->value('currency');
        $rowId = 0;
        for ($try = 0; $try < 5 && !$rowId; $try++) {
            $seq = (int) Capsule::table(Env::TOPUPS)->where('service_id', (int) $svc->id)->where('month', $month)->max('seq') + 1;
            try {
                $rowId = (int) Capsule::table(Env::TOPUPS)->insertGetId(['service_id' => (int) $svc->id, 'userid' => (int) $svc->userid,
                    'month' => $month, 'seq' => $seq, 'blocks' => 0, 'gb' => $gb, 'amount' => round((float) $item->amount, 2),
                    'currency' => $currency, 'invoice_id' => $invoiceId, 'status' => 'paid', 'created_at' => $now, 'updated_at' => $now]);
            } catch (\Throwable $e) {
                $rowId = 0; // a concurrent purchase took this slot: next one
            }
        }
        if (!$rowId) {
            Capsule::table(Env::ADDON_ITEMS)->where('invoice_item_id', (int) $item->id)->delete(); // let a later InvoicePaid retry
            self::$report['errors'][] = 'no top-up slot for #' . (int) $svc->id;
            Env::log('add-on traffic: could not record ' . $gb . ' GB for service #' . (int) $svc->id . ' (invoice #' . $invoiceId . ') — will retry', (int) $svc->userid);
            return;
        }
        Capsule::table(Env::ADDON_ITEMS)->where('invoice_item_id', (int) $item->id)->update(['status' => 'applied', 'topup_id' => $rowId]);
        $cap = self::cap($svc);
        $ok = $cap === null ? true : self::patch($svc, $cap);
        Capsule::table(Env::ADDON_ITEMS)->where('invoice_item_id', (int) $item->id)->update(['cap_ok' => $ok ? 1 : 0]);
        self::$report['applied'][] = ['service' => (int) $svc->id, 'gb' => $gb, 'item' => (int) $item->id, 'cap' => $cap, 'patched' => $ok];
        Env::log('add-on traffic: +' . $gb . ' GB for service #' . (int) $svc->id . ' (' . Env::domain((string) $svc->domain) . ') — invoice #' . $invoiceId
            . ', item #' . (int) $item->id . ' — ' . ($cap === null ? 'unlimited plan, cap unchanged' : 'cap ' . $cap . ' GB' . ($ok ? '' : ' (controller update failed, retried by cron)')), (int) $svc->userid);
    }

    /** Live CDN service with its product row. */
    private static function service(int $sid)
    {
        $r = Capsule::table('tblhosting as h')->join('tblproducts as p', 'p.id', '=', 'h.packageid')
            ->where('h.id', $sid)->whereNotIn('h.domainstatus', Env::DEAD_STATUSES)
            ->first(['h.id', 'h.userid', 'h.server', 'h.domain', 'h.domainstatus', 'p.id as pid', 'p.servertype']);
        return $r && $r->servertype === 'pasargadcdn' ? $r : null;
    }

    /** Controller cap for this month: prepaid plan GB + all paid top-ups, else plan GB + add-ons; null = unlimited plan. */
    public static function cap($svc): ?int
    {
        $row = \pasargadcdn_product_row((int) $svc->pid);
        $co = \pasargadcdn_config_options([(int) $svc->id])[(int) $svc->id] ?? [];
        $plan = \pasargadcdn_plan(['configoption1' => $row['configoption1'] ?? '', 'configoptions' => $co])['bandwidth_limit_gb'];
        // SPEC §21: an explicit bandwidth override («امکانات اختصاصی») replaces the plan GB; 0 = unlimited (no cap)
        $ov = \PasargadCdn\FeatureOverrides::bandwidth((int) $svc->id);
        if ($ov !== null) {
            $plan = $ov;
        }
        if ($plan <= 0) {
            return null;
        }
        $pp = $row ? \PasargadCdn\FeatureOverrides::prepaid((int) $svc->id, \pasargadcdn_prepaid($row, $co)) : null;
        return $pp !== null ? $pp['plan_gb'] + \pasargadcdn_topup_gb((int) $svc->id) : $plan + \pasargadcdn_addon_gb((int) $svc->id);
    }

    private static function patch($svc, int $cap): bool
    {
        $server = Capsule::table('tblservers')->where('id', (int) $svc->server)->first();
        $domain = Env::domain((string) $svc->domain);
        if (!$server || $server->type !== 'pasargadcdn' || !Env::validHostname($domain)) {
            return false;
        }
        try {
            Env::api(10, $server)->patch(ApiClient::site($domain) . '/plan', ['bandwidth_limit_gb' => $cap]);
            return true;
        } catch (\Throwable $e) {
            self::$report['errors'][] = 'patch #' . (int) $svc->id . ': ' . $e->getMessage();
            return false;
        }
    }

    /**
     * AfterCronJob: retry caps whose PATCH failed; on the first run of a new month put the caps of
     * non-prepaid services that had add-on traffic last month back to their plan (prepaid services
     * are reset by Prepaid::rollover). Never throws.
     */
    public static function onCron(): void
    {
        self::$report = ['applied' => [], 'skipped' => [], 'errors' => [], 'retried' => [], 'rollover' => []];
        try {
            // only installs whose wizard created the add-ons (flag in the memoised addon settings: no query otherwise)
            if (!Env::loadServerModule() || (\pasargadcdn_addon_settings()['traffic_addon_on'] ?? '') !== 'on' || !Env::cdnProductIds() || !Env::hasTable(Env::ADDON_ITEMS)) {
                return;
            }
            $month = \pasargadcdn_month();
            foreach (Capsule::table(Env::ADDON_ITEMS)->where('status', 'applied')->where('cap_ok', 0)->where('month', $month)->limit(50)->get() as $r) {
                $svc = self::service((int) $r->service_id);
                $cap = $svc ? self::cap($svc) : null;
                if (!$svc || $cap === null || self::patch($svc, $cap)) {
                    Capsule::table(Env::ADDON_ITEMS)->where('invoice_item_id', (int) $r->invoice_item_id)->update(['cap_ok' => 1]);
                    self::$report['retried'][] = (int) $r->service_id;
                }
            }
            if (Env::kvGet('addon_month') !== $month) {
                $prev = gmdate('Y-m', strtotime($month . '-01 12:00:00 UTC -1 month'));
                $sids = array_unique(array_map('intval', Capsule::table(Env::ADDON_ITEMS)->where('month', $prev)->where('status', 'applied')->pluck('service_id')->all()));
                foreach ($sids as $sid) {
                    $svc = self::service($sid);
                    if (!$svc || !in_array($svc->domainstatus, ['Active', 'Suspended'], true)) {
                        continue;
                    }
                    $row = \pasargadcdn_product_row((int) $svc->pid);
                    $co = \pasargadcdn_config_options([$sid])[$sid] ?? [];
                    if ($row && \pasargadcdn_prepaid($row, $co) !== null) {
                        continue; // Prepaid::rollover owns these
                    }
                    $cap = self::cap($svc);
                    if ($cap !== null && self::patch($svc, $cap)) {
                        self::$report['rollover'][] = $sid;
                    }
                }
                Env::kvSet('addon_month', $month);
                if (self::$report['rollover']) {
                    Env::log('add-on traffic: new month ' . $month . ' — caps of ' . count(self::$report['rollover']) . ' services back to their plans');
                }
            }
        } catch (\Throwable $e) {
            Env::log('add-on traffic cron error: ' . $e->getMessage());
        }
    }
}
