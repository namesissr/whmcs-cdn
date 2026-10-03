<?php

namespace PasargadCdn\Admin;

use PasargadCdn\Reseller;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Resellers', false)) {
    return;
}

/**
 * Admin-side data for the «نمایندگان» page (SPEC §10.5): the list of clients
 * flagged reseller with their sub-site counts, current-month aggregate usage
 * (from the controller) and wholesale revenue (paid reseller top-ups), plus the
 * writes that flag/unflag a client and set per-reseller rate / max-sites / state.
 *
 * All reads are of the reseller ledger only; the per-service prepaid engine is
 * never touched here.
 */
final class Resellers
{
    /** Effective global defaults for the settings block. */
    public static function globalRate(): string
    {
        return Env::setting('reseller_rate', '');
    }

    public static function globalMaxSites(): string
    {
        return Env::setting('reseller_max_sites', '20');
    }

    /**
     * All flagged resellers with client facts, sub-site count, month GB and revenue.
     * @return array list of rows [userid, name, email, enabled, rate, max_sites, note, sites, gb, revenue(array code=>amount)]
     */
    public static function listAll(?array $usageByDomain = null): array
    {
        if (!Env::hasTable(Env::RESELLERS)) {
            return [];
        }
        $rows = Capsule::table(Env::RESELLERS . ' as r')
            ->leftJoin('tblclients as c', 'c.id', '=', 'r.userid')
            ->orderBy('r.enabled', 'desc')->orderBy('r.userid')
            ->get(['r.userid', 'r.enabled', 'r.rate', 'r.max_sites', 'r.note',
                'c.firstname', 'c.lastname', 'c.companyname', 'c.email'])->all();
        if (!$rows) {
            return [];
        }
        $ids = array_map(function ($r) {
            return (int) $r->userid;
        }, $rows);
        // sub-site rows grouped by reseller
        $sitesByUser = [];
        if (Env::hasTable(Env::RESELLER_SITES)) {
            foreach (Capsule::table(Env::RESELLER_SITES)->whereIn('userid', $ids)->get(['userid', 'domain', 'suspended']) as $s) {
                $sitesByUser[(int) $s->userid][] = $s;
            }
        }
        $month = \pasargadcdn_month();
        $revByUser = self::revenue($ids, $month);
        $out = [];
        foreach ($rows as $r) {
            $uid = (int) $r->userid;
            $mySites = $sitesByUser[$uid] ?? [];
            $gb = 0.0;
            if ($usageByDomain !== null) {
                foreach ($mySites as $s) {
                    $d = strtolower(Env::domain((string) $s->domain));
                    $gb += $usageByDomain[$d] ?? 0.0;
                }
            }
            $out[] = [
                'userid' => $uid,
                'name' => Data::clientName($r),
                'email' => (string) ($r->email ?? ''),
                'enabled' => (int) $r->enabled === 1,
                'rate' => $r->rate !== null ? (float) $r->rate : null,
                'max_sites' => (int) $r->max_sites,
                'note' => (string) ($r->note ?? ''),
                'sites' => count($mySites),
                'suspended_sites' => count(array_filter($mySites, function ($s) {
                    return (int) $s->suspended === 1;
                })),
                'gb' => round($gb, 2),
                'revenue' => $revByUser[$uid] ?? [],
            ];
        }
        return $out;
    }

    /** Controller domain => month GB, for the aggregate usage column (one GET). null on error. */
    public static function usageByDomain(): ?array
    {
        try {
            $data = Env::api(10)->get('/api/v1/usage?month=' . \pasargadcdn_month());
        } catch (\Throwable $e) {
            return null;
        }
        $out = [];
        foreach ((array) ($data['sites'] ?? []) as $s) {
            $d = strtolower((string) ($s['domain'] ?? ''));
            if ($d !== '') {
                $out[$d] = (float) ($s['bytes'] ?? 0) / 1073741824;
            }
        }
        return $out;
    }

    /** userid => [currency code => paid amount] for the month's reseller top-ups. */
    public static function revenue(array $ids, string $month): array
    {
        $out = [];
        if (!$ids || !Env::hasTable(Env::RESELLER_TOPUPS)) {
            return $out;
        }
        $rows = Capsule::table(Env::RESELLER_TOPUPS . ' as t')
            ->leftJoin('tblcurrencies as cu', 'cu.id', '=', 't.currency')
            ->where('t.month', $month)->where('t.status', 'paid')->whereIn('t.userid', $ids)
            ->get(['t.userid', 't.amount', 'cu.code'])->all();
        foreach ($rows as $r) {
            $uid = (int) $r->userid;
            $code = (string) ($r->code ?? '');
            $out[$uid][$code] = ($out[$uid][$code] ?? 0.0) + (float) $r->amount;
        }
        return $out;
    }

    /** Recent reseller top-ups (for the page's purchases panel). */
    public static function topups(string $month, int $limit = 200): array
    {
        if (!Env::hasTable(Env::RESELLER_TOPUPS)) {
            return [];
        }
        return Capsule::table(Env::RESELLER_TOPUPS . ' as t')
            ->leftJoin('tblclients as c', 'c.id', '=', 't.userid')
            ->leftJoin('tblcurrencies as cu', 'cu.id', '=', 't.currency')
            ->where('t.month', $month)->orderBy('t.id', 'desc')->limit($limit)
            ->get(['t.*', 'c.firstname', 'c.lastname', 'c.companyname', 'cu.code as currency_code'])->all();
    }

    /** Sub-site rows of one reseller with client facts (admin detail). */
    public static function sitesOf(int $userid): array
    {
        if (!Env::hasTable(Env::RESELLER_SITES)) {
            return [];
        }
        return Capsule::table(Env::RESELLER_SITES)->where('userid', $userid)->orderBy('id', 'desc')->get()->all();
    }

    // ------------------------------------------------------------------ resolve / writes

    /** Resolve a client by numeric id, e-mail, or name. Returns the tblclients id or 0. */
    public static function resolveClient(string $q): int
    {
        $q = trim($q);
        if ($q === '') {
            return 0;
        }
        try {
            if (preg_match('/^#?(\d{1,10})$/', $q, $m)) {
                $id = (int) $m[1];
                return Capsule::table('tblclients')->where('id', $id)->exists() ? $id : 0;
            }
            if (strpos($q, '@') !== false) {
                $id = (int) Capsule::table('tblclients')->where('email', $q)->value('id');
                return $id;
            }
            // name / company — exact-ish match, single hit only
            $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $q) . '%';
            $rows = Capsule::table('tblclients')->where(function ($w) use ($like, $q) {
                $w->where('companyname', 'like', $like)
                    ->orWhereRaw("TRIM(CONCAT(firstname,' ',lastname)) like ?", [$like]);
            })->limit(2)->pluck('id')->all();
            return count($rows) === 1 ? (int) $rows[0] : 0;
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** Flag a client as reseller (enabled), creating or re-enabling the row. */
    public static function flag(int $userid): void
    {
        $now = date('Y-m-d H:i:s');
        $q = Capsule::table(Env::RESELLERS)->where('userid', $userid);
        if ($q->exists()) {
            $q->update(['enabled' => 1, 'updated_at' => $now]);
        } else {
            Capsule::table(Env::RESELLERS)->insert(['userid' => $userid, 'enabled' => 1, 'rate' => null,
                'max_sites' => 0, 'note' => null, 'created_at' => $now, 'updated_at' => $now]);
        }
    }

    /** Per-reseller update: rate (null clears), max_sites, enabled, note. */
    public static function save(int $userid, ?float $rate, int $maxSites, bool $enabled, ?string $note): bool
    {
        if (!Capsule::table(Env::RESELLERS)->where('userid', $userid)->exists()) {
            return false;
        }
        Capsule::table(Env::RESELLERS)->where('userid', $userid)->update([
            'rate' => $rate,
            'max_sites' => max(0, $maxSites),
            'enabled' => $enabled ? 1 : 0,
            'note' => $note !== null && $note !== '' ? mb_substr($note, 0, 191) : null,
            'updated_at' => date('Y-m-d H:i:s'),
        ]);
        return true;
    }
}
