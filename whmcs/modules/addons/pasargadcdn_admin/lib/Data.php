<?php

namespace PasargadCdn\Admin;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Data', false)) {
    return;
}

/**
 * WHMCS-side data for the admin pages (services, products, pricing) and the
 * matching between WHMCS services and controller sites.
 */
final class Data
{
    const LIVE = ['Active', 'Suspended'];

    public static function serviceQuery()
    {
        return Capsule::table('tblhosting as h')
            ->join('tblproducts as p', 'p.id', '=', 'h.packageid')
            ->leftJoin('tblclients as c', 'c.id', '=', 'h.userid')
            ->where('p.servertype', 'pasargadcdn');
    }

    const SERVICE_COLS = ['h.id', 'h.userid', 'h.packageid', 'h.server', 'h.domain', 'h.domainstatus', 'h.nextduedate',
        'h.billingcycle', 'h.bwusage', 'h.bwlimit', 'h.lastupdate', 'p.name as product', 'p.configoption1 as plan_gb',
        'p.overagesenabled', 'p.overagesbwlimit', 'p.overagesbwprice', 'c.firstname', 'c.lastname', 'c.companyname',
        'c.currency'];

    /**
     * Filtered, paginated CDN services.
     * @return array [rows, total]
     */
    public static function services(array $f, int $page = 1, int $per = 25): array
    {
        $q = self::serviceQuery();
        $term = trim((string) ($f['q'] ?? ''));
        if ($term !== '') {
            $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $term) . '%';
            $q->where(function ($w) use ($term, $like) {
                $w->where('h.domain', 'like', $like)->orWhere('c.firstname', 'like', $like)
                    ->orWhere('c.lastname', 'like', $like)->orWhere('c.companyname', 'like', $like)
                    ->orWhere('c.email', 'like', $like);
                if (preg_match('/^#?(\d{1,10})$/', $term, $m)) {
                    $w->orWhere('h.id', (int) $m[1]);
                }
            });
        }
        if (!empty($f['status'])) {
            $q->where('h.domainstatus', (string) $f['status']);
        }
        if (!empty($f['pid'])) {
            $q->where('h.packageid', (int) $f['pid']);
        }
        if (!empty($f['ids'])) {
            $q->whereIn('h.id', array_map('intval', (array) $f['ids']));
        }
        $total = (int) (clone $q)->count();
        $rows = $q->orderBy('h.id', 'desc')->offset(max(0, ($page - 1) * $per))->limit($per)->get(self::SERVICE_COLS)->all();
        return [$rows, $total];
    }

    /** Every CDN service (for the sync report / matching), minimal columns. */
    public static function allServices(): array
    {
        return self::serviceQuery()->orderBy('h.id')->get(['h.id', 'h.userid', 'h.packageid', 'h.domain', 'h.domainstatus',
            'h.server', 'p.name as product', 'c.firstname', 'c.lastname', 'c.companyname'])->all();
    }

    /** Active services on a product with tunnel mode (configoption15), 0 on any error. */
    public static function tunnelServices(): int
    {
        try {
            return (int) self::serviceQuery()->where('h.domainstatus', 'Active')->where('p.configoption15', 'on')->count();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    public static function statusCounts(): array
    {
        $out = [];
        foreach (self::serviceQuery()->groupBy('h.domainstatus')
                     ->get([Capsule::raw('h.domainstatus as s'), Capsule::raw('count(*) as n')]) as $r) {
            $out[(string) $r->s] = (int) $r->n;
        }
        return $out;
    }

    public static function clientName($r): string
    {
        $n = trim(((string) ($r->firstname ?? '')) . ' ' . ((string) ($r->lastname ?? '')));
        $co = trim((string) ($r->companyname ?? ''));
        if ($co !== '') {
            $n = $n !== '' ? $n . ' (' . $co . ')' : $co;
        }
        return $n !== '' ? $n : 'مشتری #' . (int) ($r->userid ?? 0);
    }

    public static function serviceUrl(int $userId, int $id): string
    {
        return 'clientsservices.php?userid=' . $userId . '&id=' . $id;
    }

    public static function clientUrl(int $userId): string
    {
        return 'clientssummary.php?userid=' . $userId;
    }

    /** Prepaid settings of a service row (SERVICE_COLS), or null. */
    public static function prepaid($svc, array $configoptions = []): ?array
    {
        if (!function_exists('pasargadcdn_prepaid')) {
            return null;
        }
        return \pasargadcdn_prepaid(['id' => (int) ($svc->packageid ?? 0), 'configoption1' => $svc->plan_gb ?? 0,
            'overagesenabled' => $svc->overagesenabled ?? '', 'overagesbwlimit' => $svc->overagesbwlimit ?? 0,
            'overagesbwprice' => $svc->overagesbwprice ?? 0], $configoptions);
    }

    /** Configurable option values of these services, one query ([sid => [name => value]]). */
    public static function configOptions(array $rows): array
    {
        if (!function_exists('pasargadcdn_config_options') || !$rows) {
            return [];
        }
        return \pasargadcdn_config_options(array_map(function ($r) {
            return (int) $r->id;
        }, $rows));
    }

    /** Traffic purchases of $month (newest first), with service/client facts. */
    public static function topups(string $month, int $limit = 500): array
    {
        if (!Env::hasTable(Env::TOPUPS)) {
            return [];
        }
        return Capsule::table(Env::TOPUPS . ' as t')
            ->leftJoin('tblhosting as h', 'h.id', '=', 't.service_id')
            ->leftJoin('tblclients as c', 'c.id', '=', 't.userid')
            ->leftJoin('tblcurrencies as cu', 'cu.id', '=', 't.currency')
            ->where('t.month', $month)->orderBy('t.id', 'desc')->limit($limit)
            ->get(['t.*', 'h.domain', 'c.firstname', 'c.lastname', 'c.companyname', 'cu.code as currency_code'])->all();
    }

    /** service id => ['gb' => paid GB, 'amount' => paid amount, 'code' => currency, 'invoices' => [ids]] for $month. */
    public static function topupSums(string $month): array
    {
        $out = [];
        foreach (self::topups($month, 100000) as $t) {
            if ($t->status !== 'paid') {
                continue;
            }
            $o = $out[(int) $t->service_id] ?? ['gb' => 0, 'amount' => 0.0, 'code' => (string) $t->currency_code, 'invoices' => []];
            $o['gb'] += (int) $t->gb;
            $o['amount'] += (float) $t->amount;
            if ($t->invoice_id) {
                $o['invoices'][] = (int) $t->invoice_id;
            }
            $out[(int) $t->service_id] = $o;
        }
        return $out;
    }

    // ------------------------------------------------------------------ products / pricing

    public static function products(): array
    {
        $cols = ['p.*', 'g.name as group_name', 'sg.name as servergroup_name'];
        return Capsule::table('tblproducts as p')
            ->leftJoin('tblproductgroups as g', 'g.id', '=', 'p.gid')
            ->leftJoin('tblservergroups as sg', 'sg.id', '=', 'p.servergroup')
            ->where('p.servertype', 'pasargadcdn')->orderBy('p.gid')->orderBy('p.order')->orderBy('p.id')
            ->get($cols)->all();
    }

    public static function currencies(): array
    {
        try {
            return Capsule::table('tblcurrencies')->orderBy('default', 'desc')->orderBy('id')->get()->all();
        } catch (\Throwable $e) {
            return [];
        }
    }

    /** relid => currency => row */
    public static function pricing(array $pids): array
    {
        $out = [];
        if (!$pids) {
            return $out;
        }
        foreach (Capsule::table('tblpricing')->where('type', 'product')->whereIn('relid', $pids)->get() as $r) {
            $out[(int) $r->relid][(int) $r->currency] = $r;
        }
        return $out;
    }

    // ------------------------------------------------------------------ WHMCS ↔ controller matching

    /**
     * Index controller sites (from /api/v1/usage or /api/v1/sites) by external id and domain.
     * @return array ['ext' => [id => site], 'domain' => [domain => site]]
     */
    public static function siteIndex(array $sites): array
    {
        $ix = ['ext' => [], 'domain' => []];
        foreach ($sites as $s) {
            if (!is_array($s) || empty($s['domain'])) {
                continue;
            }
            $ix['domain'][strtolower((string) $s['domain'])] = $s;
            $ext = (string) ($s['external_id'] ?? '');
            if ($ext !== '' && ctype_digit($ext)) {
                $ix['ext'][(int) $ext] = $s;
            }
        }
        return $ix;
    }

    /** Controller site of a WHMCS service, or null. Sets $conflict when the domain belongs to another service. */
    public static function siteFor($svc, array $ix, &$conflict = null)
    {
        $conflict = null;
        $id = (int) $svc->id;
        $d = Env::domain((string) $svc->domain);
        if (isset($ix['ext'][$id]) && strtolower((string) $ix['ext'][$id]['domain']) === $d) {
            return $ix['ext'][$id];
        }
        if (isset($ix['domain'][$d])) {
            $s = $ix['domain'][$d];
            $ext = (string) ($s['external_id'] ?? '');
            if ($ext === '' || $ext === (string) $id) {
                return $s;
            }
            $conflict = $s;
        }
        return null;
    }

    /**
     * Sync report between WHMCS and the controller.
     * missing:   live WHMCS services with no site on the controller (fix: ModuleCreate)
     * conflicts: live WHMCS services whose domain is on the controller for another external id
     * orphans:   controller sites with no live WHMCS CDN service (fix: delete on controller)
     */
    public static function sync(array $sites): array
    {
        $ix = self::siteIndex($sites);
        $services = self::allServices();
        $missing = $conflicts = $orphans = [];
        $claimed = [];
        $byId = [];
        foreach ($services as $svc) {
            $byId[(int) $svc->id] = $svc;
            $live = in_array((string) $svc->domainstatus, self::LIVE, true);
            $site = self::siteFor($svc, $ix, $conflict);
            if ($site) {
                if ($live || (string) $svc->domainstatus === 'Pending') {
                    $claimed[strtolower((string) $site['domain'])] = true;
                }
                continue;
            }
            if (!$live) {
                continue;
            }
            if ($conflict) {
                $conflicts[] = ['service' => $svc, 'site' => $conflict];
            } else {
                $missing[] = $svc;
            }
        }
        foreach ($ix['domain'] as $domain => $site) {
            if (isset($claimed[$domain])) {
                continue;
            }
            $ext = (string) ($site['external_id'] ?? '');
            $svc = ($ext !== '' && ctype_digit($ext)) ? ($byId[(int) $ext] ?? null) : null;
            // A conflicting live service still owns the domain in WHMCS terms: not an orphan.
            $owned = false;
            foreach ($conflicts as $c) {
                if (strtolower((string) $c['site']['domain']) === $domain && $svc && in_array((string) $svc->domainstatus, self::LIVE, true)) {
                    $owned = true;
                }
            }
            if ($svc && in_array((string) $svc->domainstatus, array_merge(self::LIVE, ['Pending']), true)) {
                $owned = true;
            }
            if (!$owned) {
                $orphans[] = ['site' => $site, 'service' => $svc];
            }
        }
        return ['missing' => $missing, 'conflicts' => $conflicts, 'orphans' => $orphans];
    }

    /** Is $domain an orphan right now (re-checked before deleting it on the controller)? */
    public static function isOrphan(string $domain, array $sites): bool
    {
        foreach (self::sync($sites)['orphans'] as $o) {
            if (strtolower((string) $o['site']['domain']) === strtolower($domain)) {
                return true;
            }
        }
        return false;
    }

    /** domain => service row, for linking controller data back to WHMCS. */
    public static function servicesByDomain(): array
    {
        $out = [];
        foreach (self::allServices() as $svc) {
            $d = Env::domain((string) $svc->domain);
            if ($d === '') {
                continue;
            }
            // Prefer live services over terminated ones for the same domain.
            if (!isset($out[$d]) || in_array((string) $svc->domainstatus, self::LIVE, true)) {
                $out[$d] = $svc;
            }
        }
        return $out;
    }
}
