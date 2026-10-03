<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\DomainRules', false)) {
    return;
}

/**
 * Domain ownership rules shared by the checkout (addon CartValidator) and the reseller sub-site create path
 * (security review C1): a domain may not be a public suffix, and may not be a parent or a child of a domain
 * that belongs to ANOTHER client's live CDN service or reseller sub-site (sub.victim.com while victim.com is
 * someone else's, or victim.com while sub.victim.com is). The same client may freely nest its own domains.
 * The controller enforces the same rule; this is the early, friendly check. The suffix list lives here only.
 */
class DomainRules
{
    /** Public suffixes (registries' second levels) that can never be ordered as a site. Lower case. */
    const PUBLIC_SUFFIXES = [
        // Iran (IRNIC)
        'ir', 'co.ir', 'ac.ir', 'gov.ir', 'org.ir', 'net.ir', 'sch.ir', 'id.ir',
        // common ccTLD second levels
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
        'com.tr', 'net.tr', 'org.tr', 'gen.tr', 'biz.tr', 'av.tr', 'edu.tr', 'gov.tr',
        'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'co.in', 'com.br', 'com.cn', 'com.hk',
        'co.za', 'com.sg', 'com.my', 'co.kr', 'com.mx', 'com.ar', 'co.il', 'com.ua', 'com.ru', 'com.af', 'com.iq',
        'com.sa', 'ae.org', 'co.ae', 'com.pk', 'com.eg',
        // generic
        'com', 'net', 'org', 'info', 'biz', 'io', 'co', 'me', 'xyz', 'online', 'site', 'app', 'dev',
    ];
    const DEAD = ['Terminated', 'Cancelled', 'Fraud'];

    public static function norm(string $d): string
    {
        $d = strtolower(trim($d));
        $d = (string) preg_replace('#^[a-z][a-z0-9+.-]*://#', '', $d);
        $d = (string) preg_replace('#[/?\#].*$#', '', $d);
        $d = (string) preg_replace('#:\d+$#', '', $d);
        return (string) preg_replace('/^www\./', '', rtrim($d, '.'));
    }

    public static function isPublicSuffix(string $d): bool
    {
        $d = self::norm($d);
        return $d !== '' && (strpos($d, '.') === false || in_array($d, self::PUBLIC_SUFFIXES, true));
    }

    /** Proper parent domains of $d that are not public suffixes (a.b.c.ir → b.c.ir, c.ir). */
    public static function parents(string $d): array
    {
        $labels = explode('.', self::norm($d));
        $out = [];
        for ($i = 1; $i < count($labels) - 1; $i++) {
            $p = implode('.', array_slice($labels, $i));
            if (!self::isPublicSuffix($p)) {
                $out[] = $p;
            }
        }
        return $out;
    }

    /** Is $a a parent or a child of $b (both normalised, not equal)? */
    public static function nested(string $a, string $b): bool
    {
        return $a !== $b && $a !== '' && $b !== '' && (substr($a, -strlen('.' . $b)) === '.' . $b || substr($b, -strlen('.' . $a)) === '.' . $a);
    }

    /**
     * Domains of live CDN rows (tblhosting on $pids, reseller sub-sites) related to $d: equal, parent or child.
     * @return array list of ['domain', 'userid', 'status', 'kind' => service|reseller]
     */
    public static function related(string $d, array $pids, bool $resellerSites = true): array
    {
        $d = self::norm($d);
        if ($d === '') {
            return [];
        }
        $exact = [];
        foreach (array_merge([$d], self::parents($d)) as $x) {
            $exact[] = $x;
            $exact[] = 'www.' . $x;
        }
        $out = [];
        $keep = function (string $raw) use ($d) {
            $n = self::norm($raw);
            return $n === $d || self::nested($n, $d) ? $n : null;
        };
        if ($pids) {
            $rows = Capsule::table('tblhosting')->whereIn('packageid', $pids)->whereNotIn('domainstatus', self::DEAD)
                ->where(function ($q) use ($exact, $d) {
                    $q->whereIn('domain', $exact)->orWhere('domain', 'like', '%.' . $d . '%');
                })->get(['domain', 'userid', 'domainstatus'])->all();
            foreach ($rows as $r) {
                if (($n = $keep((string) $r->domain)) !== null) {
                    $out[] = ['domain' => $n, 'userid' => (int) $r->userid, 'status' => (string) $r->domainstatus, 'kind' => 'service'];
                }
            }
        }
        if ($resellerSites && Capsule::schema()->hasTable('mod_pasargadcdn_reseller_sites')) {
            $rows = Capsule::table('mod_pasargadcdn_reseller_sites')->where(function ($q) use ($exact, $d) {
                $q->whereIn('domain', $exact)->orWhere('domain', 'like', '%.' . $d);
            })->get(['domain', 'userid'])->all();
            foreach ($rows as $r) {
                if (($n = $keep((string) $r->domain)) !== null) {
                    $out[] = ['domain' => $n, 'userid' => (int) $r->userid, 'status' => 'Active', 'kind' => 'reseller'];
                }
            }
        }
        return $out;
    }

    /**
     * The first parent/child domain of $d owned by someone other than $userid (0 = unknown visitor: every owner
     * is "someone else"), or null. Exact matches are left to the callers' own duplicate rules.
     */
    public static function foreignNested(string $d, int $userid, array $rows): ?string
    {
        $d = self::norm($d);
        foreach ($rows as $r) {
            if ($r['domain'] !== $d && ($userid <= 0 || $r['userid'] !== $userid) && self::nested($r['domain'], $d)) {
                return $r['domain'];
            }
        }
        return null;
    }
}
