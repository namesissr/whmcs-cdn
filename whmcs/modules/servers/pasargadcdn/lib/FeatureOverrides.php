<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\FeatureOverrides', false)) {
    return;
}

/**
 * SPEC §21 — per-domain feature overrides («امکانات اختصاصی»), set by the admin addon, applied by this module.
 *
 * One row per scope in mod_pasargadcdn_feature_overrides: `key` = "service:<id>" (a CDN service) or "domain:<domain>" (an
 * operator site), `overrides` = JSON {"v": {field: value}, "base": {field: value}} where a field is a top-level plan field
 * (bandwidth_limit_gb, max_records, ssl_allowed, rate_limit_rps) or "features.<key>" (any key of the controller's plan
 * features), and "base" keeps, for fields the product plan does not send (or every field of an operator site), the value the
 * site had before the override — so clearing restores it (PATCH /plan merges features; it never removes a key).
 *
 * pasargadcdn_plan() merges the overrides of "service:<serviceid>" on top of the product plan for every caller that passes a
 * service id (Create, ChangePackage, Unsuspend / renew resync, the addon's bulk pushes, transfers) — the one place a plan is
 * built — unless the caller asks for the bare product plan ('pcdn_plan_base'). Every read degrades to "no overrides" when the
 * table cannot be read (older install, test stubs); one query per scope and request (memoised).
 */
final class FeatureOverrides
{
    const TABLE = 'mod_pasargadcdn_feature_overrides';
    const TOP = ['bandwidth_limit_gb', 'max_records', 'ssl_allowed', 'rate_limit_rps'];
    /** Controller ranges (routes_admin.Plan / sections.Features); a field missing here is validated by its type only. */
    const RANGES = [
        'bandwidth_limit_gb' => [0, 100000000], 'max_records' => [1, 10000], 'rate_limit_rps' => [0, 100000],
        'features.max_page_rules' => [0, 1000], 'features.max_firewall_rules' => [0, 1000], 'features.max_ratelimit_rules' => [0, 1000],
        'features.max_pools' => [0, 100], 'features.max_tunnel_paths' => [0, 50], 'features.max_tunnel_connections' => [0, 1000000],
        'features.tunnel_max_mbps' => [0, 100000], 'features.max_transform_rules' => [0, 1000], 'features.max_redirects' => [0, 10000],
        'features.max_webhooks' => [0, 50], 'features.sla_target' => [0, 100], 'features.max_l4_apps' => [0, 100],
        'features.storage_gb' => [0, 1000000], 'features.max_functions' => [0, 32],
        'features.max_tunnel_origins' => [1, 10],
    ];
    const ENUMS = ['features.edge_group' => ['general', 'tunnel']];
    const FIELD_RE = '/^(?:bandwidth_limit_gb|max_records|ssl_allowed|rate_limit_rps|features\.[a-z][a-z0-9_]{0,47})$/D';

    private static $memo = [];

    public static function reset(): void
    {
        self::$memo = [];
    }

    /** Scope key of module params: "service:<id>", "domain:<operator domain>" ('pcdn_operator_domain') or ''. */
    public static function keyOf(array $params): string
    {
        if (!empty($params['pcdn_plan_base'])) {
            return '';
        }
        $sid = (int) ($params['serviceid'] ?? 0);
        if ($sid > 0) {
            return 'service:' . $sid;
        }
        $d = strtolower(trim((string) ($params['pcdn_operator_domain'] ?? '')));
        return $d !== '' ? 'domain:' . $d : '';
    }

    public static function serviceKey(int $sid): string
    {
        return 'service:' . $sid;
    }

    public static function domainKey(string $domain): string
    {
        return 'domain:' . strtolower(trim($domain));
    }

    /** Creates the table when missing (addon activation / 1.6.0 upgrade / first save). Never throws. */
    public static function ensure(): bool
    {
        try {
            $schema = Capsule::schema();
            if (!$schema->hasTable(self::TABLE)) {
                $schema->create(self::TABLE, function ($t) {
                    $t->increments('id');
                    $t->string('key', 191)->unique('mod_pcdn_fo_key');
                    $t->text('overrides')->nullable();
                    $t->integer('admin_id')->default(0);
                    $t->dateTime('updated_at')->nullable();
                });
            }
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** ['v' => [field => value], 'base' => [field => value], 'admin_id', 'updated_at'] of a scope (empty when none). */
    public static function get(string $key): array
    {
        $empty = ['v' => [], 'base' => [], 'admin_id' => 0, 'updated_at' => null];
        if ($key === '') {
            return $empty;
        }
        if (!array_key_exists($key, self::$memo)) {
            $out = $empty;
            try {
                $r = Capsule::table(self::TABLE)->where('key', $key)->first();
                if ($r) {
                    $j = json_decode((string) ($r->overrides ?? ''), true);
                    $out = ['v' => self::clean(is_array($j['v'] ?? null) ? $j['v'] : []), 'base' => is_array($j['base'] ?? null) ? $j['base'] : [],
                        'admin_id' => (int) ($r->admin_id ?? 0), 'updated_at' => $r->updated_at ?? null];
                }
            } catch (\Throwable $e) {
                $out = $empty;
            }
            self::$memo[$key] = $out;
        }
        return self::$memo[$key];
    }

    /** Only well-formed fields with scalar values survive (a hand-edited row never breaks a plan push). */
    private static function clean(array $v): array
    {
        $out = [];
        foreach ($v as $k => $val) {
            if (is_string($k) && preg_match(self::FIELD_RE, $k) && (is_bool($val) || is_int($val) || is_float($val) || is_string($val))) {
                $out[$k] = $val;
            }
        }
        return $out;
    }

    /** Loads many scopes into the memo with one query (lists, cron engines). */
    public static function preload(array $keys): void
    {
        $keys = array_values(array_diff(array_unique(array_filter($keys, 'is_string')), array_keys(self::$memo)));
        if (!$keys) {
            return;
        }
        $empty = ['v' => [], 'base' => [], 'admin_id' => 0, 'updated_at' => null];
        try {
            $rows = [];
            foreach (Capsule::table(self::TABLE)->whereIn('key', $keys)->get() as $r) {
                $rows[(string) $r->key] = $r;
            }
        } catch (\Throwable $e) {
            $rows = [];
        }
        foreach ($keys as $k) {
            $r = $rows[$k] ?? null;
            $j = $r ? json_decode((string) ($r->overrides ?? ''), true) : null;
            self::$memo[$k] = $r ? ['v' => self::clean(is_array($j['v'] ?? null) ? $j['v'] : []), 'base' => is_array($j['base'] ?? null) ? $j['base'] : [],
                'admin_id' => (int) ($r->admin_id ?? 0), 'updated_at' => $r->updated_at ?? null] : $empty;
        }
    }

    /** Number of overridden fields of a scope. */
    public static function count(string $key): int
    {
        return count(self::get($key)['v']);
    }

    /** Overrides of many scopes at once: key => count (one query; for lists). */
    public static function counts(array $keys): array
    {
        $out = [];
        $keys = array_values(array_unique(array_filter($keys, 'is_string')));
        if (!$keys) {
            return $out;
        }
        try {
            foreach (Capsule::table(self::TABLE)->whereIn('key', $keys)->get(['key', 'overrides']) as $r) {
                $j = json_decode((string) $r->overrides, true);
                $n = count(self::clean(is_array($j['v'] ?? null) ? $j['v'] : []));
                if ($n > 0) {
                    $out[(string) $r->key] = $n;
                }
            }
        } catch (\Throwable $e) {
            return [];
        }
        return $out;
    }

    /** $plan with the override values on top (top-level fields and features.*). */
    public static function apply(array $plan, array $v): array
    {
        foreach ($v as $field => $val) {
            if (strpos($field, 'features.') === 0) {
                if (!isset($plan['features']) || !is_array($plan['features'])) {
                    $plan['features'] = [];
                }
                $plan['features'][substr($field, 9)] = $val;
            } else {
                $plan[$field] = $val;
            }
        }
        return $plan;
    }

    /** A plan's value of one field (null when absent). */
    public static function valueOf(array $plan, string $field)
    {
        if (strpos($field, 'features.') === 0) {
            return $plan['features'][substr($field, 9)] ?? null;
        }
        return $plan[$field] ?? null;
    }

    /**
     * Validates one value for a field whose type is the type of $like (the plan / effective value): [ok, value | error].
     * Booleans: true / false / "1" / "0" / "on"; numbers: digits within the controller's range; enums: their values.
     */
    public static function validate(string $field, $raw, $like): array
    {
        if (!preg_match(self::FIELD_RE, $field)) {
            return [false, 'فیلد نامعتبر است.'];
        }
        if (isset(self::ENUMS[$field])) {
            $v = is_string($raw) ? trim($raw) : '';
            return in_array($v, self::ENUMS[$field], true) ? [true, $v] : [false, 'مقدار مجاز: ' . implode(' / ', self::ENUMS[$field])];
        }
        if (is_bool($like) || $field === 'ssl_allowed') {
            if (is_bool($raw)) {
                return [true, $raw];
            }
            $s = strtolower(trim((string) $raw));
            if (in_array($s, ['1', 'on', 'true', 'yes'], true)) {
                return [true, true];
            }
            if (in_array($s, ['0', 'off', 'false', 'no', ''], true)) {
                return [true, false];
            }
            return [false, 'مقدار باید روشن یا خاموش باشد.'];
        }
        $s = strtr(trim((string) $raw), ['۰' => '0', '۱' => '1', '۲' => '2', '۳' => '3', '۴' => '4', '۵' => '5', '۶' => '6', '۷' => '7', '۸' => '8', '۹' => '9', '٫' => '.', ',' => '', '٬' => '']);
        $float = is_float($like) || $field === 'features.sla_target';
        if ($s === '' || !preg_match($float ? '/^\d{1,9}(?:\.\d{1,3})?$/D' : '/^\d{1,10}$/D', $s)) {
            return [false, $float ? 'یک عدد (حداکثر سه رقم اعشار) وارد کنید.' : 'یک عدد صحیح نامنفی وارد کنید.'];
        }
        $v = $float ? (float) $s : (int) $s;
        if (is_int($like) || $float || is_numeric($like) || isset(self::RANGES[$field])) {
            [$min, $max] = self::RANGES[$field] ?? [0, PHP_INT_MAX];
            if ($v < $min || $v > $max) {
                return [false, 'مقدار باید بین ' . $min . ' و ' . $max . ' باشد.'];
            }
            return [true, $v];
        }
        return [false, 'نوع این فیلد پشتیبانی نمی‌شود.'];
    }

    /** Stores the overrides of a scope ([] removes the row). */
    public static function save(string $key, array $v, array $base, int $admin): bool
    {
        if ($key === '' || !self::ensure()) {
            return false;
        }
        unset(self::$memo[$key]);
        $v = self::clean($v);
        $base = array_intersect_key($base, $v);
        if (!$v) {
            Capsule::table(self::TABLE)->where('key', $key)->delete();
            return true;
        }
        $row = ['overrides' => json_encode(['v' => $v, 'base' => $base], JSON_UNESCAPED_UNICODE), 'admin_id' => $admin, 'updated_at' => date('Y-m-d H:i:s')];
        if (Capsule::table(self::TABLE)->where('key', $key)->exists()) {
            Capsule::table(self::TABLE)->where('key', $key)->update($row);
        } else {
            Capsule::table(self::TABLE)->insert(['key' => $key] + $row);
        }
        return true;
    }

    /** Moves the overrides of $from to $to (a transfer); an existing row of $to is replaced. */
    public static function rekey(string $from, string $to): bool
    {
        if ($from === '' || $to === '' || $from === $to) {
            return false;
        }
        try {
            if (!Capsule::table(self::TABLE)->where('key', $from)->exists()) {
                return false;
            }
            Capsule::table(self::TABLE)->where('key', $to)->delete();
            Capsule::table(self::TABLE)->where('key', $from)->update(['key' => $to, 'updated_at' => date('Y-m-d H:i:s')]);
            self::$memo = [];
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Removes the overrides of a scope. */
    public static function drop(string $key): bool
    {
        try {
            $n = Capsule::table(self::TABLE)->where('key', $key)->delete();
            unset(self::$memo[$key]);
            return $n > 0;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * The prepaid facts of a service with an explicit bandwidth override applied: the override replaces the plan GB the
     * engine tops up from (paid blocks still add on top); an override of 0 (unlimited) takes the service out of the engine.
     */
    public static function prepaid(int $sid, ?array $pp): ?array
    {
        if ($pp === null) {
            return null;
        }
        $gb = self::bandwidth($sid);
        if ($gb === null) {
            return $pp;
        }
        if ($gb <= 0) {
            return null;
        }
        $pp['plan_gb'] = $gb;
        return $pp;
    }

    /** Explicit bandwidth_limit_gb override of a service (null = none) — for the prepaid / add-on traffic cap engines. */
    public static function bandwidth(int $sid): ?int
    {
        $v = self::get(self::serviceKey($sid))['v'];
        return array_key_exists('bandwidth_limit_gb', $v) ? max(0, (int) $v['bandwidth_limit_gb']) : null;
    }
}
