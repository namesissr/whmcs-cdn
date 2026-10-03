<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\TeamAccess', false)) {
    return;
}

/**
 * Team access (SPEC §14.3.7): WHMCS 8 lets a client account be shared by several users, each
 * with per-account permissions. A logged-in user who is NOT the account owner and lacks the
 * "manageproducts" permission gets a read-only app — the boot payload carries readonly=true and
 * api.php refuses every non-GET call (ClientApi::handle, 'readonly' => true).
 *
 * Every WHMCS API used here is optional and guarded (class_exists / method_exists / try-catch).
 * Whenever something cannot be determined — WHMCS 7 (no users), no logged-in user, a missing
 * method, an unreadable table — the answer is "full access", i.e. the behaviour before §14.3.7.
 * Only a positive "this user is not the owner AND has no manageproducts" makes the app read-only.
 *
 * WHMCS APIs assumed (verify on a staging WHMCS 8.x, see docs/WHMCS.md):
 *   - \WHMCS\Authentication\CurrentUser: user() → \WHMCS\User\User|null, client() → \WHMCS\User\Client|null
 *   - \WHMCS\User\Client::isOwnedBy(User $user): bool, Client::owner(): ?User (fallbacks for ownership)
 *   - table tblusers_clients (auth_user_id, client_id, owner, permissions = comma-separated
 *     identifiers like "products,manageproducts,productsso", the format of the UpdateUserPermissions API)
 *   - checkContactPermission('manageproducts', true): bool — legacy client-area helper, last fallback
 */
class TeamAccess
{
    /** WHMCS permission identifier for "manage products/services" (GetPermissionsList). */
    const MANAGE = 'manageproducts';

    /**
     * Test hook: fn(int $userId, int $clientId): ?array{owner: bool, permissions: string[]} replacing the
     * tblusers_clients lookup (null = no row / unknown).
     * @var callable|null
     */
    public static $pivotLookup = null;

    /** Read-only app for the current WHMCS session? ($currentUser: injected CurrentUser for tests). */
    public static function readonly($currentUser = null): bool
    {
        return self::decide($currentUser)['readonly'];
    }

    /**
     * Decision with its reason (for tests and the docs): legacy | no-user | no-client | owner |
     * permitted | unknown | readonly. Only "readonly" restricts.
     */
    public static function decide($currentUser = null): array
    {
        $out = function (string $reason) {
            return ['readonly' => $reason === 'readonly', 'reason' => $reason];
        };
        try {
            $cu = $currentUser;
            if ($cu === null) {
                if (!class_exists('\\WHMCS\\Authentication\\CurrentUser')) {
                    return $out('legacy');          // WHMCS 7: no users, no per-user permissions
                }
                $cu = new \WHMCS\Authentication\CurrentUser();
            }
            if (!is_object($cu) || !method_exists($cu, 'user') || !method_exists($cu, 'client')) {
                return $out('legacy');
            }
            $user = $cu->user();
            if (!is_object($user)) {
                return $out('no-user');
            }
            $client = $cu->client();
            if (!is_object($client)) {
                return $out('no-client');
            }
            $userId = self::id($user);
            $clientId = self::id($client);
            $pivot = ($userId > 0 && $clientId > 0) ? self::pivot($userId, $clientId) : null;

            $owner = self::isOwner($client, $user, $userId, $pivot);
            if ($owner === true) {
                return $out('owner');
            }
            $source = '';
            $manage = self::canManage($pivot, $source);
            if ($manage === true) {
                return $out('permitted');
            }
            // Read-only only on positive answers: not the owner and no manageproducts. The legacy
            // checkContactPermission() already answers "true" for the owner, so its "false" alone suffices.
            if ($manage === false && ($owner === false || $source === 'contact')) {
                return $out('readonly');
            }
            return $out('unknown');
        } catch (\Throwable $e) {
            return $out('unknown');
        }
    }

    /** Model id (Eloquent attribute) or 0. */
    private static function id($model): int
    {
        try {
            $v = $model->id ?? 0;
            return is_numeric($v) ? (int) $v : 0;
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** true / false, or null when no API could tell. */
    private static function isOwner($client, $user, int $userId, ?array $pivot): ?bool
    {
        if (method_exists($client, 'isOwnedBy')) {
            try {
                return (bool) $client->isOwnedBy($user);
            } catch (\Throwable $e) {
                // fall through to the next source
            }
        }
        if (method_exists($client, 'owner')) {
            try {
                $o = $client->owner();
                if (is_object($o) && $userId > 0 && self::id($o) > 0) {
                    return self::id($o) === $userId;
                }
            } catch (\Throwable $e) {
                // fall through
            }
        }
        return $pivot !== null ? $pivot['owner'] : null;
    }

    /** Does the user hold manageproducts for the active client? null = unknown; $source: pivot | contact. */
    private static function canManage(?array $pivot, string &$source): ?bool
    {
        if ($pivot !== null) {
            $source = 'pivot';
            return in_array(self::MANAGE, $pivot['permissions'], true);
        }
        if (function_exists('checkContactPermission')) {
            try {
                $r = checkContactPermission(self::MANAGE, true);
                if (is_bool($r)) {
                    $source = 'contact';
                    return $r;
                }
            } catch (\Throwable $e) {
                return null;
            }
        }
        return null;
    }

    /** The user↔client row: {owner, permissions[]} or null (no row, no table, any error). */
    private static function pivot(int $userId, int $clientId): ?array
    {
        try {
            if (self::$pivotLookup) {
                $r = (self::$pivotLookup)($userId, $clientId);
                return is_array($r) ? ['owner' => !empty($r['owner']), 'permissions' => self::perms($r['permissions'] ?? [])] : null;
            }
            if (!class_exists('\\WHMCS\\Database\\Capsule')) {
                return null;
            }
            $row = Capsule::table('tblusers_clients')->where('auth_user_id', $userId)->where('client_id', $clientId)
                ->first(['owner', 'permissions']);
            if (!$row) {
                return null;
            }
            $row = (array) $row;
            return ['owner' => !empty($row['owner']), 'permissions' => self::perms($row['permissions'] ?? '')];
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** Permission identifiers from a comma-separated string (or a JSON list / array, defensively). */
    public static function perms($raw): array
    {
        if (is_string($raw)) {
            $t = trim($raw);
            if ($t !== '' && $t[0] === '[') {
                $j = json_decode($t, true);
                $raw = is_array($j) ? $j : [];
            } else {
                $raw = explode(',', $t);
            }
        }
        if (!is_array($raw)) {
            return [];
        }
        $out = [];
        foreach ($raw as $p) {
            if (is_string($p) && ($p = strtolower(trim($p))) !== '') {
                $out[] = $p;
            }
        }
        return array_values(array_unique($out));
    }
}
