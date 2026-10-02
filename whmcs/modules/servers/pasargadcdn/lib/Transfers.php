<?php

namespace PasargadCdn;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Transfers', false)) {
    return;
}

/**
 * SPEC §19.2 — the WHMCS-side ledger of domain transfers (mod_pasargadcdn_transfers), shared by the admin addon
 * (which writes it inside the transfer's DB transaction) and this module (which reads it):
 *
 *  - guard = 1 on the old service of a client → operator transfer: the site now belongs to the operator, so the
 *    module's Terminate / Suspend / Unsuspend / ChangePackage never touch it on the controller again (the WHMCS
 *    service itself is Cancelled; a later Terminate only finishes the WHMCS side);
 *  - banner = 1 on the service the new owner received (client → client: the same service; operator → client: the
 *    new one) until that client dismisses the one-time notice in the client app («این دامنه به حساب شما منتقل شد»).
 *
 * Every read degrades to "nothing recorded" when the table cannot be read (older install, test stubs); writes are
 * done by the addon (Admin\Transfer) only.
 */
class Transfers
{
    const TABLE = 'mod_pasargadcdn_transfers';
    const DIRECTIONS = ['client_client', 'operator_client', 'client_operator'];

    /** Creates the table when missing (addon activation / upgrade / first transfer). Never throws. */
    public static function ensure(): bool
    {
        try {
            $schema = Capsule::schema();
            if (!$schema->hasTable(self::TABLE)) {
                $schema->create(self::TABLE, function ($t) {
                    $t->increments('id');
                    $t->string('domain', 253);
                    $t->integer('service_id')->default(0);       // the WHMCS service of the move (see class doc)
                    $t->string('direction', 24);
                    $t->integer('from_client')->default(0);      // 0 = operator
                    $t->integer('to_client')->default(0);        // 0 = operator
                    $t->integer('admin_id')->default(0);
                    $t->string('status', 16)->default('done');   // done | rolled_back | failed
                    $t->tinyInteger('guard')->default(0);
                    $t->tinyInteger('banner')->default(0);
                    $t->text('detail')->nullable();              // JSON: controller answer, invoices moved, credit, …
                    $t->dateTime('created_at')->nullable();
                    $t->dateTime('updated_at')->nullable();
                    $t->index('service_id', 'mod_pcdn_transfers_service');
                    $t->index('domain', 'mod_pcdn_transfers_domain');
                });
            }
            // SPEC §19.3: who started it (admin wizard | client request) and the request it came from (added on upgrade)
            if (!$schema->hasColumn(self::TABLE, 'initiated_by')) {
                $schema->table(self::TABLE, function ($t) {
                    $t->string('initiated_by', 16)->default('admin');
                });
            }
            if (!$schema->hasColumn(self::TABLE, 'request_id')) {
                $schema->table(self::TABLE, function ($t) {
                    $t->integer('request_id')->default(0);
                });
            }
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** SPEC §19.3 customer transfer requests (the addon's Admin\CustomerTransfer owns them; the module only cancels). */
    const REQUESTS = 'mod_pasargadcdn_transfer_requests';
    const OPEN = ['pending', 'awaiting'];

    /**
     * The service was suspended / terminated / transferred / cancelled meanwhile: its open customer request ends
     * (status cancelled + reason). $except keeps the request that is being executed. Returns the count; never throws.
     */
    public static function cancelRequests(int $sid, string $reason, int $except = 0): int
    {
        if ($sid <= 0) {
            return 0;
        }
        try {
            $q = Capsule::table(self::REQUESTS)->where('service_id', $sid)->whereIn('status', self::OPEN);
            if ($except > 0) {
                $q->where('id', '<>', $except);
            }
            return (int) $q->update(['status' => 'cancelled', 'reason' => substr($reason, 0, 64), 'token_hash' => null, 'decided_at' => date('Y-m-d H:i:s')]);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** True when $sid was handed to the operator: the module must not act on its (former) site. */
    public static function guarded(int $sid): bool
    {
        if ($sid <= 0) {
            return false;
        }
        try {
            return (bool) Capsule::table(self::TABLE)->where('service_id', $sid)->where('guard', 1)->first();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** The pending one-time notice of service $sid for client $uid: ['at' => 'Y-m-d H:i:s'] or null. */
    public static function banner(int $sid, int $uid): ?array
    {
        if ($sid <= 0 || $uid <= 0) {
            return null;
        }
        try {
            $r = Capsule::table(self::TABLE)->where('service_id', $sid)->where('banner', 1)->first();
        } catch (\Throwable $e) {
            return null;
        }
        if (!$r || (int) ($r->to_client ?? 0) !== $uid) {
            return null;
        }
        return ['at' => (string) ($r->created_at ?? '')];
    }

    /** The client dismissed the notice (client app local op `transfer`). */
    public static function dismiss(int $sid, int $uid): bool
    {
        try {
            Capsule::table(self::TABLE)->where('service_id', $sid)->where('to_client', $uid)->where('banner', 1)
                ->update(['banner' => 0, 'updated_at' => date('Y-m-d H:i:s')]);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
