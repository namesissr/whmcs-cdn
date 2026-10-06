<?php
/**
 * Pasargad CDN — standalone JSON endpoint for a shared-domain member's client app.
 *
 *   <METHOD> modules/addons/pasargadcdn_admin/sharedapi.php?share=<id>&path=<sub-path>[&...]
 *   Header X-PCDN-CSRF: <token from the shared page>
 *
 * A direct entry point — exactly like the server module's api.php — so a member's writes (add an A
 * record, save a rule, …) never go through WHMCS's client-area POST routing
 * (index.php?m=pasargadcdn_admin&page=sharedapi), which some web-server / WHMCS setups answer with a
 * bare "405 Method Not Allowed" for non-GET requests. Authorisation, the CSRF check, the per-role
 * whitelist and the re-read share context all live in lib/Sharing.php / the server module's
 * lib/ClientApi.php; this file only bootstraps WHMCS, resolves the logged-in client and hands off to
 * the SAME Sharing::clientArea() code path the page route uses.
 */

require __DIR__ . '/../../../init.php';
require_once __DIR__ . '/lib/Env.php';
require_once __DIR__ . '/lib/Data.php';
require_once __DIR__ . '/lib/Sharing.php';

use PasargadCdn\Admin\Sharing;

$clientId = 0;
try {
    if (class_exists('\\WHMCS\\Authentication\\CurrentUser')) { // WHMCS 8+
        $c = (new \WHMCS\Authentication\CurrentUser())->client();
        $clientId = $c ? (int) $c->id : 0;
    } else {
        $clientId = (int) ($_SESSION['uid'] ?? 0);
    }
} catch (\Throwable $e) {
    $clientId = (int) ($_SESSION['uid'] ?? 0);
}

$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$get = array_filter($_GET, 'is_string');
// Force the JSON branch of clientArea(): it loads the server module, runs Sharing::api() and emits the
// JSON (or a streamed download), then exit()s. It only returns here if the server module cannot load.
$get['page'] = 'sharedapi';
Sharing::clientArea($get, [], $method, $clientId);

// Reached only when Sharing::clientArea() could not load the server module.
if (!headers_sent()) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
}
echo json_encode(['detail' => 'بارگذاری پنل ممکن نشد؛ کمی بعد دوباره تلاش کنید.'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
