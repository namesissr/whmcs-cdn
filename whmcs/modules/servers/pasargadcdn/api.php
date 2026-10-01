<?php
/**
 * Pasargad CDN — JSON endpoint for the client-area app.
 *
 *   <METHOD> modules/servers/pasargadcdn/api.php?id=<serviceid>&path=<sub-path>[&period=..]
 *   Header X-PCDN-CSRF: <token from the client area page>
 *
 * Authorisation and the path whitelist live in lib/ClientApi.php.
 */

require __DIR__ . '/../../../init.php';
require_once __DIR__ . '/pasargadcdn.php';
require_once __DIR__ . '/lib/ClientApi.php';
require_once __DIR__ . '/lib/TeamAccess.php';

use PasargadCdn\ClientApi;
use PasargadCdn\TeamAccess;

function pasargadcdn_api_client_id(): int
{
    if (class_exists('\WHMCS\Authentication\CurrentUser')) { // WHMCS 8+
        $client = (new \WHMCS\Authentication\CurrentUser())->client();
        return $client ? (int) $client->id : 0;
    }
    return (int) ($_SESSION['uid'] ?? 0);
}

$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$body = '';
if ($method === 'POST' || $method === 'PUT') {
    // Read one byte past the limit so ClientApi can reject oversized bodies.
    $body = (string) file_get_contents('php://input', false, null, 0, ClientApi::MAX_BODY + 1);
}
$str = function ($v) {
    return is_string($v) ? $v : '';
};
$query = $_GET;
unset($query['id'], $query['path'], $query['rsid'], $query['rop']);

// Reseller context (SPEC §10.5) — gathered server-side from the request; the logged-in
// client id decides ownership. A reseller-site id selects one of the client's OWN sub-sites
// (ClientApi resolves its domain from mod_pasargadcdn_reseller_sites), and a reseller op is a
// reseller-level action (list / create / delete / report). The domain is never trusted from input.
$rsid = ctype_digit((string) ($_GET['rsid'] ?? '')) ? (int) $_GET['rsid'] : 0;
$rop = $str($_GET['rop'] ?? '');

[$code, $data] = ClientApi::handle([
    'method' => $method,
    'id' => $str($_GET['id'] ?? ''),
    'path' => $str($_GET['path'] ?? ''),
    'query' => $query,
    'body' => $body,
    'csrf' => (string) ($_SERVER['HTTP_X_PCDN_CSRF'] ?? ''),
    'session_csrf' => (string) ($_SESSION['pasargadcdn_csrf'] ?? ''),
    'client_id' => pasargadcdn_api_client_id(),
    'reseller_site_id' => $rsid,
    'reseller_op' => $rop,
    // SPEC §14.3.7: a WHMCS user who is not the account owner and lacks "manageproducts" may only
    // read; ClientApi refuses every non-GET call for them (server side, whatever the UI shows).
    // Only writes need the decision, so reads (e.g. the 30 s live-analytics poll) skip the lookup.
    'readonly' => $method !== 'GET' && TeamAccess::readonly(),
]);

http_response_code($code);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
