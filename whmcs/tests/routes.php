<?php
/**
 * The client proxy's route and query whitelist (lib/ClientApi.php), exercised directly.
 *
 * ClientApi::allowed() is what decides whether a path the app asks for reaches the controller at
 * all, and ClientApi::query() is what decides which query parameters survive. Both are private and
 * both are easy to get wrong in a way no linter sees: the file manager first shipped asking for
 * `storage/buckets/<b>/objects?prefix=…`, which api.php sends as ONE encoded path value, so every
 * listing came back 404. These assertions fail on that mistake.
 *
 * Run: php whmcs/tests/routes.php
 */
require __DIR__ . '/../modules/servers/pasargadcdn/lib/ClientApi.php';

$cls = new ReflectionClass(PasargadCdn\ClientApi::class);
$allowedM = $cls->getMethod('allowed');
$allowedM->setAccessible(true);
$queryM = $cls->getMethod('query');
$queryM->setAccessible(true);
$allowed = fn(string $m, string $p): bool => (bool) $allowedM->invoke(null, $m, $p);
$query = fn(string $p, array $in) => $queryM->invoke(null, $p, $in);

$fail = 0;
$n = 0;
function check(string $what, $got, $want): void
{
    global $fail, $n;
    $n++;
    if ($got === $want) {
        return;
    }
    $fail++;
    fwrite(STDERR, sprintf("FAIL %s\n  got:  %s\n  want: %s\n", $what, var_export($got, true), var_export($want, true)));
}

$B = 'storage/buckets/assets/objects';

// the file manager's own routes
check('GET objects', $allowed('GET', $B), true);
foreach (['upload', 'download', 'folder', 'rename', 'delete', 'multipart',
          'multipart/parts', 'multipart/complete', 'multipart/abort'] as $op) {
    check("POST objects/$op", $allowed('POST', "$B/$op"), true);
}
// a query string belongs in api()'s query parameter, never glued onto the path
check('GET objects?prefix=', $allowed('GET', $B . '?prefix=docs/'), false);
// and no write route is reachable with the wrong method
check('GET objects/delete', $allowed('GET', "$B/delete"), false);
check('POST objects', $allowed('POST', $B), false);
check('DELETE objects', $allowed('DELETE', $B), false);
// a bucket name the module must not pass through (the controller's own rule: 3..40 of a-z 0-9 -)
check('GET objects of BAD bucket', $allowed('GET', 'storage/buckets/Bad_Name/objects'), false);
check('GET objects of ../ bucket', $allowed('GET', 'storage/buckets/../objects'), false);

// the listing's query: the folder on screen, the server's continuation token and the page size
check('query prefix+limit', $query($B, ['prefix' => 'docs/', 'limit' => '200']), '?prefix=docs%2F&limit=200');
check('query root', $query($B, ['prefix' => '', 'limit' => '200']), '?prefix=&limit=200');
check('query token kept', $query($B, ['token' => 'T1=']), '?token=T1%3D');
check('query persian prefix', $query($B, ['prefix' => 'عکس‌ها/']), '?prefix=' . urlencode('عکس‌ها/'));
// invalid values make the whole call invalid rather than being dropped silently
check('query `..` refused', $query($B, ['prefix' => 'a/../b']), null);
check('query control char refused', $query($B, ['prefix' => "a\nb"]), null);
check('query limit 0 refused', $query($B, ['limit' => '0']), null);
check('query limit 1001 refused', $query($B, ['limit' => '1001']), null);
check('query empty token refused', $query($B, ['token' => '']), null);
// an unknown key is dropped, not an error
check('query unknown key dropped', $query($B, ['prefix' => 'a/', 'nope' => '1']), '?prefix=a%2F');

// SPEC §20: a shared domain's roles. Listing and a download link are reads for every role; the
// writes need `editor`; nothing reaches a role that is not on its list.
$share = fn(string $r, string $m, string $p): bool => PasargadCdn\ClientApi::shareAllows($r, $m, $p);
foreach (['viewer', 'dns', 'editor'] as $role) {
    check("$role GET objects", $share($role, 'GET', $B), true);
    check("$role POST objects/download", $share($role, 'POST', "$B/download"), true);
}
foreach (['upload', 'folder', 'rename', 'delete', 'multipart', 'multipart/parts',
          'multipart/complete', 'multipart/abort'] as $op) {
    check("editor POST objects/$op", $share('editor', 'POST', "$B/$op"), true);
    check("viewer POST objects/$op", $share('viewer', 'POST', "$B/$op"), false);
    check("dns POST objects/$op", $share('dns', 'POST', "$B/$op"), false);
}
// a bucket key itself stays with the owner
check('editor POST rotate-key', $share('editor', 'POST', 'storage/buckets/assets/rotate-key'), false);

printf("%d checks, %d failed\n", $n, $fail);
exit($fail === 0 ? 0 : 1);
