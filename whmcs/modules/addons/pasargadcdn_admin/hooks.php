<?php
/**
 * Pasargad CDN admin addon — hooks. WHMCS loads this file only while the addon
 * is activated. It defines no functions, classes or globals; each hook is a
 * closure that returns immediately unless the request concerns a Pasargad CDN
 * product:
 *
 *  - ShoppingCartValidateCheckout: empty cart → no work; cart without CDN
 *    products → one memoised query (CDN product ids); CDN products → domain /
 *    Origin IP rules, then at most one controller request (≤ 5 s, fail-open).
 *  - ShoppingCartValidateProductUpdate: same local rules for the edited item,
 *    no controller request.
 *  - AdminHomeWidgets: registers the widget (data cached 5 minutes).
 *  - InvoicePaid: one query on the paid invoice's items; only an Add Funds or a
 *    CDN traffic top-up invoice does more (prepaid mode: buy traffic / reconnect
 *    this client's CDN services, pay its CDN-only invoices from credit). A paid
 *    «بسته‌ی ترافیک افزوده» add-on line (Wave 7, any billing mode) raises the
 *    service's cap for the month, once per invoice item (AddonTraffic).
 *  - AfterCronJob: prepaid mode only; no CDN products → 2 small queries. Otherwise
 *    one controller /api/v1/usage call per CDN server and work only for services
 *    at/near their cap. Wave 7: one GET /api/v1/events?type=tunnel per CDN server
 *    for the origin-down / back-up e-mails (TunnelAlerts) and the add-on traffic
 *    cap retries / month rollover (AddonTraffic). SPEC §16.8: once a month, after it
 *    closes, one GET /api/v1/storage/usage per CDN server and one invoice / billable item
 *    per service that stored data (StorageBilling; off while the storage price is 0).
 *    Errors are logged, never thrown into WHMCS's cron.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

add_hook('ShoppingCartValidateCheckout', 1, function ($vars) {
    $cart = isset($_SESSION['cart']) && is_array($_SESSION['cart']) ? $_SESSION['cart'] : [];
    if (empty($cart['products']) || !is_array($cart['products'])) {
        return [];
    }
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/CartValidator.php';
        return \PasargadCdn\Admin\CartValidator::checkout($cart, is_array($vars) ? $vars : []);
    } catch (\Throwable $e) {
        // Never block a sale because of an unexpected error in this addon.
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: checkout validation error (order allowed): ' . $e->getMessage());
        }
        return [];
    }
});

add_hook('ShoppingCartValidateProductUpdate', 1, function ($vars) {
    $cart = isset($_SESSION['cart']) && is_array($_SESSION['cart']) ? $_SESSION['cart'] : [];
    if (empty($cart['products']) || !is_array($cart['products'])) {
        return [];
    }
    $i = is_array($vars) && isset($vars['i']) ? $vars['i'] : ($_REQUEST['i'] ?? null);
    if (!is_numeric($i) || !isset($cart['products'][(int) $i])) {
        return [];
    }
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/CartValidator.php';
        $fields = isset($_POST['customfield']) && is_array($_POST['customfield']) ? $_POST['customfield'] : [];
        return \PasargadCdn\Admin\CartValidator::productUpdate($cart, (int) $i, $fields);
    } catch (\Throwable $e) {
        return [];
    }
});

add_hook('AdminHomeWidgets', 1, function () {
    if (!class_exists('\\WHMCS\\Module\\AbstractWidget')) {
        return null;
    }
    try {
        require_once __DIR__ . '/lib/Env.php';
        if (!\PasargadCdn\Admin\Env::enabled('widget', true) || !\PasargadCdn\Admin\Env::loadServerModule()) {
            return null;
        }
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/WidgetData.php';
        require_once __DIR__ . '/lib/Widget.php';
        return class_exists('\\PasargadCdn\\Admin\\Widget') ? new \PasargadCdn\Admin\Widget() : null;
    } catch (\Throwable $e) {
        return null;
    }
});

add_hook('InvoicePaid', 1, function ($vars) {
    $id = is_array($vars) ? (int) ($vars['invoiceid'] ?? 0) : 0;
    if ($id <= 0) {
        return;
    }
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Prepaid.php';
        require_once __DIR__ . '/lib/Wizard.php';
        require_once __DIR__ . '/lib/AddonTraffic.php';
        // Prepaid reads the invoice lines once; Wave 7 «Addon» lines go to AddonTraffic (any billing mode)
        \PasargadCdn\Admin\Prepaid::onInvoicePaid($id);
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: InvoicePaid hook error: ' . $e->getMessage());
        }
    }
});

add_hook('AfterCronJob', 1, function ($vars) {
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Prepaid.php';
        \PasargadCdn\Admin\Prepaid::onCron();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: cron hook error: ' . $e->getMessage());
        }
    }
    // Wave 7 (SPEC §15.7): independent passes — a failure in one never stops the others.
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Wizard.php';
        require_once __DIR__ . '/lib/TunnelAlerts.php';
        require_once __DIR__ . '/lib/AddonTraffic.php';
        \PasargadCdn\Admin\TunnelAlerts::onCron();
        \PasargadCdn\Admin\AddonTraffic::onCron();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: tunnel/add-on cron hook error: ' . $e->getMessage());
        }
    }
    // Growth: free-trial reminders / end of trial, and the scheduled e-mail reports — independent passes
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Wizard.php';
        require_once __DIR__ . '/lib/Reports.php';
        require_once __DIR__ . '/lib/Trials.php';
        \PasargadCdn\Admin\Trials::onCron();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: trial cron hook error: ' . $e->getMessage());
        }
    }
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Wizard.php';
        require_once __DIR__ . '/lib/Reports.php';
        \PasargadCdn\Admin\Reports::onCron();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: e-mail report cron hook error: ' . $e->getMessage());
        }
    }
    // SPEC §16.8: object-storage charges of the previous month (once, after the month closes)
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Prepaid.php';
        require_once __DIR__ . '/lib/StorageBilling.php';
        \PasargadCdn\Admin\StorageBilling::onCron();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: storage billing cron hook error: ' . $e->getMessage());
        }
    }
});
