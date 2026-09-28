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
        return \PasargadCdn\Admin\CartValidator::checkout($cart);
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
