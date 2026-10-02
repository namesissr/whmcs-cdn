<?php
/**
 * Pasargad CDN admin addon — hooks. WHMCS loads this file only while the addon
 * is activated. It defines no functions, classes or globals; each hook is a
 * closure that returns immediately unless the request concerns a Pasargad CDN
 * product:
 *
 *  - ShoppingCartValidateCheckout: empty cart → no work; cart without CDN
 *    products → one memoised query (CDN product ids); CDN products → domain /
 *    Origin IP rules, then one POST /api/v1/domain-check per CDN domain (in
 *    parallel, ≤ 5 s, memoised per request, fail-open).
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
 *    Security review C1: owner sync (OwnerSync) — while existing sites lack an owner,
 *    one GET /api/v1/sites per CDN server and at most 100 PATCH …/owner per run;
 *    afterwards one pass every 6 hours (addon setting «همگام‌سازی مالکیت دامنه‌ها»).
 *    Errors are logged, never thrown into WHMCS's cron.
 *  - Wave 10 (SPEC §18.5) referral programme — every hook returns after one memoised settings read while
 *    the programme is off (the default): ClientAreaPage keeps a `?ref=` code (session + 30-day cookie),
 *    AfterShoppingCartCheckout attaches it to the new client's first CDN order, InvoicePaid qualifies it
 *    (through Prepaid's single read of the invoice lines; only invoices with a Hosting line cost one more
 *    settings read), InvoiceRefunded / InvoiceCancelled cancel an unpaid reward,
 *    AfterCronJob pays due rewards once a day (AddCredit), ClientAreaHomepagePanels shows the client card.
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
        require_once __DIR__ . '/lib/Referrals.php';
        // Prepaid reads the invoice lines once; Wave 7 «Addon» lines go to AddonTraffic (any billing mode); Wave 10
        // Hosting lines of a referred client's first CDN invoice qualify the referral (Referrals)
        \PasargadCdn\Admin\Prepaid::onInvoicePaid($id);
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: InvoicePaid hook error: ' . $e->getMessage());
        }
    }
});

// ---------------------------------------------------------------- Wave 10 (SPEC §18.5) referral programme

add_hook('ClientAreaPage', 1, function ($vars) {
    if (!isset($_GET['ref']) || !is_string($_GET['ref'])) {
        return [];
    }
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Referrals.php';
        if (\PasargadCdn\Admin\Referrals::on()) {
            \PasargadCdn\Admin\Referrals::capture($_GET);
        }
    } catch (\Throwable $e) {
        // a referral link never breaks a page
    }
    return [];
});

add_hook('AfterShoppingCartCheckout', 1, function ($vars) {
    $order = is_array($vars) ? (int) ($vars['OrderID'] ?? 0) : 0;
    // SPEC §19.2: the order of an operator → client domain transfer (AddOrder by the wizard) is no referral sale
    if ($order <= 0 || (class_exists('\\PasargadCdn\\Admin\\Transfer', false) && \PasargadCdn\Admin\Transfer::$creating)) {
        return;
    }
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Referrals.php';
        if (\PasargadCdn\Admin\Referrals::on()) {
            \PasargadCdn\Admin\Referrals::attach($order, (int) ($vars['InvoiceID'] ?? 0), '', (string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        }
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: referral checkout error (order not affected): ' . $e->getMessage());
        }
    }
});

foreach (['InvoiceRefunded' => 'refunded', 'InvoiceCancelled' => 'invoice_cancelled'] as $pcdnHook => $pcdnReason) {
    add_hook($pcdnHook, 1, function ($vars) use ($pcdnReason) {
        $id = is_array($vars) ? (int) ($vars['invoiceid'] ?? 0) : 0;
        if ($id <= 0) {
            return;
        }
        try {
            require_once __DIR__ . '/lib/Env.php';
            require_once __DIR__ . '/lib/View.php';
            require_once __DIR__ . '/lib/Referrals.php';
            \PasargadCdn\Admin\Referrals::onInvoiceReversed($id, $pcdnReason);
        } catch (\Throwable $e) {
            if (function_exists('logActivity')) {
                logActivity('Pasargad CDN: referral refund hook error: ' . $e->getMessage());
            }
        }
    });
}
unset($pcdnHook, $pcdnReason);

add_hook('ClientAreaHomepagePanels', 1, function ($panels) {
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Referrals.php';
        if (!is_object($panels) || !method_exists($panels, 'addChild')) {
            return;
        }
        $uid = 0;
        if (class_exists('\\WHMCS\\Authentication\\CurrentUser')) {
            $c = (new \WHMCS\Authentication\CurrentUser())->client();
            $uid = $c ? (int) $c->id : 0;
        } else {
            $uid = (int) ($_SESSION['uid'] ?? 0);
        }
        if ($uid <= 0) {
            return;
        }
        // SPEC §20.2: «دعوت به مدیریت دامنه» — pending invitations to this client's primary e-mail (one query when none)
        try {
            require_once __DIR__ . '/lib/Data.php';
            require_once __DIR__ . '/lib/Sharing.php';
            if (\PasargadCdn\Admin\Env::loadServerModule() && ($card = \PasargadCdn\Admin\Sharing::homeCard($uid)) !== '') {
                $en = function_exists('pasargadcdn_lang') && \pasargadcdn_lang([]) === 'en';
                $panels->addChild('pasargadcdn_share_invites', [
                    'label' => $en ? 'Invitation to manage a domain' : 'دعوت به مدیریت دامنه',
                    'icon' => 'fa-share-alt',
                    'order' => 240,
                    'extras' => ['color' => 'blue', 'btn-link' => \PasargadCdn\Admin\Sharing::ROUTE, 'btn-text' => $en ? 'View invitations' : 'مشاهدهٔ دعوت‌ها'],
                    'bodyHtml' => $card,
                ]);
            }
        } catch (\Throwable $e) {
            // the home page never breaks because of this card
        }
        if (!\PasargadCdn\Admin\Referrals::on()) {
            return;
        }
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Pricing.php';
        require_once __DIR__ . '/lib/Referrals.php';
        if (!\PasargadCdn\Admin\Referrals::enabled()) {
            return;
        }
        $lang = \PasargadCdn\Admin\Pricing::lang([]);
        $panels->addChild('pasargadcdn_referral', [
            'label' => \PasargadCdn\Admin\Referrals::tx('title', $lang),
            'icon' => 'fa-gift',
            'order' => 250,
            'extras' => ['color' => 'teal', 'btn-link' => 'index.php?m=pasargadcdn_admin&page=referral',
                'btn-text' => \PasargadCdn\Admin\Referrals::tx('more', $lang)],
            'bodyHtml' => \PasargadCdn\Admin\Referrals::cardHtml($uid, $lang),
        ]);
    } catch (\Throwable $e) {
        // the home page never breaks because of this card
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
    // Security review C1: owners (client_id) of sites created before the controller knew them
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/Data.php';
        require_once __DIR__ . '/lib/OwnerSync.php';
        \PasargadCdn\Admin\OwnerSync::onCron();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: owner sync cron hook error: ' . $e->getMessage());
        }
    }
    // Wave 10 (SPEC §18.5): due referral rewards (once a day; nothing while the programme is off)
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Referrals.php';
        if (\PasargadCdn\Admin\Referrals::on()) {
            \PasargadCdn\Admin\Referrals::onCron();
        }
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: referral cron hook error: ' . $e->getMessage());
        }
    }
    // SPEC §20.2: pending domain-share invitations past their 7 days → expired (once a day)
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Data.php';
        require_once __DIR__ . '/lib/Sharing.php';
        \PasargadCdn\Admin\Sharing::onCron();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: share cron hook error: ' . $e->getMessage());
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
