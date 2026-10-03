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
        // SPEC §20.3: «دامنه‌های اشتراکی» — the domains other accounts shared with this client, with «مدیریت»
        try {
            require_once __DIR__ . '/lib/Data.php';
            require_once __DIR__ . '/lib/Sharing.php';
            if (\PasargadCdn\Admin\Env::loadServerModule() && ($card = \PasargadCdn\Admin\Sharing::homeSharedCard($uid)) !== '') {
                $en = function_exists('pasargadcdn_lang') && \pasargadcdn_lang([]) === 'en';
                $panels->addChild('pasargadcdn_shared_domains', [
                    'label' => $en ? 'Domains shared with you' : 'دامنه‌های اشتراکی',
                    'icon' => 'fa-users',
                    'order' => 235,
                    'extras' => ['color' => 'green', 'btn-link' => \PasargadCdn\Admin\Sharing::ROUTE, 'btn-text' => $en ? 'All shared domains' : 'همهٔ دامنه‌های اشتراکی'],
                    'bodyHtml' => $card,
                ]);
            }
        } catch (\Throwable $e) {
            // the home page never breaks because of this card
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
        // SPEC §19.3: «درخواست انتقال دامنه» — transfers other clients asked to move to this account (accept / decline)
        try {
            if (pasargadcdn_admin_xfer_load() && ($card = \PasargadCdn\Admin\CustomerTransfer::homeCard($uid)) !== '') {
                $en = function_exists('pasargadcdn_lang') && \pasargadcdn_lang([]) === 'en';
                $panels->addChild('pasargadcdn_transfer_requests', [
                    'label' => $en ? 'Domain transfer to your account' : 'درخواست انتقال دامنه به حساب شما',
                    'icon' => 'fa-exchange-alt',
                    'order' => 238,
                    'extras' => ['color' => 'orange', 'btn-link' => \PasargadCdn\Admin\CustomerTransfer::ROUTE, 'btn-text' => $en ? 'View and answer' : 'مشاهده و پاسخ'],
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
    // SPEC §23.5 / §23.10 (wave 14): customer alert e-mails from the controller's outbox (AlertMail) — independent pass
    try {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/TunnelAlerts.php';
        require_once __DIR__ . '/lib/AlertMail.php';
        \PasargadCdn\Admin\AlertMail::onCron();
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: alert e-mail cron hook error: ' . $e->getMessage());
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
    // SPEC §19.3: open customer transfer requests past their 7 days → expired, invalid ones cancelled (once a day)
    try {
        if (pasargadcdn_admin_xfer_load()) {
            \PasargadCdn\Admin\CustomerTransfer::onCron();
        }
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('Pasargad CDN: customer transfer cron hook error: ' . $e->getMessage());
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

/**
 * SPEC §20.3: the logged-in client's id for the client-area menu hooks below (0 when nobody is logged in).
 */
if (!function_exists('pasargadcdn_admin_client_id')) {
    function pasargadcdn_admin_client_id(): int
    {
        try {
            if (class_exists('\\WHMCS\\Authentication\\CurrentUser')) {
                $c = (new \WHMCS\Authentication\CurrentUser())->client();
                return $c ? (int) $c->id : 0;
            }
        } catch (\Throwable $e) {
            // fall through
        }
        return (int) ($_SESSION['uid'] ?? 0);
    }
}

/** The client's shared domains / pending invitations, or null when there are none (or on any error). */
if (!function_exists('pasargadcdn_admin_shared_links')) {
    function pasargadcdn_admin_shared_links(int $uid): ?array
    {
        if ($uid <= 0) {
            return null;
        }
        try {
            require_once __DIR__ . '/lib/Env.php';
            require_once __DIR__ . '/lib/View.php';
            require_once __DIR__ . '/lib/Data.php';
            require_once __DIR__ . '/lib/Sharing.php';
            if (!\PasargadCdn\Admin\Env::loadServerModule()) {
                return null;
            }
            $mine = \PasargadCdn\Admin\Sharing::mine($uid);
            if (!$mine['active'] && !$mine['pending']) {
                return null;
            }
            return ['label' => \PasargadCdn\Admin\Sharing::menuLabel($uid), 'links' => \PasargadCdn\Admin\Sharing::links($uid)];
        } catch (\Throwable $e) {
            return null;
        }
    }
}

/** SPEC §19.3: loads the customer-transfer library (false when the server module is missing). */
if (!function_exists('pasargadcdn_admin_xfer_load')) {
    function pasargadcdn_admin_xfer_load(): bool
    {
        require_once __DIR__ . '/lib/Env.php';
        require_once __DIR__ . '/lib/View.php';
        require_once __DIR__ . '/lib/Data.php';
        require_once __DIR__ . '/lib/Pages.php';
        require_once __DIR__ . '/lib/Operator.php';
        require_once __DIR__ . '/lib/Transfer.php';
        require_once __DIR__ . '/lib/CustomerTransfer.php';
        return \PasargadCdn\Admin\Env::loadServerModule();
    }
}

/** SPEC §19.3: menu label «درخواست‌های انتقال دامنه (n)» when transfers wait for this client's answer, else null. */
if (!function_exists('pasargadcdn_admin_xfer_hint')) {
    function pasargadcdn_admin_xfer_hint(int $uid): ?string
    {
        if ($uid <= 0) {
            return null;
        }
        try {
            if (!pasargadcdn_admin_xfer_load()) {
                return null;
            }
            $n = \PasargadCdn\Admin\CustomerTransfer::pendingCount($uid);
            if ($n <= 0) {
                return null;
            }
            return function_exists('pasargadcdn_lang') && \pasargadcdn_lang([]) === 'en' ? 'Domain transfer requests (' . $n . ')'
                : 'درخواست‌های انتقال دامنه (' . strtr((string) $n, ['0' => '۰', '1' => '۱', '2' => '۲', '3' => '۳', '4' => '۴', '5' => '۵', '6' => '۶', '7' => '۷', '8' => '۸', '9' => '۹']) . ')';
        } catch (\Throwable $e) {
            return null;
        }
    }
}

// SPEC §20.3: «دامنه‌های اشتراکی» under the client-area «Services» menu (only for clients with a share or an invite)
// SPEC §19.3: «درخواست‌های انتقال دامنه (n)» next to it while transfers wait for this client's answer
add_hook('ClientAreaPrimaryNavbar', 1, function ($navbar) {
    try {
        if (!is_object($navbar) || !method_exists($navbar, 'getChild')) {
            return;
        }
        $uid = pasargadcdn_admin_client_id();
        $items = [];
        $info = pasargadcdn_admin_shared_links($uid);
        if ($info !== null) {
            $items['pasargadcdn-shared-domains'] = ['label' => $info['label'], 'uri' => \PasargadCdn\Admin\Sharing::ROUTE, 'order' => 15];
        }
        $xfer = pasargadcdn_admin_xfer_hint($uid);
        if ($xfer !== null) {
            $items['pasargadcdn-transfer-requests'] = ['label' => $xfer, 'uri' => \PasargadCdn\Admin\CustomerTransfer::ROUTE, 'order' => 16];
        }
        if (!$items) {
            return;
        }
        $services = $navbar->getChild('Services');
        foreach ($items as $key => $item) {
            if (is_object($services) && method_exists($services, 'addChild')) {
                $services->addChild($key, $item);
            } else {
                $navbar->addChild($key, ['order' => $item['order'] + 10] + $item);
            }
        }
    } catch (\Throwable $e) {
        // the menu never breaks because of this item
    }
});

// SPEC §20.3: on «My Services» (and the service pages) a sidebar box lists the shared domains with direct
// «مدیریت» links — a shared domain is not a WHMCS service of the member, so it is not in that list itself
add_hook('ClientAreaSecondarySidebar', 1, function ($sidebar) {
    try {
        if (!is_object($sidebar) || !method_exists($sidebar, 'addChild')) {
            return;
        }
        $script = basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''));
        $action = (string) ($_GET['action'] ?? '');
        if ($script !== 'clientarea.php' || !in_array($action, ['products', 'services', 'productdetails'], true)) {
            return;
        }
        $uid = pasargadcdn_admin_client_id();
        // SPEC §19.3: transfers waiting for this client's answer
        $xfer = pasargadcdn_admin_xfer_hint($uid);
        if ($xfer !== null) {
            $xbox = $sidebar->addChild('pasargadcdn-transfer-requests', ['label' => $xfer, 'icon' => 'fa-exchange-alt', 'order' => 4]);
            if (is_object($xbox) && method_exists($xbox, 'addChild')) {
                $xbox->addChild('pcdn-xfer-open', ['label' => function_exists('pasargadcdn_lang') && \pasargadcdn_lang([]) === 'en'
                    ? 'View and answer' : 'مشاهده و پاسخ', 'uri' => \PasargadCdn\Admin\CustomerTransfer::ROUTE, 'order' => 1]);
            }
        }
        $info = pasargadcdn_admin_shared_links($uid);
        if ($info === null) {
            return;
        }
        $box = $sidebar->addChild('pasargadcdn-shared-domains', ['label' => $info['label'], 'icon' => 'fa-users', 'order' => 5]);
        if (!is_object($box) || !method_exists($box, 'addChild')) {
            return;
        }
        $i = 0;
        foreach ($info['links'] as [$domain, $uri, $id]) {
            $box->addChild('pcdn-share-' . $id, ['label' => $domain, 'uri' => $uri, 'order' => ++$i]);
        }
        $box->addChild('pcdn-share-all', ['label' => function_exists('pasargadcdn_lang') && \pasargadcdn_lang([]) === 'en'
            ? 'All shared domains / invitations' : 'همهٔ دامنه‌های اشتراکی و دعوت‌ها', 'uri' => \PasargadCdn\Admin\Sharing::ROUTE, 'order' => 999]);
    } catch (\Throwable $e) {
        // the sidebar never breaks because of this box
    }
});

// SPEC §20.3: a «دامنه‌های اشتراکی» box on top of «My Services» (clientarea.php?action=services|products). The box is
// rendered server-side and moved above the services table by a tiny script (works with the standard templates;
// with an unknown template it stays where the footer is, still visible).
add_hook('ClientAreaFooterOutput', 1, function ($vars) {
    try {
        $script = basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''));
        $action = (string) ($_GET['action'] ?? '');
        if ($script !== 'clientarea.php' || !in_array($action, ['services', 'products'], true)) {
            return '';
        }
        $uid = pasargadcdn_admin_client_id();
        if (pasargadcdn_admin_shared_links($uid) === null) {
            return '';
        }
        $box = \PasargadCdn\Admin\Sharing::servicesBox($uid);
        if ($box === '') {
            return '';
        }
        return '<div id="pcdn-shared-services-holder">' . $box . '</div><script>(function(){var b=document.getElementById("pcdn-shared-services");'
            . 'if(!b)return;var t=document.getElementById("tableServicesList")||document.querySelector(".table-container table, table.table-list, .main-content table");'
            . 'var anchor=t?(t.closest(".table-container")||t.closest(".dataTables_wrapper")||t):(document.querySelector(".main-content")||document.querySelector("#main-body"));'
            . 'if(!anchor)return;if(t){anchor.parentNode.insertBefore(b,anchor);}else{anchor.insertBefore(b,anchor.firstChild);}})();</script>';
    } catch (\Throwable $e) {
        return '';
    }
});
