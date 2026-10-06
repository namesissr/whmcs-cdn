<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;

if (class_exists(__NAMESPACE__ . '\\AbusePage', false)) {
    return;
}

/**
 * SPEC §23.10 — the public abuse report page of the client area: index.php?m=pasargadcdn_admin&page=abuse (no login).
 *
 *   GET                         form: category, 1..10 URLs, description (≤ 4000), optional e-mail, a hidden honeypot and a proof-of-work
 *                               challenge from the controller (GET /public/v1/abuse/challenge) that assets/abuse.js solves in the browser:
 *                               sha256(UTF-8(salt hex string + decimal nonce string)) with ≥ `bits` leading zero bits, nonce sent as a string;
 *   POST                        server-side submit to the admin API POST /api/v1/abuse/reports (same body) with X-PCDN-Reporter-IP (the
 *                               controller hashes it at once and never stores it) → the ticket and the one-time status token are shown once;
 *   GET ?ticket=AB-…&token=…    status lookup (GET /public/v1/abuse/reports/{ticket}?token=…): status + public note only.
 * Off unless the addon setting «صفحهٔ عمومی گزارش تخلف» is on (and the controller has ABUSE_ENABLED). The form carries a session token
 * against cross-site posts. Persian (RTL) or English (?lang=en). Nothing on the page names the billing software.
 */
final class AbusePage
{
    const ROUTE = 'index.php?m=pasargadcdn_admin&page=abuse';
    const TICKET = '/^AB-[0-9A-Z]{8}$/D';
    const TOKEN = '/^[A-Za-z0-9_-]{16,64}$/D';
    const CATEGORIES = ['phishing' => ['فیشینگ (جعل هویت برای سرقت اطلاعات)', 'Phishing'], 'malware' => ['بدافزار', 'Malware'],
        'illegal' => ['محتوای غیرقانونی', 'Illegal content'], 'spam' => ['هرزنامه', 'Spam'], 'copyright' => ['نقض حق نشر', 'Copyright infringement'],
        'other' => ['سایر', 'Other']];
    const STATUS = ['new' => ['دریافت شد', 'Received'], 'triage' => ['در حال بررسی', 'Under review'], 'notified' => ['به صاحب سایت اطلاع داده شد', 'Site owner notified'],
        'actioned' => ['اقدام شد', 'Action taken'], 'closed' => ['بسته شد', 'Closed'], 'rejected' => ['رد شد', 'Rejected']];
    const T = [
        'title' => ['گزارش تخلف', 'Report abuse'],
        'lead' => ['اگر سایتی که از شبکهٔ CDN ما استفاده می‌کند محتوای ناقض قانون یا مخرب دارد، اینجا گزارش دهید. هویت شما برای صاحب سایت فاش نمی‌شود.',
            'If a site that uses our CDN hosts illegal or harmful content, report it here. Your identity is never shared with the site owner.'],
        'off' => ['این صفحه فعال نیست.', 'This page is not available.'],
        'category' => ['نوع تخلف', 'Category'],
        'urls' => ['نشانی‌ها (هر خط یک نشانی، حداکثر ۱۰)', 'Addresses (one per line, up to 10)'],
        'desc' => ['توضیح', 'Description'],
        'email' => ['ایمیل شما (اختیاری، برای اطلاع از نتیجه)', 'Your e-mail (optional, to hear about the outcome)'],
        'send' => ['ارسال گزارش', 'Send report'],
        'solving' => ['در حال آماده‌سازی ارسال…', 'Preparing to send…'],
        'nojs' => ['برای ارسال، جاوااسکریپت مرورگر را فعال کنید.', 'Enable JavaScript in your browser to send the report.'],
        'done' => ['گزارش شما ثبت شد.', 'Your report has been received.'],
        'ticket' => ['شناسهٔ پیگیری', 'Tracking ID'],
        'token' => ['کد پیگیری (فقط همین یک بار نمایش داده می‌شود؛ آن را نگه دارید)', 'Tracking code (shown only once; keep it)'],
        'track' => ['پیگیری وضعیت', 'Check status'],
        'lookup' => ['پیگیری گزارش قبلی', 'Check an earlier report'],
        'status' => ['وضعیت', 'Status'],
        'created' => ['ثبت', 'Received'],
        'updated' => ['آخرین تغییر', 'Last update'],
        'note' => ['یادداشت', 'Note'],
        'notfound' => ['گزارشی با این شناسه و کد پیدا نشد.', 'No report with this ID and code was found.'],
        'bad' => ['اطلاعات واردشده کامل یا معتبر نیست؛ نشانی‌ها باید با http:// یا https:// شروع شوند.', 'The form is incomplete or invalid; addresses must start with http:// or https://.'],
        'rate' => ['تعداد گزارش‌های این ساعت به سقف رسیده است؛ کمی بعد دوباره تلاش کنید.', 'Too many reports this hour; try again a little later.'],
        'expired' => ['فرم منقضی شده است؛ صفحه را دوباره بارگذاری کنید.', 'The form has expired; reload the page.'],
        'down' => ['ارسال گزارش در حال حاضر ممکن نیست؛ کمی بعد دوباره تلاش کنید.', 'Reports cannot be sent right now; try again a little later.'],
        'lang' => ['English', 'فارسی'],
        'new' => ['گزارش جدید', 'New report'],
    ];

    /** @var callable|null tests: receives the page array instead of WHMCS rendering it */
    public static $clientIp = null;

    public static function tx(string $k, string $lang): string
    {
        return self::T[$k][$lang === 'en' ? 1 : 0] ?? $k;
    }

    private static function e($v): string
    {
        return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private static function page(string $html, string $lang): array
    {
        $title = self::tx('title', $lang);
        return ['pagetitle' => $title, 'breadcrumb' => [self::ROUTE => $title], 'templatefile' => 'pricing', 'requirelogin' => false, 'forcessl' => false,
            'vars' => ['pcdn_html' => $html, 'pcdn_lang' => $lang]];
    }

    private static function wrap(string $body, string $lang): string
    {
        $dir = $lang === 'en' ? 'ltr' : 'rtl';
        $other = $lang === 'en' ? 'fa' : 'en';
        return '<div class="pcdn-abuse" dir="' . $dir . '" lang="' . $lang . '"><style>.pcdn-abuse{max-width:760px;margin:0 auto;padding:8px 0 28px}'
            . '.pcdn-abuse *{box-sizing:border-box}.pcdn-abuse h1{font-size:1.5rem;margin:0 0 6px}.pcdn-abuse .pa-top{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}'
            . '.pcdn-abuse label{display:block;font-weight:600;margin:12px 0 4px}.pcdn-abuse input,.pcdn-abuse select,.pcdn-abuse textarea{width:100%;max-width:100%;padding:8px 10px;border:1px solid rgba(0,0,0,.25);border-radius:8px;font:inherit}'
            . '.pcdn-abuse textarea{min-height:90px}.pcdn-abuse .pa-btn{margin-top:14px;padding:10px 18px;border:0;border-radius:8px;background:#1d5fd6;color:#fff;font-weight:700;cursor:pointer}'
            . '.pcdn-abuse .pa-btn[disabled]{opacity:.6;cursor:wait}.pcdn-abuse .pa-box{border:1px solid rgba(0,0,0,.15);border-radius:12px;padding:16px;margin:14px 0}'
            . '.pcdn-abuse .pa-ok{border-color:#16a34a;background:rgba(22,163,74,.06)}.pcdn-abuse .pa-err{border-color:#dc2626;background:rgba(220,38,38,.06)}'
            . '.pcdn-abuse code{direction:ltr;unicode-bidi:embed;word-break:break-all}.pcdn-abuse .pa-hp{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap}'
            . '.pcdn-abuse .pa-muted{opacity:.75;font-size:.9rem}</style>'
            . '<div class="pa-top"><h1>' . self::e(self::tx('title', $lang)) . '</h1><a hreflang="' . $other . '" href="' . self::e(self::ROUTE . '&lang=' . $other) . '">' . self::e(self::tx('lang', $lang)) . '</a></div>'
            . $body . '</div>';
    }

    private static function lang(array $get): string
    {
        $l = strtolower((string) ($get['lang'] ?? ''));
        if ($l === 'en' || $l === 'fa') {
            return $l;
        }
        return strtolower((string) ($_SESSION['Language'] ?? '')) === 'english' ? 'en' : 'fa';
    }

    private static function api(): ApiClient
    {
        return Env::api(10);
    }

    public static function clientArea(array $get, array $post, string $method, ?array &$session = null): array
    {
        if ($session === null) {
            $session = &$_SESSION;
        }
        $lang = self::lang($get);
        if (!Env::enabled('abuse_page', false)) {
            return self::page(self::wrap('<p>' . self::e(self::tx('off', $lang)) . '</p>', $lang), $lang);
        }
        if ($method === 'POST') {
            return self::page(self::wrap(self::submit($post, $lang, $session), $lang), $lang);
        }
        $ticket = strtoupper(trim((string) ($get['ticket'] ?? '')));
        $token = trim((string) ($get['token'] ?? ''));
        if ($ticket !== '' || $token !== '') {
            return self::page(self::wrap(self::lookup($ticket, $token, $lang) . self::lookupForm($lang, $ticket), $lang), $lang);
        }
        return self::page(self::wrap(self::form($lang, $session) . self::lookupForm($lang, ''), $lang), $lang);
    }

    /** The report form with a fresh proof-of-work challenge from the controller. */
    private static function form(string $lang, array &$session, string $err = ''): string
    {
        try {
            [$code, $ch] = self::api()->raw('GET', '/public/v1/abuse/challenge');
        } catch (\Throwable $e) {
            $code = 0;
            $ch = null;
        }
        if ($code === 404) {
            return '<p>' . self::e(self::tx('off', $lang)) . '</p>';
        }
        if ($code !== 200 || !is_array($ch) || !is_string($ch['id'] ?? null) || !is_string($ch['salt'] ?? null) || !preg_match('/^[0-9a-fA-F]{8,128}$/D', $ch['salt'])
            || !is_numeric($ch['bits'] ?? null)) {
            return '<div class="pa-box pa-err">' . self::e(self::tx('down', $lang)) . '</div>';
        }
        $tok = bin2hex(random_bytes(16));
        $session['pcdn_abuse_tok'] = $tok;
        $bits = max(1, min(30, (int) $ch['bits']));
        $opts = '';
        foreach (self::CATEGORIES as $k => [$fa, $en]) {
            $opts .= '<option value="' . $k . '">' . self::e($lang === 'en' ? $en : $fa) . '</option>';
        }
        return '<p>' . self::e(self::tx('lead', $lang)) . '</p>' . ($err !== '' ? '<div class="pa-box pa-err" role="alert">' . self::e($err) . '</div>' : '')
            . '<form method="post" action="' . self::e(self::ROUTE . '&lang=' . $lang) . '" class="pa-form" data-pow="1" data-salt="' . self::e($ch['salt']) . '" data-bits="' . $bits . '">'
            . '<input type="hidden" name="pa_tok" value="' . self::e($tok) . '"><input type="hidden" name="challenge_id" value="' . self::e($ch['id']) . '">'
            . '<input type="hidden" name="challenge_salt" value="' . self::e($ch['salt']) . '"><input type="hidden" name="nonce" value="" data-nonce="1">'
            . '<label for="pa-cat">' . self::e(self::tx('category', $lang)) . '</label><select id="pa-cat" name="category" required>' . $opts . '</select>'
            . '<label for="pa-urls">' . self::e(self::tx('urls', $lang)) . '</label><textarea id="pa-urls" name="urls" dir="ltr" required maxlength="21000" placeholder="https://example.com/page"></textarea>'
            . '<label for="pa-desc">' . self::e(self::tx('desc', $lang)) . '</label><textarea id="pa-desc" name="description" dir="auto" required maxlength="4000"></textarea>'
            . '<label for="pa-email">' . self::e(self::tx('email', $lang)) . '</label><input id="pa-email" name="email" type="email" dir="ltr" maxlength="254" autocomplete="email">'
            . '<div class="pa-hp" aria-hidden="true"><label for="pa-web">Website</label><input id="pa-web" name="website" tabindex="-1" autocomplete="off" value=""></div>'
            . '<noscript><p class="pa-muted">' . self::e(self::tx('nojs', $lang)) . '</p></noscript>'
            . '<button type="submit" class="pa-btn" disabled data-label="' . self::e(self::tx('send', $lang)) . '" data-wait="' . self::e(self::tx('solving', $lang)) . '">'
            . self::e(self::tx('solving', $lang)) . '</button></form>'
            . '<script src="modules/addons/pasargadcdn_admin/assets/abuse.js?v=' . (string) @filemtime(dirname(__DIR__) . '/assets/abuse.js') . '" defer></script>';
    }

    private static function lookupForm(string $lang, string $ticket): string
    {
        return '<div class="pa-box"><h2 style="font-size:1.1rem;margin:0">' . self::e(self::tx('lookup', $lang)) . '</h2>'
            . '<form method="get" action="index.php" class="pa-lookup"><input type="hidden" name="m" value="pasargadcdn_admin"><input type="hidden" name="page" value="abuse">'
            . '<input type="hidden" name="lang" value="' . $lang . '"><label for="pa-t">' . self::e(self::tx('ticket', $lang)) . '</label>'
            . '<input id="pa-t" name="ticket" dir="ltr" maxlength="11" placeholder="AB-XXXXXXXX" value="' . self::e($ticket) . '">'
            . '<label for="pa-k">' . self::e(self::tx('token', $lang)) . '</label><input id="pa-k" name="token" dir="ltr" maxlength="64" autocomplete="off">'
            . '<button type="submit" class="pa-btn">' . self::e(self::tx('track', $lang)) . '</button></form></div>';
    }

    private static function lookup(string $ticket, string $token, string $lang): string
    {
        if (!preg_match(self::TICKET, $ticket) || !preg_match(self::TOKEN, $token)) {
            return '<div class="pa-box pa-err" role="alert">' . self::e(self::tx('notfound', $lang)) . '</div>';
        }
        try {
            [$code, $d] = self::api()->raw('GET', '/public/v1/abuse/reports/' . rawurlencode($ticket) . '?token=' . rawurlencode($token));
        } catch (\Throwable $e) {
            return '<div class="pa-box pa-err">' . self::e(self::tx('down', $lang)) . '</div>';
        }
        if ($code !== 200 || !is_array($d)) {
            return '<div class="pa-box pa-err" role="alert">' . self::e(self::tx($code === 404 || $code === 403 || $code === 401 ? 'notfound' : 'down', $lang)) . '</div>';
        }
        $st = (string) ($d['status'] ?? '');
        $label = self::STATUS[$st][$lang === 'en' ? 1 : 0] ?? $st;
        return '<div class="pa-box pa-ok" data-abuse-status="' . self::e($st) . '"><p><strong>' . self::e(self::tx('ticket', $lang)) . ':</strong> <code>' . self::e($ticket) . '</code></p>'
            . '<p><strong>' . self::e(self::tx('status', $lang)) . ':</strong> ' . self::e($label) . '</p>'
            . '<p class="pa-muted">' . self::e(self::tx('created', $lang)) . ': ' . self::e((string) ($d['created_at'] ?? '')) . ' · ' . self::e(self::tx('updated', $lang)) . ': ' . self::e((string) ($d['updated_at'] ?? '')) . '</p>'
            . (!empty($d['public_note']) ? '<p><strong>' . self::e(self::tx('note', $lang)) . ':</strong> <span dir="auto">' . self::e(mb_substr((string) $d['public_note'], 0, 500)) . '</span></p>' : '')
            . '</div>';
    }

    private static function clientIp(): string
    {
        if (self::$clientIp) {
            return (string) (self::$clientIp)();
        }
        return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    }

    private static function submit(array $post, string $lang, array &$session): string
    {
        $tok = (string) ($session['pcdn_abuse_tok'] ?? '');
        unset($session['pcdn_abuse_tok']);
        if ($tok === '' || !hash_equals($tok, (string) ($post['pa_tok'] ?? ''))) {
            return self::form($lang, $session, self::tx('expired', $lang));
        }
        $cat = (string) ($post['category'] ?? '');
        $urls = [];
        foreach (preg_split('/[\r\n]+/', (string) ($post['urls'] ?? '')) as $u) {
            $u = trim($u);
            if ($u !== '') {
                $urls[] = $u;
            }
        }
        $desc = trim((string) ($post['description'] ?? ''));
        $email = trim((string) ($post['email'] ?? ''));
        $nonce = (string) ($post['nonce'] ?? '');
        $ok = isset(self::CATEGORIES[$cat]) && $urls && count($urls) <= 10 && $desc !== '' && mb_strlen($desc) <= 4000
            && ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL)) && preg_match('/^[0-9]{1,20}$/D', $nonce)
            && preg_match('/^[0-9a-fA-F]{8,128}$/D', (string) ($post['challenge_salt'] ?? '')) && preg_match('/^[A-Za-z0-9._:-]{1,200}$/D', (string) ($post['challenge_id'] ?? ''));
        foreach ($urls as $u) {
            $ok = $ok && strlen($u) <= 2048 && preg_match('#^https?://[^\s/$.?\#][^\s]*$#iD', $u);
        }
        if (!$ok) {
            return self::form($lang, $session, self::tx('bad', $lang));
        }
        $body = ['category' => $cat, 'urls' => $urls, 'description' => $desc,
            'challenge' => ['id' => (string) $post['challenge_id'], 'salt' => (string) $post['challenge_salt'], 'nonce' => $nonce],
            // the honeypot goes through as typed: the controller refuses a filled one (bots)
            'website' => (string) ($post['website'] ?? '')];
        if ($email !== '') {
            $body['email'] = $email;
        }
        try {
            $api = self::api()->setReporterIp(self::clientIp());
            try {
                [$code, $d] = $api->raw('POST', '/api/v1/abuse/reports', (string) json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            } finally {
                $api->setReporterIp('');   // the memoised client never carries it into another call
            }
        } catch (\Throwable $e) {
            return self::form($lang, $session, self::tx('down', $lang));
        }
        if ($code === 429) {
            return self::form($lang, $session, self::tx('rate', $lang));
        }
        if ($code === 422 || $code === 400) {
            return self::form($lang, $session, self::tx('bad', $lang));
        }
        if ($code < 200 || $code >= 300 || !is_array($d) || !preg_match(self::TICKET, (string) ($d['ticket'] ?? '')) || !preg_match(self::TOKEN, (string) ($d['status_token'] ?? ''))) {
            return self::form($lang, $session, self::tx($code === 404 ? 'off' : 'down', $lang));
        }
        $link = self::ROUTE . '&lang=' . $lang . '&ticket=' . rawurlencode((string) $d['ticket']) . '&token=' . rawurlencode((string) $d['status_token']);
        Env::log('abuse report ' . $d['ticket'] . ' received from the public page (' . $cat . ', ' . count($urls) . ' URL(s))');
        return '<div class="pa-box pa-ok" data-abuse-ticket="' . self::e($d['ticket']) . '" role="status"><p><strong>' . self::e(self::tx('done', $lang)) . '</strong></p>'
            . '<p>' . self::e(self::tx('ticket', $lang)) . ': <code>' . self::e($d['ticket']) . '</code></p>'
            . '<p>' . self::e(self::tx('token', $lang)) . ': <code data-status-token="1">' . self::e($d['status_token']) . '</code></p>'
            . '<p><a href="' . self::e($link) . '">' . self::e(self::tx('track', $lang)) . '</a> · <a href="' . self::e(self::ROUTE . '&lang=' . $lang) . '">' . self::e(self::tx('new', $lang)) . '</a></p></div>';
    }
}
