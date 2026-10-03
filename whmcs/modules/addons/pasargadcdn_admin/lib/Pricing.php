<?php

namespace PasargadCdn\Admin;

use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Pricing', false)) {
    return;
}

/**
 * Wave 10 (SPEC §18.5) — public pricing / comparison page of the CDN plans, served by the addon's client-area
 * route `index.php?m=pasargadcdn_admin&page=pricing` (no login) and as embeddable JSON (`&format=json`, CORS *).
 * Off by default (addon setting «صفحهٔ عمومی قیمت‌ها»); plans listed in «پلن‌های پنهان» are left out.
 *
 * Plans = the products the wizard manages (mod_pasargadcdn_settings wizard_pids, in plan order), else every
 * visible CDN product; never the trial product, hidden or retired products. Prices come from tblpricing in the
 * visitor's currency (logged-in client → their currency; `?currency=<id>`; session; WHMCS default); quota and
 * features from the product's module settings (pasargadcdn_plan, the same mapping provisioning uses). The plan
 * data is cached 10 minutes per currency (Env::cacheGet/Set). Order buttons go to WHMCS's own cart.
 */
final class Pricing
{
    const TTL = 600;
    const CACHE = 'pcdn_pricing_v1_';

    /** Feature rows of the comparison: key → [fa, en, kind (bool|num)]. */
    const FEATURES = [
        'ssl_allowed' => ['SSL رایگان', 'Free SSL', 'bool'],
        'max_records' => ['رکورد DNS', 'DNS records', 'num'],
        'waf' => ['فایروال برنامهٔ وب (WAF)', 'Web application firewall (WAF)', 'bool'],
        'ddos' => ['حفاظت DDoS', 'DDoS protection', 'bool'],
        'max_firewall_rules' => ['قانون فایروال', 'Firewall rules', 'num'],
        'max_page_rules' => ['قانون صفحه', 'Page rules', 'num'],
        'max_ratelimit_rules' => ['قانون محدودیت نرخ', 'Rate-limit rules', 'num'],
        'load_balancer' => ['توزیع بار', 'Load balancing', 'bool'],
        'image_optimization' => ['بهینه‌سازی تصویر', 'Image optimization', 'bool'],
        'custom_ssl' => ['گواهی SSL اختصاصی', 'Custom SSL certificate', 'bool'],
        'dnssec' => ['DNSSEC', 'DNSSEC', 'bool'],
        'tunnel' => ['تونل (VPN پشت CDN)', 'Tunnel (VPN over CDN)', 'bool'],
        'max_tunnel_paths' => ['مسیر تونل', 'Tunnel paths', 'num'],
        'max_tunnel_origins' => ['مبدأ هر مسیر تونل (جایگزینی خودکار)', 'Origins per tunnel path (automatic failover)', 'num'],
        'waiting_room' => ['اتاق انتظار', 'Waiting room', 'bool'],
        'access' => ['دسترسی محافظت‌شده', 'Protected access', 'bool'],
    ];

    const T = [
        'title' => ['قیمت پلن‌های CDN', 'CDN plans and pricing'],
        'lead' => ['سرعت بیشتر و امنیت بالاتر برای سایت شما، با نیم‌سرورها و نودهای داخل ایران.', 'A faster, safer site with nameservers and edge nodes inside Iran.'],
        'monthly' => ['ماهانه', 'Monthly'],
        'annually' => ['سالانه', 'Yearly'],
        'per_month' => ['در ماه', 'per month'],
        'per_year' => ['در سال', 'per year'],
        'traffic' => ['ترافیک ماهانه', 'Monthly traffic'],
        'unlimited' => ['نامحدود', 'Unlimited'],
        'order' => ['سفارش', 'Order'],
        'order_year' => ['سفارش سالانه', 'Order yearly'],
        'compare' => ['مقایسهٔ امکانات', 'Compare features'],
        'feature' => ['امکان', 'Feature'],
        'yes' => ['دارد', 'Yes'],
        'no' => ['ندارد', 'No'],
        'none' => ['فعلاً پلنی برای نمایش نیست.', 'No plans to show right now.'],
        'off' => ['این صفحه فعال نیست.', 'This page is not available.'],
        'lang' => ['English', 'فارسی'],
        'na' => ['—', '—'],
    ];

    /** @var callable|null tests: receives [status, headers, body] instead of exit */
    public static $sink = null;

    public static function tx(string $k, string $lang): string
    {
        return self::T[$k][$lang === 'en' ? 1 : 0] ?? $k;
    }

    public static function enabled(): bool
    {
        return Env::enabled('pricing_enabled', false);
    }

    /** Product ids the admin hid from the page («پلن‌های پنهان»: ids, comma separated). */
    public static function hiddenIds(): array
    {
        $out = [];
        foreach (preg_split('/[\s,،]+/u', Env::setting('pricing_hidden', '')) ?: [] as $v) {
            if (ctype_digit($v)) {
                $out[(int) $v] = true;
            }
        }
        return $out;
    }

    /** fa | en: ?lang= first, then the visitor's client-area language (cookie / session / client / default). */
    public static function lang(array $get): string
    {
        $l = is_string($get['lang'] ?? null) ? strtolower($get['lang']) : '';
        if ($l === 'fa' || $l === 'en') {
            return $l;
        }
        if ($l === 'english') {
            return 'en';
        }
        if ($l === 'farsi' || $l === 'persian') {
            return 'fa';
        }
        if (Env::loadServerModule() && class_exists('\\PasargadCdn\\I18n')) {
            return \PasargadCdn\I18n::lang();
        }
        return 'fa';
    }

    /** The visitor's currency row: logged-in client's, ?currency=<id>, session, WHMCS default. */
    public static function currency(array $get, int $clientId = 0)
    {
        $id = 0;
        if ($clientId > 0) {
            $id = (int) Capsule::table('tblclients')->where('id', $clientId)->value('currency');
        }
        if ($id <= 0 && is_string($get['currency'] ?? null) && ctype_digit($get['currency'])) {
            $id = (int) $get['currency'];
        }
        if ($id <= 0 && isset($_SESSION['currency']) && is_numeric($_SESSION['currency'])) {
            $id = (int) $_SESSION['currency'];
        }
        $c = $id > 0 ? Capsule::table('tblcurrencies')->where('id', $id)->first() : null;
        return $c ?: (Capsule::table('tblcurrencies')->where('default', 1)->first() ?: Capsule::table('tblcurrencies')->orderBy('id')->first());
    }

    /** The plan products, in order (wizard plans first, in plan order). */
    public static function products(): array
    {
        $hidden = self::hiddenIds();
        $trial = (int) Env::setting('trial_pid', '0');
        $q = Capsule::table('tblproducts')->where('servertype', 'pasargadcdn');
        $all = [];
        foreach ($q->orderBy('order')->orderBy('id')->get()->all() as $p) {
            $all[(int) $p->id] = $p;
        }
        $order = [];
        foreach ((array) Env::kvGet('wizard_pids', []) as $pid) {
            if (isset($all[(int) $pid])) {
                $order[(int) $pid] = true;
            }
        }
        foreach (array_keys($all) as $pid) {
            $order[$pid] = true;
        }
        $out = [];
        foreach (array_keys($order) as $pid) {
            $p = $all[$pid];
            if (isset($hidden[$pid]) || $pid === $trial || !empty($p->hidden) || !empty($p->retired ?? 0)) {
                continue;
            }
            $out[] = $p;
        }
        return $out;
    }

    /** Plan data for one currency (cached 10 minutes). */
    public static function data($currency, bool $fresh = false): array
    {
        $key = self::CACHE . (int) ($currency->id ?? 0);
        if (!$fresh) {
            $c = Env::cacheGet($key);
            if (is_array($c) && isset($c['plans'])) {
                return $c;
            }
        }
        Env::loadServerModule();
        $plans = [];
        foreach (self::products() as $p) {
            $row = (array) $p;
            $plan = function_exists('pasargadcdn_plan') ? \pasargadcdn_plan($row) : ['features' => []];
            $f = (array) ($plan['features'] ?? []);
            $f['ssl_allowed'] = !empty($plan['ssl_allowed']);
            $f['max_records'] = (int) ($plan['max_records'] ?? 0);
            $over = function_exists('pasargadcdn_overage') ? \pasargadcdn_overage($row) : null;
            $quota = $over !== null ? (float) $over['included_gb'] : (float) ($plan['bandwidth_limit_gb'] ?? 0);
            $price = Capsule::table('tblpricing')->where('type', 'product')->where('relid', (int) $p->id)
                ->where('currency', (int) ($currency->id ?? 0))->first(['monthly', 'annually']);
            $m = $price && (float) $price->monthly >= 0 ? round((float) $price->monthly, 2) : null;
            $a = $price && (float) $price->annually >= 0 ? round((float) $price->annually, 2) : null;
            if ($m === null && $a === null) {
                continue;   // not orderable in this currency
            }
            $feat = [];
            foreach (self::FEATURES as $k => [, , $kind]) {
                $feat[$k] = $kind === 'bool' ? !empty($f[$k]) : (int) ($f[$k] ?? 0);
            }
            // SPEC §22.4: a tunnel plan without the «Tunnel Origins» option gets the controller default (1 origin per path)
            if (!empty($f['tunnel']) && $feat['max_tunnel_origins'] <= 0) {
                $feat['max_tunnel_origins'] = 1;
            }
            $plans[] = ['id' => (int) $p->id, 'name' => (string) $p->name, 'monthly' => $m, 'annually' => $a,
                'quota_gb' => $quota, 'features' => $feat,
                'order_url' => ['monthly' => $m !== null ? 'cart.php?a=add&pid=' . (int) $p->id . '&billingcycle=monthly' : null,
                    'annually' => $a !== null ? 'cart.php?a=add&pid=' . (int) $p->id . '&billingcycle=annually' : null]];
        }
        $data = ['currency' => ['id' => (int) ($currency->id ?? 0), 'code' => (string) ($currency->code ?? ''),
            'prefix' => (string) ($currency->prefix ?? ''), 'suffix' => trim((string) ($currency->suffix ?? ''))],
            'plans' => $plans, 'generated_at' => gmdate('Y-m-d\TH:i:s\Z')];
        Env::cacheSet($key, $data, self::TTL);
        return $data;
    }

    private static function systemUrl(): string
    {
        try {
            return rtrim((string) Capsule::table('tblconfiguration')->where('setting', 'SystemURL')->value('value'), '/');
        } catch (\Throwable $e) {
            return '';
        }
    }

    /** JSON for the marketing site: absolute order URLs, feature labels in both languages. */
    public static function json(array $data, string $lang): string
    {
        $base = self::systemUrl();
        foreach ($data['plans'] as &$p) {
            foreach ($p['order_url'] as $k => $u) {
                if ($u !== null && $base !== '') {
                    $p['order_url'][$k] = $base . '/' . $u;
                }
            }
        }
        unset($p);
        $labels = [];
        foreach (self::FEATURES as $k => [$fa, $en]) {
            $labels[$k] = ['fa' => $fa, 'en' => $en];
        }
        return (string) json_encode(['lang' => $lang] + $data + ['feature_labels' => $labels],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    }

    private static function e($v): string
    {
        return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private static function num($v, string $lang, int $dec = 0): string
    {
        $s = number_format((float) $v, abs((float) $v - round((float) $v)) < 0.005 ? 0 : $dec, '.', ',');
        return $lang === 'en' ? $s : View::digits($s);
    }

    private static function money(?float $v, array $cur, string $lang): string
    {
        if ($v === null) {
            return '—';
        }
        $s = self::num($v, $lang, 2);
        return trim(($cur['prefix'] !== '' ? $cur['prefix'] : '') . $s . ($cur['suffix'] !== '' ? ' ' . $cur['suffix'] : ($cur['prefix'] === '' ? ' ' . $cur['code'] : '')));
    }

    /** The whole page body (self-contained styles, RTL / LTR, responsive). */
    public static function html(array $data, string $lang, string $selfUrl = 'index.php?m=pasargadcdn_admin&page=pricing'): string
    {
        $dir = $lang === 'en' ? 'ltr' : 'rtl';
        $cur = $data['currency'];
        $other = $lang === 'en' ? 'fa' : 'en';
        $h = '<div class="pcdn-pricing" dir="' . $dir . '" lang="' . $lang . '">'
            . '<style>.pcdn-pricing{--b:#1d5fd6;font-family:inherit;max-width:1180px;margin:0 auto;padding:8px 0 32px;color:inherit}'
            . '.pcdn-pricing *{box-sizing:border-box}.pcdn-pricing h1{font-size:1.7rem;margin:0 0 6px}.pcdn-pricing .pp-lead{opacity:.8;margin:0 0 18px}'
            . '.pcdn-pricing .pp-top{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:12px}'
            . '.pcdn-pricing .pp-lang{font-size:.9rem}.pcdn-pricing .pp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;margin:8px 0 28px}'
            . '.pcdn-pricing .pp-card{border:1px solid rgba(0,0,0,.12);border-radius:14px;padding:18px;display:flex;flex-direction:column;gap:10px;background:rgba(255,255,255,.6);min-width:0}'
            . '.pcdn-pricing .pp-name{font-size:1.2rem;font-weight:700;margin:0}.pcdn-pricing .pp-price{font-size:1.5rem;font-weight:800;color:var(--b);overflow-wrap:anywhere}'
            . '.pcdn-pricing .pp-sub{font-size:.85rem;opacity:.75}.pcdn-pricing ul.pp-feat{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:4px;font-size:.92rem}'
            . '.pcdn-pricing .pp-y{color:#16803c}.pcdn-pricing .pp-n{opacity:.45}.pcdn-pricing .pp-btns{margin-top:auto;display:flex;flex-wrap:wrap;gap:8px}'
            . '.pcdn-pricing .pp-btn{display:inline-block;padding:9px 16px;border-radius:9px;background:var(--b);color:#fff;text-decoration:none;font-weight:600;text-align:center;flex:1 1 auto}'
            . '.pcdn-pricing .pp-btn.pp-alt{background:transparent;color:var(--b);border:1px solid var(--b)}'
            . '.pcdn-pricing .pp-wrap{overflow-x:auto;border:1px solid rgba(0,0,0,.12);border-radius:12px}.pcdn-pricing table{width:100%;border-collapse:collapse;font-size:.92rem}'
            . '.pcdn-pricing th,.pcdn-pricing td{padding:9px 12px;border-bottom:1px solid rgba(0,0,0,.08);text-align:center;white-space:nowrap}'
            . '.pcdn-pricing th:first-child,.pcdn-pricing td:first-child{text-align:start;white-space:normal}'
            . '@media (max-width:600px){.pcdn-pricing h1{font-size:1.35rem}.pcdn-pricing .pp-grid{grid-template-columns:1fr}}</style>'
            . '<div class="pp-top"><div><h1>' . self::e(self::tx('title', $lang)) . '</h1><p class="pp-lead">' . self::e(self::tx('lead', $lang)) . '</p></div>'
            . '<a class="pp-lang" hreflang="' . $other . '" href="' . self::e($selfUrl . '&lang=' . $other) . '">' . self::e(self::tx('lang', $lang)) . '</a></div>';
        if (!$data['plans']) {
            return $h . '<p class="pp-none">' . self::e(self::tx('none', $lang)) . '</p></div>';
        }
        $h .= '<div class="pp-grid">';
        foreach ($data['plans'] as $p) {
            $f = $p['features'];
            $main = $p['monthly'] !== null ? [$p['monthly'], 'per_month'] : [$p['annually'], 'per_year'];
            $h .= '<section class="pp-card" data-plan="' . (int) $p['id'] . '"><h2 class="pp-name">' . self::e($p['name']) . '</h2>'
                . '<div class="pp-price">' . self::e(self::money($main[0], $cur, $lang)) . ' <span class="pp-sub">' . self::e(self::tx($main[1], $lang)) . '</span></div>'
                . ($p['monthly'] !== null && $p['annually'] !== null ? '<div class="pp-sub">' . self::e(self::tx('annually', $lang) . ': ' . self::money($p['annually'], $cur, $lang)) . '</div>' : '')
                . '<ul class="pp-feat"><li><strong>' . self::e(self::tx('traffic', $lang)) . ':</strong> '
                . self::e($p['quota_gb'] > 0 ? self::num($p['quota_gb'], $lang) . ' GB' : self::tx('unlimited', $lang)) . '</li>';
            foreach (['waf', 'ddos', 'tunnel', 'waiting_room', 'access', 'load_balancer'] as $k) {
                $on = !empty($f[$k]);
                $h .= '<li class="' . ($on ? 'pp-y' : 'pp-n') . '" data-f="' . $k . '">' . ($on ? '✓ ' : '✗ ') . self::e(self::FEATURES[$k][$lang === 'en' ? 1 : 0]) . '</li>';
            }
            $h .= '</ul><div class="pp-btns">';
            if ($p['order_url']['monthly'] !== null) {
                $h .= '<a class="pp-btn" href="' . self::e($p['order_url']['monthly']) . '">' . self::e(self::tx('order', $lang)) . '</a>';
            }
            if ($p['order_url']['annually'] !== null) {
                $h .= '<a class="pp-btn pp-alt" href="' . self::e($p['order_url']['annually']) . '">' . self::e(self::tx('order_year', $lang)) . '</a>';
            }
            $h .= '</div></section>';
        }
        $h .= '</div><h2 style="font-size:1.25rem">' . self::e(self::tx('compare', $lang)) . '</h2><div class="pp-wrap"><table class="pp-table"><thead><tr><th scope="col">'
            . self::e(self::tx('feature', $lang)) . '</th>';
        foreach ($data['plans'] as $p) {
            $h .= '<th scope="col">' . self::e($p['name']) . '</th>';
        }
        $h .= '</tr></thead><tbody><tr><th scope="row">' . self::e(self::tx('traffic', $lang)) . '</th>';
        foreach ($data['plans'] as $p) {
            $h .= '<td>' . self::e($p['quota_gb'] > 0 ? self::num($p['quota_gb'], $lang) . ' GB' : self::tx('unlimited', $lang)) . '</td>';
        }
        $h .= '</tr>';
        foreach (self::FEATURES as $k => [$fa, $en, $kind]) {
            $h .= '<tr data-row="' . $k . '"><th scope="row">' . self::e($lang === 'en' ? $en : $fa) . '</th>';
            foreach ($data['plans'] as $p) {
                $v = $p['features'][$k];
                $h .= '<td>' . ($kind === 'bool' ? '<span class="' . ($v ? 'pp-y' : 'pp-n') . '" role="img" aria-label="' . self::e(self::tx($v ? 'yes' : 'no', $lang))
                    . '" title="' . self::e(self::tx($v ? 'yes' : 'no', $lang)) . '">' . ($v ? '✓' : '✗') . '</span>'
                    : self::e($v > 0 ? self::num($v, $lang) : ($k === 'max_tunnel_paths' || $k === 'max_tunnel_origins' || $k === 'max_records' ? self::tx('na', $lang) : self::num(0, $lang)))) . '</td>';
            }
            $h .= '</tr>';
        }
        return $h . '</tbody></table></div></div>';
    }

    /**
     * Client-area entry (pasargadcdn_admin_clientarea, page=pricing). JSON is sent and the request ends (or the
     * test sink gets it); HTML returns WHMCS's clientarea array (templates/pricing.tpl prints pcdn_html).
     */
    public static function clientArea(array $get, int $clientId = 0): ?array
    {
        $lang = self::lang($get);
        $json = ($get['format'] ?? '') === 'json';
        if (!self::enabled()) {
            if ($json) {
                self::send(404, ['Content-Type: application/json; charset=utf-8', 'Access-Control-Allow-Origin: *', 'Cache-Control: no-store'],
                    json_encode(['detail' => 'pricing page disabled']));
                return null;
            }
            return self::page(self::tx('title', $lang), '<div class="alert alert-info" dir="' . ($lang === 'en' ? 'ltr' : 'rtl') . '">' . self::e(self::tx('off', $lang)) . '</div>', $lang);
        }
        $cur = self::currency($get, $clientId);
        $data = self::data($cur);
        if ($json) {
            self::send(200, ['Content-Type: application/json; charset=utf-8', 'Access-Control-Allow-Origin: *', 'Cache-Control: public, max-age=' . self::TTL,
                'X-Content-Type-Options: nosniff'], self::json($data, $lang));
            return null;
        }
        return self::page(self::tx('title', $lang), self::html($data, $lang), $lang);
    }

    public static function page(string $title, string $html, string $lang): array
    {
        return ['pagetitle' => $title, 'breadcrumb' => ['index.php?m=pasargadcdn_admin&page=pricing' => $title],
            'templatefile' => 'pricing', 'requirelogin' => false, 'forcessl' => false,
            'vars' => ['pcdn_html' => $html, 'pcdn_lang' => $lang]];
    }

    private static function send(int $code, array $headers, string $body): void
    {
        if (self::$sink) {
            (self::$sink)([$code, $headers, $body]);
            return;
        }
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        if (!headers_sent()) {
            http_response_code($code);
            foreach ($headers as $hd) {
                header($hd);
            }
        }
        echo $body;
        exit;
    }
}
