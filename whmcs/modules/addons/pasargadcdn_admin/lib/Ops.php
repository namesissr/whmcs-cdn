<?php

namespace PasargadCdn\Admin;

use PasargadCdn\ApiClient;
use WHMCS\Database\Capsule;

if (class_exists(__NAMESPACE__ . '\\Ops', false)) {
    return;
}

/**
 * SPEC §23 (wave 14) — the addon's «عملیات» pages (one tab, sub-navigation):
 *   - releases      «انتشار نسخه»: releases with node counts, pinned release per group, «شروع انتشار…» (preview = dry run showing the
 *                   rings), the live rollout (rings → nodes with state badges and gate details) and its actions
 *                   (POST /api/v1/rollouts…, §23.2);
 *   - backups       «پشتیبان‌گیری»: encryption / off-site / last backup / last restore test cards, run history with checks, «پشتیبان‌گیری
 *                   اکنون» / «آزمون بازیابی اکنون» (§23.3);
 *   - abuse         «گزارش‌های تخلف»: filters, queue, detail with evidence URLs as text (never fetched), linked site / owner, actions
 *                   with confirmations, notes timeline (§23.10);
 *   - slo           «SLO و بودجهٔ خطا»: month picker, per group objective vs actual, budget bar, burn per window, alert state, daily
 *                   chart (§23.11);
 *   - provisioning  «پیشنهاد افزودن نود»: capacity-driven proposals — edit region / size / count, «تأیید», plan summary with
 *                   «اجرای طرح» (refused when the plan destroys anything), join progress, «رد» (§23.9).
 * plus the admin-audience diagnostics report of one site (page=sites&view=diag, §23.8). Every page degrades to a notice when
 * the controller answers 404 (older controller / feature switched off). Every action is CSRF-checked by Admin and logged.
 */
final class Ops
{
    const PAGES = ['releases' => ['انتشار نسخه', 'sync'], 'backups' => ['پشتیبان‌گیری', 'download'], 'abuse' => ['گزارش‌های تخلف', 'shield'],
        'slo' => ['SLO و بودجهٔ خطا', 'activity'], 'provisioning' => ['پیشنهاد افزودن نود', 'server']];
    const ACTIONS = ['ops_rollout_preview', 'ops_rollout_create', 'ops_rollout_act', 'ops_rollout_edge', 'ops_backup_run', 'ops_backup_verify',
        'ops_abuse_patch', 'ops_abuse_notify', 'ops_abuse_action', 'ops_prov_approve', 'ops_prov_apply', 'ops_prov_reject', 'ops_prov_create'];

    const ROLLOUT_STATE = ['planned' => ['برنامه‌ریزی‌شده', 'muted'], 'running' => ['در حال اجرا', 'brand'], 'paused' => ['متوقف موقت', 'warn'],
        'completed' => ['کامل شد', 'ok'], 'aborted' => ['لغو شد', 'muted'], 'rolling_back' => ['در حال بازگردانی', 'warn'],
        'rolled_back' => ['بازگردانده شد', 'violet'], 'failed' => ['ناموفق', 'bad']];
    const EDGE_STATE = ['pending' => ['در انتظار', 'muted'], 'upgrading' => ['در حال ارتقا', 'brand'], 'soaking' => ['در دورهٔ پایش', 'violet'],
        'healthy' => ['سالم', 'ok'], 'failed' => ['ناموفق', 'bad'], 'rolling_back' => ['در حال بازگردانی', 'warn'], 'rolled_back' => ['بازگردانده شد', 'violet'],
        'skipped' => ['رد شد', 'muted'], 'blocked' => ['مسدود: آخرین نود', 'bad'], 'manual' => ['ارتقای دستی', 'warn']];
    const ROLLOUT_OPS = ['start' => 'شروع', 'pause' => 'توقف موقت', 'resume' => 'ادامه', 'abort' => 'لغو', 'rollback' => 'بازگردانی همه'];
    const EDGE_OPS = ['skip' => 'رد کردن', 'force' => 'ارتقا بدون تخلیه', 'retry' => 'تلاش دوباره'];
    const FORCE_CONFIRM = 'این آخرین نود این گروه/منطقه است؛ در طول ارتقا این مجموعه نود فعالی ندارد';
    const DETAILS = [
        'rollout_active' => 'یک انتشار دیگر در جریان است؛ ابتدا آن را تمام یا لغو کنید.',
        'no_rollback_release' => 'برای این نودها نسخهٔ قبلی در پوشهٔ انتشارها نیست و بازگردانی خودکار ممکن نیست',
        'invalid_state' => 'این کار در وضعیت فعلی ممکن نیست',
        'plan_destroys' => 'طرح Terraform چیزی را حذف می‌کند و اجرا نمی‌شود',
        'encryption_required' => 'برای تأیید، کنترلر باید DATA_ENCRYPTION_KEY داشته باشد (توکن‌های پیوستن رمزنگاری‌شده نگه داشته می‌شوند)',
    ];

    const ABUSE_STATUS = ['new' => ['جدید', 'bad'], 'triage' => ['در حال بررسی', 'warn'], 'notified' => ['اطلاع داده شد', 'brand'],
        'actioned' => ['اقدام شد', 'violet'], 'closed' => ['بسته شد', 'ok'], 'rejected' => ['رد شد', 'muted']];
    const ABUSE_CATEGORY = ['phishing' => 'فیشینگ', 'malware' => 'بدافزار', 'illegal' => 'محتوای غیرقانونی', 'spam' => 'هرزنامه',
        'copyright' => 'نقض حق نشر', 'other' => 'سایر'];
    const ABUSE_ACTIONS = ['warn' => ['هشدار به مالک', 'آیا به مالک سایت هشدار داده شود؟'],
        'suspend' => ['تعلیق سایت', 'سایت به دلیل تخلف معلق شود؟ بازدیدکنندگان صفحهٔ تعلیق را می‌بینند و تمدید صورت‌حساب آن را برنمی‌گرداند.'],
        'unsuspend' => ['رفع تعلیق تخلف', 'تعلیق تخلف این سایت برداشته شود؟'],
        'close' => ['بستن گزارش', 'گزارش بسته شود؟'], 'reject' => ['رد گزارش', 'گزارش رد شود؟']];
    const ABUSE_EVENT = ['created' => 'ثبت', 'triaged' => 'بررسی', 'notified' => 'اطلاع به مالک', 'note' => 'یادداشت', 'action' => 'اقدام',
        'status' => 'تغییر وضعیت', 'reporter_update' => 'به‌روزرسانی گزارش‌دهنده'];

    const PROV_STATE = ['proposed' => ['پیشنهاد شده', 'brand'], 'approved' => ['تأیید شد', 'violet'], 'planning' => ['در حال تهیهٔ طرح', 'warn'],
        'planned' => ['طرح آماده است', 'warn'], 'apply_approved' => ['اجرای طرح تأیید شد', 'violet'], 'applying' => ['در حال اجرا', 'brand'],
        'applied' => ['اجرا شد؛ در انتظار پیوستن نودها', 'brand'], 'joined' => ['نودها پیوستند', 'ok'], 'failed' => ['ناموفق', 'bad'],
        'rejected' => ['رد شد', 'muted'], 'expired' => ['منقضی شد', 'muted']];
    const SIZES = ['small' => 'کوچک', 'medium' => 'متوسط', 'large' => 'بزرگ'];
    const SLI = ['availability' => 'در دسترس‌بودن', 'latency' => 'تأخیر', 'errors' => 'خطاهای سکو'];
    const SLO_ALERT = ['fast' => ['مصرف سریع بودجه', 'bad'], 'slow' => ['مصرف کند بودجه', 'warn'], 'exhausted' => ['بودجه تمام شد', 'bad']];

    // ------------------------------------------------------------------ controller helpers

    /** [code, data] of one controller call (code 0 = unreachable); never throws. */
    public static function call(string $method, string $path, ?array $body = null): array
    {
        try {
            $payload = $body === null ? null : (string) json_encode($body === [] ? new \stdClass() : $body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            [$code, $data] = Env::api(10)->raw($method, $path, $payload);
            return [$code, $data];
        } catch (\Throwable $e) {
            return [0, ['detail' => $e->getMessage()]];
        }
    }

    /** Persian text of a controller error answer. */
    public static function err(int $code, $data): string
    {
        if ($code === 0) {
            return 'کنترلر در دسترس نیست: ' . (is_array($data) && is_string($data['detail'] ?? null) ? $data['detail'] : '');
        }
        $d = is_array($data) ? ($data['detail'] ?? null) : null;
        if (is_string($d) && isset(self::DETAILS[$d])) {
            $msg = self::DETAILS[$d];
            if ($d === 'no_rollback_release' && is_array($data['edges'] ?? null)) {
                $msg .= ': ' . implode('، ', array_map('strval', array_slice(array_filter($data['edges'], 'is_scalar'), 0, 20)));
            }
            if ($d === 'invalid_state' && is_string($data['state'] ?? null)) {
                $msg .= ' (وضعیت: ' . $data['state'] . ')';
            }
            return $msg;
        }
        return ApiClient::errorMessage($data, $code);
    }

    /** A list from a controller answer: a JSON list, or {items|rollouts|reports|proposals|runs: [...]}. */
    public static function items($data, array $keys = ['items']): array
    {
        if (!is_array($data)) {
            return [];
        }
        if (array_keys($data) !== range(0, count($data) - 1)) {
            foreach ($keys as $k) {
                if (isset($data[$k]) && is_array($data[$k])) {
                    $data = $data[$k];
                    break;
                }
            }
        }
        return array_values(array_filter(is_array($data) ? $data : [], 'is_array'));
    }

    private static function badge(array $map, $key): string
    {
        [$label, $tone] = $map[(string) $key] ?? [(string) $key, 'muted'];
        return View::badge($label, $tone, ' data-state="' . View::e((string) $key) . '"');
    }

    private static function unavailable(string $what): string
    {
        return View::alert('info', View::e($what) . ' روی این کنترلر فعال نیست (کنترلر قدیمی‌تر از موج ۱۴، یا قابلیت در تنظیمات کنترلر خاموش است).');
    }

    /** Sub-navigation of the «عملیات» tab. */
    public static function nav(string $page): string
    {
        $h = '<nav class="pcdna-subnav" aria-label="بخش‌های عملیات">';
        foreach (self::PAGES as $id => [$label, $icon]) {
            $h .= '<a class="pcdna-subnav-item' . ($id === $page ? ' is-active' : '') . '" href="' . View::url(['page' => $id]) . '"' . ($id === $page ? ' aria-current="page"' : '')
                . ' data-ops="' . $id . '">' . View::icon($icon) . '<span>' . View::e($label) . '</span></a>';
        }
        return $h . '</nav>';
    }

    public static function page(string $page, array $get, array $state): string
    {
        $ping = Pages::ping();
        $body = !$ping['ok'] ? Pages::ctlError($ping) : '';
        if ($ping['ok']) {
            switch ($page) {
                case 'releases':
                    $body = self::releases($get, $state);
                    break;
                case 'backups':
                    $body = self::backups();
                    break;
                case 'abuse':
                    $body = self::abuse($get);
                    break;
                case 'slo':
                    $body = self::slo($get);
                    break;
                case 'provisioning':
                    $body = self::provisioning($state);
                    break;
            }
        }
        return self::nav($page) . $body;
    }

    private static function size($b): string
    {
        return is_numeric($b) ? View::bytes((float) $b) : '—';
    }

    private static function sha($s): string
    {
        return is_string($s) && $s !== '' ? '<code dir="ltr" title="' . View::e($s) . '">' . View::e(substr($s, 0, 12)) . '…</code>' : '—';
    }

    // ------------------------------------------------------------------ releases & rollouts (§23.2)

    /** «نسخهٔ پین‌شده: general vX · tunnel vY · کنترلر vZ» from GET /api/v1/releases (+ /healthz); '' when unknown. */
    public static function pinnedLine(?array $rel, ?string $ctlVersion): string
    {
        if ($rel === null && ($ctlVersion === null || $ctlVersion === '')) {
            return '';
        }
        $parts = [];
        $groups = is_array($rel['groups'] ?? null) ? $rel['groups'] : [];
        foreach (['general' => 'general', 'tunnel' => 'tunnel'] as $g => $label) {
            $v = $groups[$g] ?? ($rel['pinned'] ?? null);
            $parts[] = View::e($label) . ' ' . (is_string($v) && $v !== '' ? View::ltr($v, 'pcdna-code') : '<span class="pcdna-muted">بدون پین</span>');
        }
        $cv = is_string($rel['controller'] ?? null) && $rel['controller'] !== '' ? $rel['controller'] : $ctlVersion;
        $parts[] = 'کنترلر ' . (is_string($cv) && $cv !== '' ? View::ltr('v' . ltrim($cv, 'v'), 'pcdna-code') : '<span class="pcdna-muted">نامشخص</span>');
        return '<p class="pcdna-pinned" data-pinned="1">' . View::icon('tag') . '<span><strong>نسخهٔ پین‌شده:</strong> ' . implode(' · ', $parts) . '</span></p>';
    }

    private static function releases(array $get, array $state): string
    {
        $r = Pages::fetch(['/api/v1/releases', '/api/v1/rollouts?limit=20', '/healthz']);
        $rel = $r['/api/v1/releases'];
        if (($rel['code'] ?? 0) === 404) {
            return self::unavailable('انتشار مرحله‌ای نسخه‌ها');
        }
        if (!Pages::ok($rel)) {
            return View::alert('bad', 'فهرست نسخه‌ها دریافت نشد: ' . View::e((string) $rel['error']));
        }
        $data = $rel['data'];
        $hz = Pages::ok($r['/healthz']) && is_string($r['/healthz']['data']['version'] ?? null) ? $r['/healthz']['data']['version'] : null;
        $rollouts = Pages::ok($r['/api/v1/rollouts?limit=20']) ? self::items($r['/api/v1/rollouts?limit=20']['data'], ['rollouts', 'items']) : [];
        $h = self::pinnedLine($data, $hz);
        // the live (or chosen) rollout
        $id = (int) ($get['id'] ?? 0);
        $live = null;
        foreach ($rollouts as $ro) {
            if (($id > 0 && (int) ($ro['id'] ?? 0) === $id) || ($id <= 0 && in_array($ro['state'] ?? '', ['planned', 'running', 'paused', 'rolling_back'], true))) {
                $live = $ro;
                break;
            }
        }
        if ($live || $id > 0) {
            [$c, $one] = self::call('GET', '/api/v1/rollouts/' . (int) ($live['id'] ?? $id));
            if ($c === 200 && is_array($one)) {
                $live = $one;
            }
        }
        if (!empty($state['preview'])) {
            $h .= self::previewCard($state['preview']);
        }
        if ($live) {
            $h .= self::rolloutCard($live);
        }
        // releases
        $nodes = is_array($data['nodes'] ?? null) ? $data['nodes'] : [];
        $list = self::items($data['releases'] ?? [], ['releases']);
        $busy = $live && in_array($live['state'] ?? '', ['planned', 'running', 'paused', 'rolling_back'], true);
        if (!$list) {
            $t = View::emptyState('نسخه‌ای در پوشهٔ انتشارها نیست', 'بستهٔ هر نسخه را با <code dir="ltr">tools/release/fetch-edge-release.sh vX.Y.Z --dir &lt;EDGE_RELEASES_DIR&gt;</code> روی کنترلر قرار دهید.', 'tag');
        } else {
            $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-releases"><thead><tr><th>نسخه</th><th>sha256</th><th>حجم</th><th>نودها</th><th><span class="pcdna-sr">عملیات</span></th></tr></thead><tbody>';
            foreach ($list as $x) {
                $v = (string) ($x['version'] ?? '');
                $t .= '<tr data-release="' . View::e($v) . '"><td>' . View::ltr($v, 'pcdna-code') . '</td><td>' . self::sha($x['sha256'] ?? '') . '</td><td>' . self::size($x['size'] ?? null)
                    . '</td><td class="pcdna-num">' . View::n((int) ($x['nodes'] ?? 0)) . '</td><td class="pcdna-actions">' . ($busy ? '<span class="pcdna-muted pcdna-small">انتشار دیگری در جریان است</span>' : self::startForm($v)) . '</td></tr>';
            }
            $t .= '</tbody></table></div>';
        }
        $dist = '';
        if ($nodes) {
            $dist = '<p class="pcdna-small pcdna-muted" data-release-nodes="1">نودها به تفکیک نسخه: ';
            $bits = [];
            foreach ($nodes as $k => $n) {
                $bits[] = ($k === '' || $k === 'null' ? 'نامشخص' : View::ltr((string) $k)) . ' × ' . View::n((int) $n);
            }
            $dist .= implode('، ', $bits) . '</p>';
        }
        $h .= View::card('نسخه‌های نود', $t . $dist, '', '', 'tag');
        // history
        if ($rollouts) {
            $hist = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-rollouts"><thead><tr><th>#</th><th>نسخه</th><th>وضعیت</th><th>حلقه</th><th>ایجاد</th><th>پایان</th><th>دلیل</th></tr></thead><tbody>';
            foreach ($rollouts as $ro) {
                $rid = (int) ($ro['id'] ?? 0);
                $hist .= '<tr data-rollout="' . $rid . '"><td><a href="' . View::url(['page' => 'releases', 'id' => $rid]) . '">#' . View::n($rid) . '</a></td><td>' . View::ltr((string) ($ro['release'] ?? '')) . '</td><td>'
                    . self::badge(self::ROLLOUT_STATE, $ro['state'] ?? '') . '</td><td class="pcdna-num">' . View::n((int) ($ro['ring'] ?? 0)) . '</td><td>' . View::e(View::date($ro['created_at'] ?? null, true))
                    . '</td><td>' . View::e(View::date($ro['finished_at'] ?? null, true)) . '</td><td>' . (!empty($ro['reason']) ? View::ltr(View::clip((string) $ro['reason'], 80)) : '—') . '</td></tr>';
            }
            $h .= View::card('انتشارهای اخیر', $hist . '</tbody></table></div>', '', 'pcdna-flush', 'history');
        }
        $h .= View::card('روش کار', '<ul class="pcdna-bullets"><li>حلقهٔ ۰: یک نود قناری در هر گروه؛ حلقهٔ ۱: ' . View::n(25) . '٪ بقیه به‌طور پخش در منطقه‌ها؛ حلقهٔ ۲: بقیه.</li>'
            . '<li>هر نود پیش از ارتقا تخلیه می‌شود، خودش را ارتقا می‌دهد و پس از آن در «دورهٔ پایش» با سلامت خود نود (ضربان، پروب کنترلر، پروب داخلی تونل و درصد خطای سکو) سنجیده می‌شود.</li>'
            . '<li>با شکست یک نود و «بازگردانی خودکار»، همهٔ نودهای ارتقایافتهٔ همین انتشار به نسخهٔ قبلی برمی‌گردند. آخرین نود سالم یک گروه/منطقه هیچ‌وقت بی‌صدا ارتقا داده نمی‌شود.</li>'
            . '<li>نودهای بدون قابلیت خودارتقا «ارتقای دستی» نمایش داده می‌شوند و جلوی پیشرفت را نمی‌گیرند.</li></ul>', '', '', 'info');
        return $h;
    }

    private static function startForm(string $v): string
    {
        $q = ['page' => 'releases'];
        return '<details class="pcdna-menu pcdna-rollout-start"><summary class="pcdna-btn pcdna-btn-sm pcdna-btn-primary" data-start="' . View::e($v) . '">' . View::icon('sync') . '<span>شروع انتشار…</span></summary>'
            . '<div class="pcdna-menu-list pcdna-wide-menu"><form method="post" action="' . View::url($q) . '" class="pcdna-edge-form" data-rollout-form="1">' . View::csrf()
            . '<input type="hidden" name="release" value="' . View::e($v) . '"><p class="pcdna-small"><strong>انتشار ' . View::ltr($v) . '</strong></p>'
            . '<fieldset class="pcdna-fieldset"><legend>گروه‌ها (هیچ = همه)</legend><label class="pcdna-check"><input type="checkbox" name="groups[]" value="general"> عمومی</label>'
            . '<label class="pcdna-check"><input type="checkbox" name="groups[]" value="tunnel"> تونل</label></fieldset>'
            . '<label><span>دورهٔ پایش هر نود (دقیقه، ۵ تا ۱۴۴۰)</span><input class="pcdna-input" name="soak_minutes" dir="ltr" inputmode="numeric" value="30"></label>'
            . '<label><span>درصد حلقهٔ ۱ (۱ تا ۹۰)</span><input class="pcdna-input" name="ring_percent" dir="ltr" inputmode="numeric" value="25"></label>'
            . '<label class="pcdna-check"><input type="checkbox" name="auto_rollback" value="1" checked> بازگردانی خودکار با اولین شکست</label>'
            . '<label class="pcdna-check"><input type="checkbox" name="allow_no_rollback" value="1"> اجازه به نودهای بدون نسخهٔ قبلی (بدون بازگردانی خودکار برای آن‌ها)</label>'
            . '<div class="pcdna-form-actions"><button type="submit" name="a" value="ops_rollout_preview" class="pcdna-btn pcdna-btn-sm">' . View::icon('search') . '<span>پیش‌نمایش</span></button>'
            . '<button type="submit" name="a" value="ops_rollout_create" class="pcdna-btn pcdna-btn-sm pcdna-btn-primary">' . View::icon('check') . '<span>شروع انتشار</span></button></div>'
            . '</form></div></details>';
    }

    private static function ringsTable(array $rings, ?int $rid, string $state): string
    {
        $h = '';
        foreach ($rings as $ring) {
            if (!is_array($ring)) {
                continue;
            }
            $n = (int) ($ring['ring'] ?? 0);
            $edges = self::items($ring['edges'] ?? []);
            $h .= '<h4 class="pcdna-ring-title" data-ring="' . $n . '">' . ($n === 0 ? 'حلقهٔ ۰ — قناری' : 'حلقهٔ ' . View::n($n)) . ' <span class="pcdna-muted pcdna-small">(' . View::n(count($edges)) . ' نود)</span></h4>';
            if (!$edges) {
                $h .= '<p class="pcdna-muted pcdna-small">نودی در این حلقه نیست.</p>';
                continue;
            }
            $h .= '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-ring"><thead><tr><th>نود</th><th>گروه / منطقه</th><th>وضعیت</th><th>از نسخه</th><th>سلامت</th><th>پایان پایش</th>'
                . ($rid ? '<th><span class="pcdna-sr">عملیات</span></th>' : '') . '</tr></thead><tbody>';
            foreach ($edges as $e) {
                $eid = (int) ($e['id'] ?? 0);
                $st = (string) ($e['state'] ?? '');
                $h .= '<tr data-rollout-edge="' . $eid . '" data-edge-state="' . View::e($st) . '"><td>' . View::ltr((string) ($e['name'] ?? '#' . $eid)) . '</td><td>'
                    . View::e((string) ($e['group'] ?? '')) . ' / ' . View::e((string) ($e['region'] ?? '')) . '</td><td>' . self::badge(self::EDGE_STATE, $st)
                    . (!empty($e['error']) ? '<div class="pcdna-small pcdna-err" dir="auto">' . View::e(View::clip((string) $e['error'], 160)) . '</div>' : '') . '</td><td>'
                    . (!empty($e['from_release']) ? View::ltr((string) $e['from_release']) : '<span class="pcdna-muted">—</span>') . '</td><td>' . self::gate($e['gate'] ?? null) . '</td><td>'
                    . View::e(View::date($e['soak_until'] ?? null, true)) . '</td>';
                if ($rid) {
                    $acts = '';
                    $q = ['page' => 'releases', 'id' => $rid];
                    foreach (self::EDGE_OPS as $op => $label) {
                        $ok = ($op === 'skip' && in_array($st, ['pending', 'blocked', 'failed'], true)) || ($op === 'force' && $st === 'blocked') || ($op === 'retry' && $st === 'failed');
                        if ($ok) {
                            $acts .= View::postButton($q, 'ops_rollout_edge', ['id' => $rid, 'edge' => $eid, 'op' => $op], $label,
                                'pcdna-btn pcdna-btn-sm' . ($op === 'force' ? ' pcdna-btn-danger' : ''), $op === 'force' ? self::FORCE_CONFIRM . '. ادامه می‌دهید؟' : ($op === 'skip' ? 'این نود در این انتشار ارتقا داده نشود؟' : ''),
                                $op === 'retry' ? 'refresh' : ($op === 'force' ? 'zap' : 'x'));
                        }
                    }
                    $h .= '<td class="pcdna-actions">' . $acts . '</td>';
                }
                $h .= '</tr>';
            }
            $h .= '</tbody></table></div>';
        }
        return $h;
    }

    private static function gate($g): string
    {
        if (!is_array($g)) {
            return '<span class="pcdna-muted">—</span>';
        }
        $flag = function ($v, string $label) {
            return $v === null ? '' : '<span class="pcdna-gate ' . ($v ? 'is-ok' : 'is-bad') . '" title="' . View::e($label) . '">' . ($v ? '✓' : '✗') . ' ' . View::e($label) . '</span>';
        };
        $err = is_numeric($g['error_pct'] ?? null) ? View::n((float) $g['error_pct'], 2) . '٪' : '—';
        $lim = is_numeric($g['limit_pct'] ?? null) ? View::n((float) $g['limit_pct'], 2) . '٪' : '—';
        return '<div class="pcdna-gates" data-gate="1">' . $flag($g['heartbeat'] ?? null, 'ضربان') . $flag($g['probe'] ?? null, 'پروب')
            . $flag(array_key_exists('tunnel_probe', $g) ? $g['tunnel_probe'] : null, 'پروب تونل')
            . '<span class="pcdna-gate" title="درصد خطای سکو از شروع ارتقا / سقف">خطا ' . $err . ' / ' . $lim . '</span></div>';
    }

    private static function previewCard(array $p): string
    {
        $rings = self::items($p['rings'] ?? []);
        $blocked = 0;
        foreach ($rings as $ring) {
            foreach (self::items($ring['edges'] ?? []) as $e) {
                $blocked += ($e['state'] ?? '') === 'blocked' ? 1 : 0;
            }
        }
        $body = '<p>پیش‌نمایش انتشار ' . View::ltr((string) ($p['release'] ?? '')) . ' — چیزی ذخیره نشد.</p>'
            . ($blocked ? View::alert('warn', View::n($blocked) . ' نود «مسدود: آخرین نود» است؛ هنگام اجرا انتشار آنجا متوقف می‌شود تا «رد کردن» یا «ارتقا بدون تخلیه» را انتخاب کنید.') : '')
            . self::ringsTable($rings, null, '');
        return '<div data-rollout-preview="1">' . View::card('پیش‌نمایش حلقه‌ها', $body, '', '', 'search') . '</div>';
    }

    private static function rolloutCard(array $ro): string
    {
        $rid = (int) ($ro['id'] ?? 0);
        $st = (string) ($ro['state'] ?? '');
        $q = ['page' => 'releases', 'id' => $rid];
        $acts = '';
        $allowed = ['planned' => ['start', 'abort'], 'running' => ['pause', 'abort', 'rollback'], 'paused' => ['resume', 'abort', 'rollback'],
            'completed' => ['rollback'], 'aborted' => ['rollback'], 'failed' => ['rollback']][$st] ?? [];
        foreach ($allowed as $op) {
            $acts .= View::postButton($q, 'ops_rollout_act', ['id' => $rid, 'op' => $op], self::ROLLOUT_OPS[$op],
                'pcdna-btn pcdna-btn-sm' . ($op === 'rollback' || $op === 'abort' ? ' pcdna-btn-danger' : ($op === 'start' || $op === 'resume' ? ' pcdna-btn-primary' : '')),
                $op === 'rollback' ? 'همهٔ نودهایی که این انتشار ارتقا داده به نسخهٔ قبلی برگردانده شوند؟' : ($op === 'abort' ? 'انتشار لغو شود؟ نودهای ارتقایافته همان‌طور می‌مانند.' : ''),
                ['start' => 'power', 'pause' => 'x', 'resume' => 'refresh', 'abort' => 'x', 'rollback' => 'history'][$op]);
        }
        $live = in_array($st, ['running', 'rolling_back', 'planned'], true);
        $dl = '<dl class="pcdna-dl pcdna-dl-cols"><div><dt>نسخه</dt><dd>' . View::ltr((string) ($ro['release'] ?? '')) . '</dd></div>'
            . '<div><dt>گروه‌ها</dt><dd>' . (is_array($ro['groups'] ?? null) && $ro['groups'] ? View::e(implode('، ', array_filter($ro['groups'], 'is_string'))) : 'همه') . '</dd></div>'
            . (!empty($ro['created_by']) ? '<div><dt>ایجاد توسط</dt><dd>' . View::ltr((string) $ro['created_by']) . '</dd></div>' : '')
            . '<div><dt>وضعیت</dt><dd>' . self::badge(self::ROLLOUT_STATE, $st) . '</dd></div>'
            . '<div><dt>حلقهٔ فعلی</dt><dd>' . View::n((int) ($ro['ring'] ?? 0)) . '</dd></div>'
            . '<div><dt>دورهٔ پایش</dt><dd>' . View::n((int) ($ro['soak_minutes'] ?? 0)) . ' دقیقه</dd></div>'
            . '<div><dt>حلقهٔ ۱</dt><dd>' . View::n((int) ($ro['ring_percent'] ?? 25)) . '٪</dd></div>'
            . '<div><dt>بازگردانی خودکار</dt><dd>' . (!empty($ro['auto_rollback']) ? 'روشن' : 'خاموش') . '</dd></div>'
            . '<div><dt>شروع</dt><dd>' . View::e(View::date($ro['started_at'] ?? null, true)) . '</dd></div></dl>';
        $reason = !empty($ro['reason']) ? View::alert(in_array($st, ['failed', 'rolling_back'], true) ? 'bad' : 'warn', 'دلیل: ' . View::ltr((string) $ro['reason'])) : '';
        return '<div class="pcdna-rollout-live" data-rollout-live="' . $rid . '"' . ($live ? ' data-autorefresh="20"' : '') . '>'
            . View::card('انتشار #' . $rid, $reason . $dl . self::ringsTable(self::items($ro['rings'] ?? []), $rid, $st)
                . ($live ? '<p class="pcdna-small pcdna-muted">این صفحه هر ۲۰ ثانیه به‌روز می‌شود.</p>' : ''), $acts, '', 'sync') . '</div>';
    }

    // ------------------------------------------------------------------ backups (§23.3)

    private static function run($x): string
    {
        if (!is_array($x)) {
            return '<span class="pcdna-muted">هنوز اجرا نشده</span>';
        }
        $ok = $x['ok'] ?? null;
        return ($ok === true ? View::badge('موفق', 'ok') : ($ok === false ? View::badge('ناموفق', 'bad') : View::badge('در حال اجرا', 'brand')))
            . ' <span class="pcdna-small">' . View::e(View::ago($x['finished_at'] ?? $x['started_at'] ?? null)) . '</span>'
            . (!empty($x['level']) ? ' ' . View::badge($x['level'] === 'full' ? 'کامل' : 'جزئی', $x['level'] === 'full' ? 'ok' : 'warn', ' data-level="' . View::e((string) $x['level']) . '"') : '')
            . (!empty($x['error']) ? '<div class="pcdna-small pcdna-err" dir="ltr">' . View::e(View::clip((string) $x['error'], 200)) . '</div>' : '');
    }

    private static function backups(): string
    {
        $r = Pages::fetch(['/api/v1/backups']);
        $b = $r['/api/v1/backups'];
        if (($b['code'] ?? 0) === 404) {
            return self::unavailable('وضعیت پشتیبان‌گیری');
        }
        if (!Pages::ok($b)) {
            return View::alert('bad', 'وضعیت پشتیبان‌گیری دریافت نشد: ' . View::e((string) $b['error']));
        }
        $d = $b['data'];
        $sch = is_array($d['schedule'] ?? null) ? $d['schedule'] : [];
        $ver = is_array($sch['verify'] ?? null) ? $sch['verify'] : [];
        $remote = is_array($d['remote'] ?? null) ? $d['remote'] : null;
        $days = ['دوشنبه', 'سه‌شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه', 'شنبه', 'یکشنبه'];
        $h = '<div class="pcdna-kpis" data-backup-cards="1">'
            . View::kpi('key', !empty($d['encrypted']) ? 'ok' : 'bad', 'رمزنگاری', !empty($d['encrypted']) ? 'روشن' : 'خاموش',
                !empty($d['encrypted']) ? 'AES-256-GCM با کلید جدا از کلید داده‌ها' : 'BACKUP_ENCRYPTION_KEY را تنظیم کنید')
            . View::kpi('globe', !empty($d['offsite']) ? 'ok' : 'warn', 'خارج از سرور', !empty($d['offsite']) ? 'روشن' : 'فقط محلی',
                $remote ? View::n((int) ($remote['count'] ?? 0)) . ' نسخه · ' . self::size($remote['bytes'] ?? null) : 'مقصد S3 تعریف نشده')
            . View::kpi('download', ($d['last_backup']['ok'] ?? null) === false ? 'bad' : 'brand', 'آخرین پشتیبان', self::run($d['last_backup'] ?? null),
                is_numeric($sch['backup_hour'] ?? null) ? 'روزانه ساعت ' . View::n((int) $sch['backup_hour']) . ' UTC' : (!empty($d['enabled']) ? '' : 'پشتیبان‌گیری خودکار خاموش است'))
            . View::kpi('check', ($d['last_verify']['ok'] ?? null) === false ? 'bad' : 'violet', 'آخرین آزمون بازیابی', self::run($d['last_verify'] ?? null),
                !empty($ver['enabled']) ? 'هفتگی، ' . View::e($days[(int) ($ver['weekday'] ?? 6)] ?? '') . ' ساعت ' . View::n((int) ($ver['hour'] ?? 4)) . ' UTC'
                    . (!empty($ver['scratch_db']) ? ' · پایگاه دادهٔ آزمایشی دارد (کامل)' : ' · بدون پایگاه دادهٔ آزمایشی (جزئی)') : 'آزمون هفتگی خاموش است')
            . '</div>';
        $acts = View::postButton(['page' => 'backups'], 'ops_backup_run', [], 'پشتیبان‌گیری اکنون', 'pcdna-btn pcdna-btn-sm pcdna-btn-primary', '', 'download')
            . View::postButton(['page' => 'backups'], 'ops_backup_verify', [], 'آزمون بازیابی اکنون', 'pcdna-btn pcdna-btn-sm', '', 'check');
        $runs = self::items($d['runs'] ?? [], ['runs']);
        if (!$runs) {
            $t = View::emptyState('هنوز اجرایی ثبت نشده است', 'پس از اولین پشتیبان‌گیری یا آزمون بازیابی، تاریخچه اینجا نمایش داده می‌شود.', 'history');
        } else {
            $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-backup-runs"><thead><tr><th>نوع</th><th>زمان</th><th>نتیجه</th><th>نام / حجم</th><th>محل</th><th>بررسی‌ها</th></tr></thead><tbody>';
            foreach (array_slice($runs, 0, 30) as $x) {
                $checks = '';
                foreach ((array) ($x['checks'] ?? []) as $k => $v) {
                    $checks .= '<span class="pcdna-gate ' . ($v ? 'is-ok' : 'is-bad') . '">' . ($v ? '✓' : '✗') . ' ' . View::e((string) $k) . '</span>';
                }
                $t .= '<tr data-run="' . (int) ($x['id'] ?? 0) . '" data-kind="' . View::e((string) ($x['kind'] ?? '')) . '"><td>' . (($x['kind'] ?? '') === 'verify' ? 'آزمون بازیابی' : 'پشتیبان') . '</td><td>'
                    . View::e(View::date($x['started_at'] ?? null, true)) . '</td><td>' . self::run($x) . '</td><td>' . (!empty($x['name']) ? View::ltr((string) $x['name']) : '—')
                    . '<div class="pcdna-small pcdna-muted">' . self::size($x['size'] ?? null) . '</div></td><td>' . View::e(['local' => 'محلی', 's3' => 'S3', 'both' => 'محلی + S3'][$x['location'] ?? ''] ?? '—')
                    . '</td><td><div class="pcdna-gates">' . ($checks ?: '—') . '</div></td></tr>';
            }
            $t .= '</tbody></table></div>';
        }
        $h .= View::card('اجراها', $t, $acts, 'pcdna-flush', 'history');
        $h .= View::card('نکته‌ها', '<ul class="pcdna-bullets"><li>«کامل» یعنی نسخه واقعاً در یک پایگاه دادهٔ جدا بازیابی و تعداد ردیف‌ها و رمزگشایی یک مقدار بررسی شده است؛ «جزئی» فقط فهرست و مانیفست را بررسی می‌کند.</li>'
            . '<li>کلید رمزنگاری پشتیبان باید با DATA_ENCRYPTION_KEY فرق داشته باشد و جای دیگری نگه داشته شود.</li>'
            . '<li>پس از هر بارگذاری در S3، اندازه و sha256 نسخه دوباره خوانده و مقایسه می‌شود.</li></ul>', '', '', 'info');
        return $h;
    }

    // ------------------------------------------------------------------ abuse desk (§23.10)

    private static function abuse(array $get): string
    {
        $id = (int) ($get['id'] ?? 0);
        if ($id > 0) {
            return self::abuseDetail($id);
        }
        $f = ['status' => array_key_exists((string) ($get['status'] ?? ''), self::ABUSE_STATUS) ? (string) $get['status'] : '',
            'category' => array_key_exists((string) ($get['category'] ?? ''), self::ABUSE_CATEGORY) ? (string) $get['category'] : '',
            'q' => View::clip(Env::input($get['q'] ?? ''), 100)];
        $path = '/api/v1/abuse/reports?' . http_build_query(array_filter($f + ['limit' => 100], function ($v) {
            return $v !== '' && $v !== null;
        }));
        $r = Pages::fetch([$path]);
        $res = $r[$path];
        if (($res['code'] ?? 0) === 404) {
            return self::unavailable('میز رسیدگی به تخلف') . '<p class="pcdna-small pcdna-muted">روی کنترلر <code dir="ltr">ABUSE_ENABLED=true</code> را تنظیم کنید.</p>';
        }
        $form = '<form method="get" action="addonmodules.php" class="pcdna-filters"><input type="hidden" name="module" value="' . View::e(Env::MODULE) . '"><input type="hidden" name="page" value="abuse">'
            . '<label><span>وضعیت</span>' . View::select('status', ['' => 'همه'] + array_map(function ($x) {
                return $x[0];
            }, self::ABUSE_STATUS), $f['status']) . '</label>'
            . '<label><span>دسته</span>' . View::select('category', ['' => 'همه'] + self::ABUSE_CATEGORY, $f['category']) . '</label>'
            . '<label><span>جست‌وجو (شناسه یا میزبان)</span><input class="pcdna-input" name="q" dir="ltr" value="' . View::e($f['q']) . '"></label>'
            . '<button type="submit" class="pcdna-btn">' . View::icon('search') . '<span>فیلتر</span></button></form>';
        if (!Pages::ok($res)) {
            return $form . View::alert('bad', 'فهرست گزارش‌ها دریافت نشد: ' . View::e((string) $res['error']));
        }
        $list = self::items($res['data'], ['reports', 'items']);
        if (!$list) {
            $t = View::emptyState('گزارشی نیست', 'گزارش‌های تخلف از صفحهٔ عمومی «گزارش تخلف» اینجا می‌آیند.', 'shield');
        } else {
            $t = '<div class="pcdna-table-wrap"><table class="pcdna-table pcdna-abuse"><thead><tr><th>شناسه</th><th>دسته</th><th>میزبان</th><th>وضعیت</th><th>عمر</th><th>مهلت</th></tr></thead><tbody>';
            foreach ($list as $x) {
                $rid = (int) ($x['id'] ?? 0);
                $host = self::hostOf($x);
                $over = !empty($x['deadline_at']) && strtotime((string) $x['deadline_at']) < time() && ($x['status'] ?? '') === 'notified';
                $t .= '<tr data-abuse="' . $rid . '"' . ($over ? ' class="is-bad"' : '') . '><td><a href="' . View::url(['page' => 'abuse', 'id' => $rid]) . '">' . View::ltr((string) ($x['ticket'] ?? '#' . $rid)) . '</a></td><td>'
                    . View::e(self::ABUSE_CATEGORY[$x['category'] ?? ''] ?? (string) ($x['category'] ?? '')) . '</td><td>' . ($host !== '' ? View::ltr($host) : '—') . '</td><td>' . self::badge(self::ABUSE_STATUS, $x['status'] ?? '')
                    . '</td><td>' . View::e(View::ago($x['created_at'] ?? null)) . '</td><td>' . (!empty($x['deadline_at']) ? View::e(View::date($x['deadline_at'], true)) . ($over ? ' ' . View::badge('گذشته', 'bad') : '') : '—') . '</td></tr>';
            }
            $t .= '</tbody></table></div>';
        }
        $pub = Env::enabled('abuse_page', false) ? '<p class="pcdna-small">صفحهٔ عمومی گزارش: <code dir="ltr">index.php?m=pasargadcdn_admin&amp;page=abuse</code></p>'
            : '<p class="pcdna-small pcdna-muted">صفحهٔ عمومی «گزارش تخلف» در تنظیمات افزونه خاموش است.</p>';
        return $form . View::card('صف گزارش‌ها (' . View::n(count($list)) . ')', $t . $pub, '', 'pcdna-flush', 'shield');
    }

    private static function hostOf(array $x): string
    {
        if (is_string($x['host'] ?? null)) {
            return (string) $x['host'];
        }
        foreach ((array) ($x['urls'] ?? []) as $u) {
            $h = is_string($u) ? (string) parse_url($u, PHP_URL_HOST) : '';
            if ($h !== '') {
                return strtolower($h);
            }
        }
        return '';
    }

    /** Evidence URLs as text links that the panel never fetches or previews. */
    private static function evidence(array $urls): string
    {
        $h = '<ul class="pcdna-evidence">';
        foreach (array_slice($urls, 0, 10) as $u) {
            if (!is_string($u)) {
                continue;
            }
            $ok = preg_match('#^https?://#i', $u) === 1;
            $h .= '<li>' . ($ok ? '<a href="' . View::e($u) . '" rel="noopener noreferrer nofollow" referrerpolicy="no-referrer" target="_blank" dir="ltr">' . View::e(View::clip($u, 300)) . '</a>'
                : '<code dir="ltr">' . View::e(View::clip($u, 300)) . '</code>') . '</li>';
        }
        return $h . '</ul>';
    }

    private static function abuseDetail(int $id): string
    {
        $back = '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::url(['page' => 'abuse']) . '">' . View::icon('shield') . '<span>بازگشت به صف</span></a>';
        [$c, $x] = self::call('GET', '/api/v1/abuse/reports/' . $id);
        if ($c === 404) {
            return $back . View::alert('bad', 'گزارش پیدا نشد.');
        }
        if ($c !== 200 || !is_array($x)) {
            return $back . View::alert('bad', 'گزارش دریافت نشد: ' . View::e(self::err($c, $x)));
        }
        $q = ['page' => 'abuse', 'id' => $id];
        $site = $x['site'] ?? null;
        $domain = is_array($site) ? (string) ($site['domain'] ?? '') : (is_string($site) ? $site : '');
        // the controller answers flat site_* fields (site = domain); an object {domain, external_id, client_id} is read too
        $domain = $domain !== '' ? $domain : (string) ($x['site_domain'] ?? '');
        $ext = is_array($site) ? ($site['external_id'] ?? null) : ($x['site_external_id'] ?? $x['external_id'] ?? null);
        $cid = is_array($site) ? ($site['client_id'] ?? null) : ($x['site_client_id'] ?? $x['client_id'] ?? null);
        $susp = !empty($x['site_abuse_suspended']) || (is_array($site) && !empty($site['abuse_suspended']));
        $svcLink = '';
        if (is_scalar($ext) && ctype_digit((string) $ext) && (int) $ext > 0) {
            $svc = Capsule::table('tblhosting')->where('id', (int) $ext)->first(['id', 'userid']);
            if ($svc) {
                $svcLink = ' <a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::e(Data::serviceUrl((int) $svc->userid, (int) $svc->id)) . '">سرویس #' . (int) $svc->id . '</a>'
                    . ' <a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::e(Data::clientUrl((int) $svc->userid)) . '">مشتری #' . (int) $svc->userid . '</a>';
            }
        } elseif (is_scalar($cid) && ctype_digit((string) $cid) && (int) $cid > 0) {
            $svcLink = ' <a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::e(Data::clientUrl((int) $cid)) . '">مشتری #' . (int) $cid . '</a>';
        }
        $dl = '<dl class="pcdna-dl pcdna-dl-cols" data-abuse-detail="' . $id . '">'
            . '<div><dt>شناسه</dt><dd>' . View::ltr((string) ($x['ticket'] ?? '')) . '</dd></div>'
            . '<div><dt>دسته</dt><dd>' . View::e(self::ABUSE_CATEGORY[$x['category'] ?? ''] ?? (string) ($x['category'] ?? '')) . '</dd></div>'
            . '<div><dt>وضعیت</dt><dd>' . self::badge(self::ABUSE_STATUS, $x['status'] ?? '') . '</dd></div>'
            . '<div><dt>اقدام</dt><dd>' . View::e(['none' => 'هیچ', 'warned' => 'هشدار داده شد', 'suspended' => 'معلق شد', 'unsuspended' => 'تعلیق برداشته شد'][$x['action'] ?? 'none'] ?? (string) ($x['action'] ?? '')) . '</dd></div>'
            . '<div><dt>ثبت</dt><dd>' . View::e(View::date($x['created_at'] ?? null, true)) . '</dd></div>'
            . '<div><dt>مهلت</dt><dd>' . View::e(View::date($x['deadline_at'] ?? null, true)) . '</dd></div>'
            . '<div><dt>سایت</dt><dd>' . ($domain !== '' ? View::ltr($domain) . ($susp ? ' ' . View::badge('معلق به‌دلیل تخلف', 'bad', ' data-abuse-suspended="1"') : '') . $svcLink
                : '<span class="pcdna-muted">پیدا نشد</span>') . '</dd></div>'
            . '<div><dt>ایمیل گزارش‌دهنده</dt><dd>' . (!empty($x['reporter_email']) ? View::ltr((string) $x['reporter_email']) : '—') . '</dd></div></dl>'
            . '<h4>نشانی‌ها (فقط متن؛ پنل آن‌ها را باز نمی‌کند)</h4>' . self::evidence((array) ($x['urls'] ?? []))
            . '<h4>توضیح گزارش‌دهنده</h4><p class="pcdna-pre" dir="auto">' . View::e(View::clip((string) ($x['description'] ?? ''), 4000)) . '</p>'
            . (!empty($x['public_note']) ? '<h4>یادداشت عمومی (برای گزارش‌دهنده)</h4><p dir="auto">' . View::e((string) $x['public_note']) . '</p>' : '');
        // actions
        $acts = '';
        foreach (self::ABUSE_ACTIONS as $a => [$label, $confirm]) {
            $acts .= View::postButton($q, 'ops_abuse_action', ['id' => $id, 'act' => $a], $label,
                'pcdna-btn pcdna-btn-sm' . ($a === 'suspend' ? ' pcdna-btn-danger' : ''), $confirm, ['warn' => 'warn', 'suspend' => 'power', 'unsuspend' => 'refresh', 'close' => 'check', 'reject' => 'x'][$a]);
        }
        $notify = '<form method="post" action="' . View::url($q) . '" class="pcdna-form" data-confirm="ایمیل اطلاع‌رسانی تخلف برای مالک سایت فرستاده شود؟">' . View::csrf()
            . '<input type="hidden" name="a" value="ops_abuse_notify"><input type="hidden" name="id" value="' . $id . '"><div class="pcdna-form-grid">'
            . '<label><span>مهلت (ساعت، ۱ تا ۷۲۰)</span><input class="pcdna-input" name="deadline_hours" dir="ltr" inputmode="numeric" value="48"></label>'
            . '<label><span>زبان ایمیل</span>' . View::select('lang', ['fa' => 'فارسی', 'en' => 'انگلیسی'], 'fa') . '</label>'
            . '<label class="pcdna-span-2"><span>پیام اضافه (اختیاری؛ هویت گزارش‌دهنده هرگز فرستاده نمی‌شود)</span><textarea class="pcdna-input" name="message" rows="3" maxlength="2000"></textarea></label>'
            . '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('mail') . '<span>اطلاع به مالک</span></button></div></form>';
        $patch = '<form method="post" action="' . View::url($q) . '" class="pcdna-form">' . View::csrf()
            . '<input type="hidden" name="a" value="ops_abuse_patch"><input type="hidden" name="id" value="' . $id . '"><div class="pcdna-form-grid">'
            . '<label><span>وضعیت</span>' . View::select('status', ['' => '— بدون تغییر —'] + array_map(function ($v) {
                return $v[0];
            }, self::ABUSE_STATUS), '') . '</label>'
            . '<label><span>سایت مرتبط (دامنه)</span><input class="pcdna-input" name="site" dir="ltr" maxlength="253" placeholder="example.com" value=""></label>'
            . '<label class="pcdna-span-2"><span>یادداشت عمومی (به گزارش‌دهنده نمایش داده می‌شود، حداکثر ۵۰۰)</span><input class="pcdna-input" name="public_note" maxlength="500" value=""></label>'
            . '<label class="pcdna-span-2"><span>یادداشت داخلی (فقط مدیران)</span><textarea class="pcdna-input" name="note" rows="2" maxlength="2000"></textarea></label>'
            . '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn">' . View::icon('check') . '<span>ذخیره</span></button></div></form>';
        // timeline
        $events = self::items($x['events'] ?? []);
        $tl = '<ol class="pcdna-timeline">';
        foreach ($events as $e) {
            $data = $e['data'] ?? null;
            $txt = is_array($data) ? (string) ($data['note'] ?? $data['text'] ?? $data['action'] ?? $data['status'] ?? '') : (is_string($data) ? $data : '');
            $tl .= '<li data-abuse-event="' . View::e((string) ($e['kind'] ?? '')) . '"><strong>' . View::e(self::ABUSE_EVENT[$e['kind'] ?? ''] ?? (string) ($e['kind'] ?? '')) . '</strong> · '
                . View::e(View::date($e['at'] ?? null, true)) . (!empty($e['actor']) ? ' · ' . View::ltr((string) $e['actor']) : '')
                . ($txt !== '' ? '<div dir="auto">' . View::e(View::clip($txt, 2000)) . '</div>' : '') . '</li>';
        }
        $tl .= $events ? '</ol>' : '</ol><p class="pcdna-muted">رویدادی ثبت نشده است.</p>';
        return '<div class="pcdna-detail-head">' . $back . '<h2 class="pcdna-detail-title">گزارش تخلف ' . View::ltr((string) ($x['ticket'] ?? '#' . $id)) . '</h2></div>'
            . View::card('جزئیات', $dl, $acts, '', 'shield')
            . '<div class="pcdna-grid-2">' . View::card('اطلاع به مالک سایت', $notify, '', '', 'mail') . View::card('وضعیت و یادداشت', $patch, '', '', 'sliders') . '</div>'
            . View::card('تاریخچه', $tl, '', '', 'history');
    }

    // ------------------------------------------------------------------ SLO (§23.11)

    private static function months(): array
    {
        $out = [];
        $t = strtotime(gmdate('Y-m-01'));
        for ($i = 0; $i < 12; $i++) {
            $m = gmdate('Y-m', strtotime('-' . $i . ' month', $t));
            $out[$m] = View::digits($m);
        }
        return $out;
    }

    private static function slo(array $get): string
    {
        $months = self::months();
        $month = is_string($get['month'] ?? null) && isset($months[$get['month']]) ? $get['month'] : gmdate('Y-m');
        $path = '/api/v1/slo?month=' . $month;
        $r = Pages::fetch([$path]);
        $res = $r[$path];
        if (($res['code'] ?? 0) === 404) {
            return self::unavailable('داشبورد SLO');
        }
        $form = '<form method="get" action="addonmodules.php" class="pcdna-filters"><input type="hidden" name="module" value="' . View::e(Env::MODULE) . '"><input type="hidden" name="page" value="slo">'
            . '<label><span>ماه (UTC)</span>' . View::select('month', $months, $month) . '</label><button type="submit" class="pcdna-btn">نمایش</button></form>';
        if (!Pages::ok($res)) {
            return $form . View::alert('bad', 'داده‌های SLO دریافت نشد: ' . View::e((string) $res['error']));
        }
        $groups = self::items($res['data']['groups'] ?? []);
        if (!$groups) {
            return $form . View::emptyState('هنوز داده‌ای نیست', 'پس از چند دقیقه پروب نودها، شاخص‌ها محاسبه می‌شوند.', 'activity');
        }
        $h = $form;
        foreach ($groups as $g) {
            $name = (string) ($g['group'] ?? '');
            $slis = is_array($g['slis'] ?? null) ? $g['slis'] : [];
            $cards = '<div class="pcdna-slo-grid">';
            foreach (self::SLI as $k => $label) {
                $s = is_array($slis[$k] ?? null) ? $slis[$k] : null;
                if (!$s) {
                    continue;
                }
                $obj = (float) ($s['objective'] ?? 0);
                $act = is_numeric($s['actual'] ?? null) ? (float) $s['actual'] : null;
                $budget = is_numeric($s['budget_remaining_pct'] ?? null) ? (float) $s['budget_remaining_pct'] : null;
                $tone = $act === null ? 'muted' : ($act >= $obj ? 'ok' : 'bad');
                $burn = '';
                foreach (['5m', '30m', '1h', '6h'] as $w) {
                    $v = $s['burn'][$w] ?? null;
                    $burn .= '<span class="pcdna-gate' . (is_numeric($v) && $v >= 14.4 ? ' is-bad' : (is_numeric($v) && $v >= 6 ? ' is-warn' : '')) . '" title="نرخ مصرف بودجه در ' . $w . '">'
                        . View::e($w) . ' ' . (is_numeric($v) ? View::n((float) $v, 1) . '×' : '—') . '</span>';
                }
                $alert = is_string($s['alert'] ?? null) && isset(self::SLO_ALERT[$s['alert']]) ? View::badge(self::SLO_ALERT[$s['alert']][0], self::SLO_ALERT[$s['alert']][1], ' data-slo-alert="' . View::e($s['alert']) . '"') : View::badge('بدون هشدار', 'ok');
                $cards .= '<div class="pcdna-slo-card" data-sli="' . $k . '"><div class="pcdna-slo-head"><strong>' . View::e($label) . '</strong>' . $alert . '</div>'
                    . '<div class="pcdna-slo-val"><span class="pcdna-t-' . $tone . '">' . ($act === null ? '—' : View::n($act, 3) . '٪') . '</span> <small>هدف ' . View::n($obj, 2) . '٪</small></div>'
                    . '<div class="pcdna-small">بودجهٔ خطای باقی‌مانده: ' . ($budget === null ? '—' : View::n($budget, 1) . '٪') . '</div>'
                    . View::meter($budget === null ? 0 : max(0, min(100, $budget)) / 100, $budget !== null && $budget < 25 ? 'bad' : ($budget !== null && $budget < 50 ? 'warn' : 'ok'))
                    . '<div class="pcdna-gates">' . $burn . '</div>'
                    . '<div class="pcdna-small pcdna-muted">' . View::n((int) ($s['good'] ?? 0)) . ' خوب از ' . View::n((int) ($s['total'] ?? 0)) . '</div></div>';
            }
            $cards .= '</div>';
            $ea = is_numeric($g['edge_availability'] ?? null) ? '<p class="pcdna-small">در دسترس‌بودن تک‌تک نودها (اطلاعاتی): ' . View::n((float) $g['edge_availability'], 3) . '٪</p>' : '';
            $h .= '<div data-slo-group="' . View::e($name) . '">' . View::card('گروه ' . $name, $cards . $ea . self::sloChart((array) ($g['daily'] ?? []), $slis), '', '', 'activity') . '</div>';
        }
        $h .= View::card('تعریف‌ها', '<ul class="pcdna-bullets"><li><strong>در دسترس‌بودن:</strong> سهم پروب‌هایی که در هر منطقهٔ گروه دست‌کم یک نود سالم پاسخ داد.</li>'
            . '<li><strong>تأخیر:</strong> سهم پروب‌های موفق زیر آستانهٔ تأخیر.</li><li><strong>خطاهای سکو:</strong> ۱ − خطاهای خود سکو ÷ همهٔ درخواست‌ها (خطای سرور مشتری حساب نمی‌شود).</li>'
            . '<li>هشدار «مصرف سریع» یعنی نرخ مصرف بودجه در ۱ ساعت و ۵ دقیقهٔ اخیر بیش از ۱۴٫۴ برابر؛ «مصرف کند» یعنی ۶ برابر در ۶ ساعت و ۳۰ دقیقه.</li></ul>', '', '', 'info');
        return $h;
    }

    /** Daily chart: one polyline per SLI over the month, y = [min(objective) − 1, 100]. */
    private static function sloChart(array $daily, array $slis): string
    {
        $days = array_values(array_filter($daily, 'is_array'));
        if (count($days) < 2) {
            return '';
        }
        $lo = 100.0;
        foreach (self::SLI as $k => $l) {
            if (is_numeric($slis[$k]['objective'] ?? null)) {
                $lo = min($lo, (float) $slis[$k]['objective']);
            }
            foreach ($days as $d) {
                if (is_numeric($d[$k] ?? null)) {
                    $lo = min($lo, (float) $d[$k]);
                }
            }
        }
        $lo = max(0, floor($lo - 0.5));
        $W = 600;
        $H = 140;
        $n = count($days);
        $colors = ['availability' => 'var(--pcdna-brand, #1d5fd6)', 'latency' => '#7c3aed', 'errors' => '#0d9488'];
        $svg = '<svg class="pcdna-slo-chart" viewBox="0 0 ' . $W . ' ' . ($H + 20) . '" role="img" aria-label="نمودار روزانهٔ شاخص‌ها" preserveAspectRatio="none">';
        foreach ([$lo, ($lo + 100) / 2, 100] as $y) {
            $yy = $H - ($y - $lo) / max(0.001, 100 - $lo) * $H;
            $svg .= '<line x1="0" x2="' . $W . '" y1="' . round($yy, 1) . '" y2="' . round($yy, 1) . '" stroke="currentColor" stroke-opacity=".12"/>'
                . '<text x="2" y="' . round(max(10, $yy - 2), 1) . '" font-size="10" fill="currentColor" fill-opacity=".6">' . View::e(View::n($y, 1)) . '٪</text>';
        }
        foreach ($colors as $k => $c) {
            $pts = [];
            foreach ($days as $i => $d) {
                if (is_numeric($d[$k] ?? null)) {
                    $pts[] = round($i * $W / ($n - 1), 1) . ',' . round($H - (((float) $d[$k]) - $lo) / max(0.001, 100 - $lo) * $H, 1);
                }
            }
            if ($pts) {
                $svg .= '<polyline fill="none" stroke="' . $c . '" stroke-width="2" points="' . implode(' ', $pts) . '"><title>' . View::e(self::SLI[$k]) . '</title></polyline>';
            }
        }
        $svg .= '</svg><div class="pcdna-legend">';
        foreach ($colors as $k => $c) {
            $svg .= '<span><i style="background:' . $c . '"></i>' . View::e(self::SLI[$k]) . '</span>';
        }
        return '<div class="pcdna-slo-daily" data-slo-chart="1">' . $svg . '</div></div>';
    }

    // ------------------------------------------------------------------ provisioning (§23.9)

    private static function provisioning(array $state): string
    {
        $r = Pages::fetch(['/api/v1/provisioning/proposals']);
        $res = $r['/api/v1/provisioning/proposals'];
        if (($res['code'] ?? 0) === 404) {
            return self::unavailable('افزودن نود بر اساس ظرفیت') . '<p class="pcdna-small pcdna-muted">روی کنترلر <code dir="ltr">PROVISIONING_ENABLED=true</code> و برای اجراکننده <code dir="ltr">PROVISIONER_TOKEN</code> را تنظیم کنید.</p>';
        }
        if (!Pages::ok($res)) {
            return View::alert('bad', 'پیشنهادها دریافت نشد: ' . View::e((string) $res['error']));
        }
        $list = self::items($res['data'], ['proposals', 'items']);
        $h = View::alert('info', 'هیچ نودی بدون دو تأیید شما ساخته نمی‌شود: یک بار برای پیشنهاد و یک بار برای اجرای طرح Terraform. اندازه فقط از ظرفیت (صدک ۹۵ مصرف در برابر ظرفیت گروه) محاسبه می‌شود؛ کنترلر هیچ کلید ابری ندارد.');
        if (!$list) {
            $h .= View::emptyState('پیشنهادی نیست', 'وقتی ظرفیت یک گروه کم شود، پیشنهاد افزودن نود اینجا می‌آید؛ می‌توانید دستی هم پیشنهاد بسازید.', 'server');
        }
        foreach ($list as $p) {
            $h .= self::proposalCard($p);
        }
        $form = '<form method="post" action="' . View::url(['page' => 'provisioning']) . '" class="pcdna-form">' . View::csrf()
            . '<input type="hidden" name="a" value="ops_prov_create"><div class="pcdna-form-grid">'
            . '<label><span>گروه</span>' . View::select('group', ['general' => 'عمومی (سایت‌ها)', 'tunnel' => 'تونل (VPN)'], 'general') . '</label>'
            . '<label><span>منطقه</span>' . View::select('region', ['home' => 'ایران (home)', 'global' => 'خارج (global)'], 'home') . '</label>'
            . '<label><span>اندازه</span>' . View::select('size', self::SIZES, 'medium') . '</label>'
            . '<label><span>تعداد (۱ تا ۲۰)</span><input class="pcdna-input" name="count" dir="ltr" inputmode="numeric" value="1"></label>'
            . '</div><div class="pcdna-form-actions"><button type="submit" class="pcdna-btn">' . View::icon('plus') . '<span>ثبت پیشنهاد دستی</span></button></div></form>';
        $h .= View::card('پیشنهاد دستی', $form, '', '', 'plus');
        return $h;
    }

    private static function proposalCard(array $p): string
    {
        $id = (int) ($p['id'] ?? 0);
        $st = (string) ($p['state'] ?? '');
        $q = ['page' => 'provisioning'];
        $plan = is_array($p['plan'] ?? null) ? $p['plan'] : null;
        $body = '<dl class="pcdna-dl pcdna-dl-cols"><div><dt>گروه</dt><dd>' . View::e((string) ($p['group'] ?? '')) . '</dd></div>'
            . '<div><dt>منطقه</dt><dd>' . View::e((string) ($p['region'] ?? '')) . '</dd></div>'
            . '<div><dt>اندازه</dt><dd>' . View::e(self::SIZES[$p['size'] ?? ''] ?? (string) ($p['size'] ?? '')) . '</dd></div>'
            . '<div><dt>تعداد</dt><dd>' . View::n((int) ($p['count'] ?? 0)) . '</dd></div>'
            . '<div><dt>وضعیت</dt><dd>' . self::badge(self::PROV_STATE, $st) . '</dd></div>'
            . '<div><dt>ایجاد</dt><dd>' . View::e(View::date($p['created_at'] ?? null, true)) . '</dd></div></dl>'
            . (!empty($p['reason']) ? '<p class="pcdna-small" dir="auto"><strong>دلیل:</strong> ' . View::e(View::clip((string) $p['reason'], 400)) . '</p>' : '')
            . (!empty($p['error']) ? View::alert('bad', View::e(View::clip((string) $p['error'], 400))) : '');
        $acts = '';
        if ($st === 'proposed') {
            $body .= '<form method="post" action="' . View::url($q) . '" class="pcdna-form pcdna-form-inline" data-prov-approve="' . $id . '" data-confirm="پیشنهاد تأیید شود؟ ردیف نودها و توکن‌های یک‌بارمصرف پیوستن ساخته می‌شود.">' . View::csrf()
                . '<input type="hidden" name="a" value="ops_prov_approve"><input type="hidden" name="id" value="' . $id . '">'
                . '<label class="pcdna-inline-label"><span>منطقه</span>' . View::select('region', ['home' => 'home', 'global' => 'global'], (string) ($p['region'] ?? 'home')) . '</label>'
                . '<label class="pcdna-inline-label"><span>اندازه</span>' . View::select('size', self::SIZES, (string) ($p['size'] ?? 'medium')) . '</label>'
                . '<label class="pcdna-inline-label"><span>تعداد</span><input class="pcdna-input pcdna-input-sm" name="count" dir="ltr" inputmode="numeric" value="' . (int) ($p['count'] ?? 1) . '"></label>'
                . '<button type="submit" class="pcdna-btn pcdna-btn-primary">' . View::icon('check') . '<span>تأیید</span></button></form>';
        }
        if ($plan) {
            $destroys = (int) ($plan['destroys'] ?? 0);
            $body .= '<h4>طرح Terraform <span class="pcdna-muted pcdna-small">(' . View::e(View::date($plan['uploaded_at'] ?? null, true)) . ')</span></h4>'
                . '<p class="pcdna-gates" data-plan-counts="1"><span class="pcdna-gate is-ok">+ ' . View::n((int) ($plan['adds'] ?? 0)) . ' افزودن</span>'
                . '<span class="pcdna-gate is-warn">~ ' . View::n((int) ($plan['changes'] ?? 0)) . ' تغییر</span><span class="pcdna-gate' . ($destroys > 0 ? ' is-bad' : '') . '">− ' . View::n($destroys) . ' حذف</span></p>'
                . '<pre class="pcdna-plan" dir="ltr" data-plan-summary="1">' . View::e(View::clip((string) ($plan['summary'] ?? ''), 65536)) . '</pre>';
            if ($st === 'planned') {
                $body .= $destroys > 0 ? View::alert('bad', 'این طرح چیزی را حذف می‌کند و اجرا نمی‌شود؛ پیشنهاد را رد کنید و پیکربندی Terraform را بررسی کنید.')
                    . '<button type="button" class="pcdna-btn pcdna-btn-primary" disabled data-prov-apply="' . $id . '">' . View::icon('zap') . '<span>اجرای طرح</span></button>'
                    : View::postButton($q, 'ops_prov_apply', ['id' => $id], 'اجرای طرح', 'pcdna-btn pcdna-btn-primary', 'طرح Terraform اجرا شود؟ سرورهای جدید ساخته می‌شوند و هزینه دارند.', 'zap');
            }
        }
        $edges = self::items($p['edges'] ?? []);
        if ($edges) {
            $joined = count(array_filter($edges, function ($e) {
                return !empty($e['joined']);
            }));
            $body .= '<h4>پیوستن نودها (' . View::n($joined) . ' از ' . View::n(count($edges)) . ')</h4><ul class="pcdna-join">';
            foreach ($edges as $e) {
                $body .= '<li data-join-edge="' . (int) ($e['id'] ?? 0) . '">' . (!empty($e['joined']) ? View::badge('پیوست', 'ok') : View::badge('در انتظار', 'muted')) . ' ' . View::ltr((string) ($e['name'] ?? '')) . '</li>';
            }
            $body .= '</ul>';
        }
        if (in_array($st, ['proposed', 'approved', 'planned'], true)) {
            $acts .= View::postButton($q, 'ops_prov_reject', ['id' => $id], 'رد', 'pcdna-btn pcdna-btn-sm pcdna-btn-danger', 'پیشنهاد #' . $id . ' رد شود؟', 'x');
        }
        return '<div data-proposal="' . $id . '" data-proposal-state="' . View::e($st) . '">' . View::card('پیشنهاد #' . $id, $body, $acts, '', 'server') . '</div>';
    }

    // ------------------------------------------------------------------ site diagnostics, admin audience (§23.8)

    public static function siteDiag(int $sid): string
    {
        $back = '<a class="pcdna-btn pcdna-btn-sm pcdna-btn-ghost" href="' . View::url(['page' => 'sites']) . '">' . View::icon('globe') . '<span>بازگشت به سایت‌ها</span></a>';
        $svc = $sid > 0 ? Data::serviceQuery()->where('h.id', $sid)->first(['h.id', 'h.userid', 'h.domain', 'h.server']) : null;
        if (!$svc) {
            return $back . View::alert('bad', 'سرویس CDN پیدا نشد.');
        }
        $domain = Env::domain((string) $svc->domain);
        if (!Env::validHostname($domain)) {
            return $back . View::alert('bad', 'دامنهٔ سرویس معتبر نیست.');
        }
        $server = Capsule::table('tblservers')->where('id', (int) $svc->server)->first();
        try {
            [$c, $data] = Env::api(10, $server && $server->type === 'pasargadcdn' ? $server : null)->raw('GET', ApiClient::site($domain) . '/diagnostics?audience=admin');
        } catch (\Throwable $e) {
            return $back . View::alert('bad', 'کنترلر در دسترس نیست: ' . View::e($e->getMessage()));
        }
        if ($c === 404) {
            return $back . self::unavailable('گزارش عیب‌یابی');
        }
        if ($c !== 200 || !is_array($data)) {
            return $back . View::alert('bad', 'گزارش دریافت نشد: ' . View::e(self::err($c, $data)));
        }
        Env::log('diagnostics report (admin audience) of ' . $domain . ' viewed by admin #' . Env::adminId(), (int) $svc->userid);
        $json = (string) json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        $file = 'pcdn-diagnostics-' . preg_replace('/[^a-z0-9_]/', '', (string) ($data['report_id'] ?? 'report')) . '.json';
        $internal = is_array($data['internal'] ?? null) ? $data['internal'] : [];
        $nodes = '';
        foreach (self::items($internal['edges_serving'] ?? []) as $e) {
            $nodes .= '<li>' . View::ltr((string) ($e['name'] ?? '')) . ' — ' . View::e((string) ($e['group'] ?? '')) . '/' . View::e((string) ($e['region'] ?? ''))
                . ' ' . (!empty($e['online']) ? View::badge('آنلاین', 'ok') : View::badge('آفلاین', 'bad')) . (!empty($e['release']) ? ' ' . View::ltr((string) $e['release']) : '') . '</li>';
        }
        $acts = '<button type="button" class="pcdna-btn pcdna-btn-sm" data-copy="' . View::e($json) . '">' . View::icon('copy') . '<span>کپی</span></button>'
            . '<a class="pcdna-btn pcdna-btn-sm" download="' . View::e($file) . '" href="data:application/json;charset=utf-8;base64,' . base64_encode($json) . '">' . View::icon('download') . '<span>دانلود JSON</span></a>';
        return '<div class="pcdna-detail-head">' . $back . '<h2 class="pcdna-detail-title">گزارش عیب‌یابی ' . View::ltr($domain) . '</h2></div>'
            . ($nodes !== '' ? View::card('نودهای سرویس‌دهنده (فقط مدیر)', '<ul class="pcdna-bullets">' . $nodes . '</ul>', '', '', 'server') : '')
            . View::card('گزارش (نسخهٔ مدیر)', '<pre class="pcdna-plan" dir="ltr" data-diag-json="1">' . View::e($json) . '</pre>', $acts, '', 'info');
    }

    // ------------------------------------------------------------------ actions

    /** @return array [flash list, page state] */
    public static function action(string $action, array $post, int $admin): array
    {
        $id = (int) ($post['id'] ?? 0);
        switch ($action) {
            case 'ops_rollout_preview':
            case 'ops_rollout_create':
                $v = Env::input($post['release'] ?? '');
                if (!preg_match('/^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/D', $v)) {
                    return [[['bad', 'نسخه نامعتبر است.']], []];
                }
                $groups = array_values(array_intersect(['general', 'tunnel'], array_filter((array) ($post['groups'] ?? []), 'is_string')));
                $soak = (int) Env::input($post['soak_minutes'] ?? '30');
                $ring = (int) Env::input($post['ring_percent'] ?? '25');
                if ($soak < 5 || $soak > 1440 || $ring < 1 || $ring > 90) {
                    return [[['bad', 'دورهٔ پایش باید ۵ تا ۱۴۴۰ دقیقه و درصد حلقه ۱ تا ۹۰ باشد.']], []];
                }
                $dry = $action === 'ops_rollout_preview';
                $body = ['release' => $v, 'groups' => $groups ?: null, 'soak_minutes' => $soak, 'ring_percent' => $ring,
                    'auto_rollback' => !empty($post['auto_rollback']), 'allow_no_rollback' => !empty($post['allow_no_rollback']), 'dry_run' => $dry];
                [$c, $d] = self::call('POST', '/api/v1/rollouts', $body);
                if ($c < 200 || $c >= 300 || !is_array($d)) {
                    return [[['bad', View::e(($dry ? 'پیش‌نمایش' : 'شروع انتشار') . ' ناموفق بود: ' . self::err($c, $d))]], []];
                }
                Pages::reset();
                if ($dry) {
                    return [[['ok', 'پیش‌نمایش حلقه‌ها در پایین صفحه آمده است؛ چیزی ذخیره نشد.']], ['preview' => $d + ['release' => $v]]];
                }
                Env::log('rollout #' . (int) ($d['id'] ?? 0) . ' of ' . $v . ' created by admin #' . $admin);
                return [[['ok', 'انتشار ' . View::ltr($v) . ' ساخته شد (#' . View::n((int) ($d['id'] ?? 0)) . ').']], []];
            case 'ops_rollout_act':
                $op = Env::input($post['op'] ?? '');
                if ($id <= 0 || !isset(self::ROLLOUT_OPS[$op])) {
                    return [[['bad', 'عملیات نامعتبر است.']], []];
                }
                [$c, $d] = self::call('POST', '/api/v1/rollouts/' . $id . '/' . $op, []);
                Pages::reset();
                if ($c < 200 || $c >= 300) {
                    return [[['bad', View::e('«' . self::ROLLOUT_OPS[$op] . '» انجام نشد: ' . self::err($c, $d))]], []];
                }
                Env::log('rollout #' . $id . ' ' . $op . ' by admin #' . $admin);
                return [[['ok', View::e('«' . self::ROLLOUT_OPS[$op] . '» برای انتشار #' . $id . ' ثبت شد.')]], []];
            case 'ops_rollout_edge':
                $op = Env::input($post['op'] ?? '');
                $eid = (int) ($post['edge'] ?? 0);
                if ($id <= 0 || $eid <= 0 || !isset(self::EDGE_OPS[$op])) {
                    return [[['bad', 'عملیات نامعتبر است.']], []];
                }
                [$c, $d] = self::call('POST', '/api/v1/rollouts/' . $id . '/edges/' . $eid . '/' . $op, []);
                Pages::reset();
                if ($c < 200 || $c >= 300) {
                    return [[['bad', View::e('«' . self::EDGE_OPS[$op] . '» انجام نشد: ' . self::err($c, $d))]], []];
                }
                Env::log('rollout #' . $id . ' edge #' . $eid . ' ' . $op . ' by admin #' . $admin);
                return [[['ok', View::e('«' . self::EDGE_OPS[$op] . '» برای نود #' . $eid . ' ثبت شد.')]], []];
            case 'ops_backup_run':
            case 'ops_backup_verify':
                $what = $action === 'ops_backup_run' ? 'run' : 'verify';
                [$c, $d] = self::call('POST', '/api/v1/backups/' . $what, []);
                Pages::reset();
                if ($c === 409) {
                    return [[['warn', 'یک ' . ($what === 'run' ? 'پشتیبان‌گیری' : 'آزمون بازیابی') . ' در صف یا در حال اجراست.']], []];
                }
                if ($c < 200 || $c >= 300) {
                    return [[['bad', View::e('درخواست انجام نشد: ' . self::err($c, $d))]], []];
                }
                Env::log('backup ' . $what . ' queued by admin #' . $admin);
                return [[['ok', ($what === 'run' ? 'پشتیبان‌گیری' : 'آزمون بازیابی') . ' در صف قرار گرفت و تا یک دقیقهٔ دیگر شروع می‌شود؛ صفحه را بعداً تازه کنید.']], []];
            case 'ops_abuse_patch':
                $body = [];
                $s = Env::input($post['status'] ?? '');
                if ($s !== '') {
                    if (!isset(self::ABUSE_STATUS[$s])) {
                        return [[['bad', 'وضعیت نامعتبر است.']], []];
                    }
                    $body['status'] = $s;
                }
                $site = strtolower(Env::input($post['site'] ?? ''));
                if ($site !== '') {
                    if (!Env::validHostname($site)) {
                        return [[['bad', 'دامنهٔ سایت نامعتبر است.']], []];
                    }
                    $body['site'] = $site;
                }
                foreach (['public_note' => 500, 'note' => 2000] as $k => $max) {
                    $v = trim((string) ($post[$k] ?? ''));
                    if ($v !== '') {
                        $body[$k] = mb_substr($v, 0, $max);
                    }
                }
                if ($id <= 0 || !$body) {
                    return [[['warn', 'چیزی برای ذخیره نبود.']], []];
                }
                [$c, $d] = self::call('PATCH', '/api/v1/abuse/reports/' . $id, $body);
                if ($c < 200 || $c >= 300) {
                    return [[['bad', View::e('ذخیره انجام نشد: ' . self::err($c, $d))]], []];
                }
                Env::log('abuse report #' . $id . ' updated (' . implode(', ', array_keys($body)) . ') by admin #' . $admin);
                return [[['ok', 'گزارش به‌روز شد.']], []];
            case 'ops_abuse_notify':
                $hrs = (int) Env::input($post['deadline_hours'] ?? '48');
                $lang = Env::input($post['lang'] ?? 'fa') === 'en' ? 'en' : 'fa';
                if ($id <= 0 || $hrs < 1 || $hrs > 720) {
                    return [[['bad', 'مهلت باید ۱ تا ۷۲۰ ساعت باشد.']], []];
                }
                $body = ['deadline_hours' => $hrs, 'lang' => $lang];
                $m = trim((string) ($post['message'] ?? ''));
                if ($m !== '') {
                    $body['message'] = mb_substr($m, 0, 2000);
                }
                [$c, $d] = self::call('POST', '/api/v1/abuse/reports/' . $id . '/notify', $body);
                if ($c < 200 || $c >= 300) {
                    return [[['bad', View::e('اطلاع به مالک انجام نشد: ' . self::err($c, $d))]], []];
                }
                Env::log('abuse report #' . $id . ' owner notified (' . $hrs . ' h, ' . $lang . ') by admin #' . $admin);
                return [[['ok', 'ایمیل اطلاع‌رسانی در صف ارسال قرار گرفت (با کران بعدی فرستاده می‌شود) و مهلت ' . View::n($hrs) . ' ساعت ثبت شد.']], []];
            case 'ops_abuse_action':
                $a = Env::input($post['act'] ?? '');
                if ($id <= 0 || !isset(self::ABUSE_ACTIONS[$a])) {
                    return [[['bad', 'عملیات نامعتبر است.']], []];
                }
                $body = ['action' => $a];
                $pn = trim((string) ($post['public_note'] ?? ''));
                if ($pn !== '') {
                    $body['public_note'] = mb_substr($pn, 0, 500);
                }
                [$c, $d] = self::call('POST', '/api/v1/abuse/reports/' . $id . '/action', $body);
                Pages::reset();
                if ($c < 200 || $c >= 300) {
                    return [[['bad', View::e('«' . self::ABUSE_ACTIONS[$a][0] . '» انجام نشد: ' . self::err($c, $d))]], []];
                }
                Env::log('abuse report #' . $id . ' action ' . $a . ' by admin #' . $admin);
                return [[['ok', View::e('«' . self::ABUSE_ACTIONS[$a][0] . '» انجام شد.')]], []];
            case 'ops_prov_approve':
                $body = [];
                $reg = Env::input($post['region'] ?? '');
                $size = Env::input($post['size'] ?? '');
                $count = (int) Env::input($post['count'] ?? '0');
                if ($reg !== '') {
                    if (!in_array($reg, ['home', 'global'], true)) {
                        return [[['bad', 'منطقه نامعتبر است.']], []];
                    }
                    $body['region'] = $reg;
                }
                if ($size !== '') {
                    if (!isset(self::SIZES[$size])) {
                        return [[['bad', 'اندازه نامعتبر است.']], []];
                    }
                    $body['size'] = $size;
                }
                if ($count < 1 || $count > 20) {
                    return [[['bad', 'تعداد باید ۱ تا ۲۰ باشد.']], []];
                }
                $body['count'] = $count;
                [$c, $d] = self::call('POST', '/api/v1/provisioning/proposals/' . $id . '/approve', $body);
                Pages::reset();
                if ($c < 200 || $c >= 300) {
                    return [[['bad', View::e('تأیید انجام نشد: ' . self::err($c, $d))]], []];
                }
                Env::log('provisioning proposal #' . $id . ' approved (' . json_encode($body) . ') by admin #' . $admin);
                return [[['ok', 'پیشنهاد #' . View::n($id) . ' تأیید شد؛ اجراکننده طرح Terraform را تهیه و برای تأیید دوم بارگذاری می‌کند.']], []];
            case 'ops_prov_apply':
            case 'ops_prov_reject':
                $op = $action === 'ops_prov_apply' ? 'apply' : 'reject';
                [$c, $d] = self::call('POST', '/api/v1/provisioning/proposals/' . $id . '/' . $op, []);
                Pages::reset();
                if ($c < 200 || $c >= 300) {
                    return [[['bad', View::e(($op === 'apply' ? 'اجرای طرح' : 'رد پیشنهاد') . ' انجام نشد: ' . self::err($c, $d))]], []];
                }
                Env::log('provisioning proposal #' . $id . ' ' . $op . ' by admin #' . $admin);
                return [[['ok', $op === 'apply' ? 'اجرای طرح تأیید شد؛ اجراکننده آن را اجرا می‌کند و نودها با توکن یک‌بارمصرف می‌پیوندند.' : 'پیشنهاد #' . View::n($id) . ' رد شد.']], []];
            case 'ops_prov_create':
                $body = ['group' => Env::input($post['group'] ?? ''), 'region' => Env::input($post['region'] ?? ''), 'size' => Env::input($post['size'] ?? ''),
                    'count' => (int) Env::input($post['count'] ?? '0')];
                if (!in_array($body['group'], ['general', 'tunnel'], true) || !in_array($body['region'], ['home', 'global'], true) || !isset(self::SIZES[$body['size']])
                    || $body['count'] < 1 || $body['count'] > 20) {
                    return [[['bad', 'گروه، منطقه، اندازه یا تعداد (۱ تا ۲۰) نامعتبر است.']], []];
                }
                [$c, $d] = self::call('POST', '/api/v1/provisioning/proposals', $body);
                Pages::reset();
                if ($c < 200 || $c >= 300) {
                    return [[['bad', View::e('ثبت پیشنهاد انجام نشد: ' . self::err($c, $d))]], []];
                }
                Env::log('provisioning proposal created manually (' . json_encode($body) . ') by admin #' . $admin);
                return [[['ok', 'پیشنهاد ثبت شد.']], []];
        }
        return [[['bad', 'عملیات نامعتبر است.']], []];
    }
}
