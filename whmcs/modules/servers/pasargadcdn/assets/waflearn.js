/*
 * Pasargad CDN — client app: WAF «حالت یادگیری» (learning mode, docs/SPEC.md §17.3, docs/WHMCS.md).
 *
 * Registers PCDN.wafLearn.card(d, f2, Aa), placed by pages.js on the WAF page under «حالت کار»:
 *   - state from GET waf/learning → {state: off|learning|learned, started_at, until, requests_observed, proposals};
 *   - start: PUT config/waf = the SAVED section + learning {enabled: true, days 1..30 (default 7)};
 *     stop: the same with learning {enabled: false}. While learning the edge runs the WAF log-only — it
 *     observes and never blocks on WAF verdicts (firewall, rate limits and DDoS keep working);
 *   - progress (elapsed share, remaining time, requests observed);
 *   - proposals: kind badge, Persian summary (the English `detail` on an English page), confidence meter,
 *     a readable diff of the exact change against the current settings (+ the raw JSON), checkboxes and
 *     «اعمال موارد انتخاب‌شده» (confirm → POST waf/learning/apply {ids}); nothing is ever applied by itself.
 *
 * Feature detection: the card exists only when GET waf/learning answers; an older controller (404) gets
 * no card and never receives `learning`. Read-only team members and inactive services see the state and
 * every proposal / preview, every write control is disabled. Data reaches the DOM only via textContent.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num;

  function A() { return P.app; }
  function S() { return P.app.S; }
  function canWrite() { return !!S().active && !A().readonly; }

  // Mirrors controller/app: sections.WafLearning (days 1..30, default 7), waf_learning.proposal_id ("p_" + 16 hex);
  // ClientApi::MAX_APPLY_IDS (≤ 100 ids per apply).
  var DAYS_MIN = 1, DAYS_MAX = 30, DAYS_DEF = 7, MAX_APPLY = 100;
  var ID_RE = /^p_[0-9a-f]{16}$/;
  var KINDS = {
    waf_exclusion: [t('استثنای WAF'), 'brand', 'shieldCheck'],
    rate_limit: [t('محدودیت نرخ'), 'warning', 'gauge'],
    pack_off: [t('خاموش کردن بسته'), 'violet', 'package']
  };
  var SECTION_NAMES = { waf: 'WAF', ratelimit: t('محدودیت نرخ'), firewall: t('فایروال') };

  function has(o, k) { return !!o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k); }
  function isObj(o) { return !!o && typeof o === 'object' && !Array.isArray(o); }
  function ms(iso) { var x = iso ? new Date(iso).getTime() : NaN; return isNaN(x) ? null : x; }
  function json(v) { try { return JSON.stringify(v); } catch (e) { return String(v); } }

  /** Proposals as the controller sent them, keeping only well-formed ones (id, kind, change). */
  function proposalsOf(st) {
    return (Array.isArray(st.proposals) ? st.proposals : []).filter(function (p) {
      return isObj(p) && typeof p.id === 'string' && ID_RE.test(p.id) && isObj(p.change);
    });
  }
  function summaryOf(p) {
    if (P.isEn && typeof p.detail === 'string' && p.detail) return p.detail;
    return typeof p.summary === 'string' && p.summary ? p.summary : (typeof p.detail === 'string' ? p.detail : p.id);
  }
  /** The summary as nodes: paths (/wp-json/*) and other Latin runs isolated LTR so the RTL sentence keeps their order. */
  function summaryNodes(text) {
    var out = [], re = /\/[A-Za-z0-9\-._~%!$&'()*+,;=:@\/]*|[A-Za-z][A-Za-z0-9_.\-]*(?: [A-Za-z0-9_.\-]+)*/g, m, last = 0;
    if (P.isEn) return [String(text)];
    while ((m = re.exec(text))) {
      if (m.index > last) out.push(text.slice(last, m.index));
      out.push(h('bdi', { dir: 'ltr', text: m[0] }));
      last = m.index + m[0].length;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
  }
  function confidenceOf(p) { var c = Number(p.confidence); return isFinite(c) ? Math.max(0, Math.min(1, c)) : 0; }

  // ------------------------------------------------------------------ readable diff of a proposal's change

  function current(sec) { var c = S().site && S().site.config && S().site.config[sec]; return isObj(c) ? c : {}; }
  /**
   * The controller's change {section, op, value} (waf_learning: add_exclusion → waf.exclusions,
   * add_rule → ratelimit.rules, remove_pack → waf.packs) as a section patch {section: {key: new value}}
   * against the current settings; a plain {section: {key: value}} patch passes through; null if unknown.
   */
  function patchOf(ch) {
    if (typeof ch.section !== 'string' || typeof ch.op !== 'string') return ch;
    var cur = current(ch.section), out = {};
    var list = function (k) { return Array.isArray(cur[k]) ? cur[k].slice() : []; };
    if (ch.op === 'add_exclusion') out.exclusions = list('exclusions').concat([ch.value]);
    else if (ch.op === 'add_rule') out.rules = list('rules').concat([ch.value]);
    else if (ch.op === 'remove_pack') out.packs = list('packs').filter(function (x) { return x !== ch.value; });
    else return null;
    var r = {};
    r[ch.section] = out;
    return r;
  }
  /**
   * Lines of the change against the current settings: [{sign: 'h'|'+'|'-'|'=', label, text}]; list values
   * are compared item by item (added / removed), anything else as a whole value.
   */
  function diffLines(change) {
    var out = [], patch0 = patchOf(change);
    if (!patch0) {
      out.push({ sign: 'h', text: String(change.section) });
      out.push({ sign: '+', label: String(change.op), text: json(change.value) });
      return out;
    }
    Object.keys(patch0).forEach(function (sec) {
      var patch = patch0[sec];
      var cur = current(sec);
      var name = SECTION_NAMES[sec];
      out.push({ sign: 'h', text: name && name.toLowerCase() !== sec ? name + ' · ' + sec : sec });
      if (!isObj(patch)) { out.push({ sign: '+', text: json(patch) }); return; }
      Object.keys(patch).forEach(function (k) {
        var nw = patch[k], old = cur[k];
        if (Array.isArray(nw) && (Array.isArray(old) || old === undefined)) {
          var o = (old || []).map(json), n = nw.map(json), same = 0;
          o.forEach(function (x) { if (n.indexOf(x) < 0) out.push({ sign: '-', label: k, text: x }); else same++; });
          n.forEach(function (x) { if (o.indexOf(x) < 0) out.push({ sign: '+', label: k, text: x }); });
          if (same) out.push({ sign: '=', label: k, text: t('{0} مورد فعلی بدون تغییر می‌ماند', num(same)) });
          return;
        }
        if (json(old) === json(nw)) { out.push({ sign: '=', label: k, text: json(nw) }); return; }
        if (old !== undefined) out.push({ sign: '-', label: k, text: json(old) });
        out.push({ sign: '+', label: k, text: json(nw) });
      });
    });
    return out;
  }
  function diffView(p) {
    var lines = diffLines(p.change);
    var raw = JSON.stringify(p.change, null, 2);
    var rawBox = h('pre', { className: 'pcdn-wl-json', dir: 'ltr', tabindex: '0', hidden: true }, h('code', { text: raw }));
    var toggle = h('button', { type: 'button', className: 'pcdn-btn pcdn-btn-sm pcdn-wl-rawbtn', 'aria-expanded': 'false', 'data-ro-ok': '1', text: t('نمایش JSON'),
      onclick: function () {
        rawBox.hidden = !rawBox.hidden;
        toggle.setAttribute('aria-expanded', String(!rawBox.hidden));
        toggle.textContent = rawBox.hidden ? t('نمایش JSON') : t('پنهان کردن JSON');
      } });
    return h('div', { className: 'pcdn-wl-diff' },
      h('div', { className: 'pcdn-wl-diff-lines', dir: 'ltr', role: 'list', 'aria-label': t('تغییر دقیق این پیشنهاد') }, lines.map(function (l) {
        if (l.sign === 'h') return h('div', { className: 'pcdn-wl-dh', role: 'listitem', text: l.text });
        return h('div', { className: 'pcdn-wl-dl is-' + (l.sign === '+' ? 'add' : l.sign === '-' ? 'del' : 'same'), role: 'listitem' },
          h('span', { className: 'pcdn-wl-sign', 'aria-hidden': 'true', text: l.sign === '=' ? ' ' : l.sign }),
          h('span', { className: 'pcdn-sr', text: l.sign === '+' ? t('افزوده: ') : l.sign === '-' ? t('حذف: ') : t('بدون تغییر: ') }),
          l.label ? h('span', { className: 'pcdn-wl-key', text: l.label + ': ' }) : null,
          h('span', { className: 'pcdn-wl-val', text: l.text }));
      })),
      toggle, rawBox);
  }

  // ------------------------------------------------------------------ the card

  var cards = typeof WeakMap === 'function' ? new WeakMap() : null;

  /**
   * The «حالت یادگیری» card for the WAF form f2 (same element across redraws of that form, so its state
   * and the loaded proposals survive edits elsewhere on the page). Hidden until GET waf/learning answers.
   */
  function card(d, f2, Aa) {
    var c = cards && cards.get(f2);
    if (c) { c.sync(d); return c.el; }
    c = build(f2, Aa);
    if (cards) cards.set(f2, c);
    return c.el;
  }

  function build(f2, Aa) {
    var cur = (f2.draft || {}).learning, wafMode = (f2.draft || {}).mode;
    var st = null, picked = {}, loading = false;
    var days = isObj(cur) && Math.floor(cur.days) === cur.days && cur.days >= DAYS_MIN && cur.days <= DAYS_MAX ? cur.days : DAYS_DEF;
    var el = P.card({ title: t('حالت یادگیری'), icon: 'sparkles', tone: 'violet', id: 'waf-learning',
      subtitle: t('WAF چند روز ترافیک واقعی سایت را فقط مشاهده می‌کند و برای کاهش مسدودسازی‌های اشتباه و تنظیم محدودیت نرخ پیشنهاد می‌دهد.') });
    el.hidden = true;
    el.setAttribute('data-state', 'loading');
    var body = el.body;

    function lock() { if (A().lockWrites) A().lockWrites(el); }
    function blockedByDraft() {
      if (f2.dirty && f2.dirty()) {
        P.toast(t('ابتدا تغییرات ذخیره‌نشدهٔ این صفحه را ذخیره یا لغو کنید.'), 'error');
        return true;
      }
      return false;
    }

    function load(quiet) {
      loading = true;
      if (!quiet) { clear(body); body.appendChild(P.skeleton(3)); }
      return P.api('GET', 'waf/learning').then(function (res) {
        loading = false;
        if (res.status === 404) {          // older controller: no learning mode at all
          st = null;
          el.hidden = true;
          el.setAttribute('data-state', 'absent');
          return res;
        }
        el.hidden = false;
        if (!res.ok || !isObj(res.data)) {
          el.setAttribute('data-state', 'error');
          clear(body);
          append(body, [P.errorBox(res, t('وضعیت حالت یادگیری دریافت نشد')),
            P.btn(t('تلاش دوباره'), { icon: 'refresh', size: 'sm', cls: 'pcdn-wl-retry', onclick: function () { load(); } })]);
          return res;
        }
        st = res.data;
        var keep = {};
        proposalsOf(st).forEach(function (p) { if (picked[p.id]) keep[p.id] = true; });
        picked = keep;
        draw();
        return res;
      });
    }

    /** PUT the saved waf section with learning {enabled, days?}; refreshes the form and the state. */
    function putLearning(button, on) {
      var sec = Aa.config('waf');
      // until / started_at are the controller's (it replaces whatever is sent); days is kept on stop
      sec.learning = on ? { enabled: true, days: days } : { enabled: false, days: isObj(sec.learning) && sec.learning.days ? sec.learning.days : days };
      return P.busy(button, P.api('PUT', 'config/waf', sec)).then(function (res) {
        if (!res.ok) {
          clear(msgBox);
          msgBox.appendChild(P.errorBox(res, on ? t('شروع حالت یادگیری انجام نشد') : t('توقف حالت یادگیری انجام نشد')));
          return res;
        }
        Aa.setConfig('waf', isObj(res.data) ? res.data : sec);
        f2.load();
        f2.redraw();
        P.toast(on ? t('حالت یادگیری شروع شد؛ در این مدت WAF چیزی را مسدود نمی‌کند.') : t('حالت یادگیری متوقف شد و WAF به حالت کار عادی خود برگشت.'));
        return load();
      });
    }

    function start(button) {
      if (blockedByDraft()) return;
      var n = Number(days);
      if (!(Math.floor(n) === n && n >= DAYS_MIN && n <= DAYS_MAX)) {
        clear(msgBox);
        msgBox.appendChild(P.alertBox('danger', t('مدت یادگیری باید عددی بین ۱ تا ۳۰ روز باشد.')));
        return;
      }
      P.confirm({ title: t('شروع حالت یادگیری'), ok: t('شروع یادگیری'), cancel: t('انصراف'),
        body: h('div', null,
          h('p', { text: t('به مدت {0} روز WAF این سایت فقط ثبت می‌کند و هیچ درخواستی را به خاطر قوانین WAF مسدود نمی‌کند (مثل حالت «فقط ثبت»). فایروال، محدودیت نرخ و حفاظت DDoS مثل قبل کار می‌کنند.', num(n)) }),
          h('p', { text: t('در پایان، پیشنهادها اینجا نمایش داده می‌شوند و تا شما تأیید نکنید هیچ‌کدام اعمال نمی‌شود.') })) })
        .then(function (ok) { if (ok) putLearning(button, true); });
    }
    function stop(button) {
      if (blockedByDraft()) return;
      P.confirm({ title: t('توقف حالت یادگیری'), ok: t('توقف یادگیری'), cancel: t('ادامهٔ یادگیری'), danger: true,
        body: t('WAF بی‌درنگ به حالت کار عادی خود برمی‌گردد. پیشنهادهایی که تا الان ساخته شده‌اند باقی می‌مانند؛ هرچه یادگیری کوتاه‌تر باشد پیشنهادها کمتر و نامطمئن‌ترند.') })
        .then(function (ok) { if (ok) putLearning(button, false); });
    }

    function apply(button) {
      if (blockedByDraft()) return;
      var list = proposalsOf(st).filter(function (p) { return picked[p.id] && !p.applied; });
      if (!list.length) return;
      if (list.length > MAX_APPLY) { P.toast(t('در هر بار حداکثر ۱۰۰ پیشنهاد را می‌توانید اعمال کنید.'), 'error'); return; }
      P.confirm({ title: t('اعمال پیشنهادهای انتخاب‌شده'), ok: t('اعمال {0} پیشنهاد', num(list.length)), cancel: t('انصراف'),
        body: h('div', null,
          h('p', { text: t('این تغییرها در تنظیمات سایت ذخیره می‌شوند و تا چند ثانیه روی همه سرورها اعمال می‌شوند:') }),
          h('ul', { className: 'pcdn-list pcdn-wl-confirm-list' }, list.map(function (p) { return h('li', { text: summaryOf(p) }); })),
          h('p', { className: 'pcdn-help', text: t('هر تغییر را بعداً می‌توانید از همین صفحه (استثناها و بسته‌ها) یا صفحهٔ «محدودیت نرخ» ویرایش یا حذف کنید.') })) })
        .then(function (ok) {
          if (!ok) return;
          P.busy(button, P.api('POST', 'waf/learning/apply', { ids: list.map(function (p) { return p.id; }) })).then(function (res) {
            if (!res.ok) {
              clear(msgBox);
              msgBox.appendChild(P.errorBox(res, t('اعمال پیشنهادها انجام نشد')));
              return;
            }
            // the controller answers with the updated sections — {sections: {waf, ratelimit, …}} or the sections themselves
            var secs = isObj(res.data) && isObj(res.data.sections) ? res.data.sections : res.data;
            if (isObj(secs)) {
              Object.keys(secs).forEach(function (k) {
                if (isObj(secs[k]) && S().site && S().site.config && has(S().site.config, k)) Aa.setConfig(k, secs[k]);
              });
            }
            picked = {};
            f2.load();
            f2.redraw();
            P.toast(t('{0} پیشنهاد اعمال شد و تا چند ثانیه روی همه سرورها فعال می‌شود.', num(list.length)));
            load(true);
          });
        });
    }

    var msgBox = h('div', { className: 'pcdn-wl-msg' });

    function explain() {
      return h('ul', { className: 'pcdn-wl-points' },
        h('li', null, icon('eye'), h('span', { text: t('فقط مشاهده می‌کند: در مدت یادگیری WAF مثل حالت «فقط ثبت» کار می‌کند و هیچ درخواستی را به خاطر قوانین WAF مسدود نمی‌کند.') })),
        h('li', null, icon('shield'), h('span', { text: t('فایروال، محدودیت نرخ و حفاظت DDoS در این مدت مثل قبل کار می‌کنند.') })),
        h('li', null, icon('bulb'), h('span', { text: t('در پایان، پیشنهادهایی برای استثنای WAF، محدودیت نرخ و خاموش کردن بسته‌های بی‌فایده می‌بینید که هیچ‌کدام خودکار اعمال نمی‌شود.') })));
    }

    function startForm(again) {
      var id = P.uid('pcdn-wl-days-');
      var input = h('input', { type: 'number', id: id, className: 'pcdn-input pcdn-wl-days', min: String(DAYS_MIN), max: String(DAYS_MAX), step: '1', value: String(days),
        inputmode: 'numeric', dir: 'ltr', oninput: function (e) { days = e.target.value === '' ? '' : Number(e.target.value); } });
      return h('div', { className: 'pcdn-wl-start' },
        h('div', { className: 'pcdn-field pcdn-wl-days-field' },
          h('label', { className: 'pcdn-label', 'for': id, text: t('مدت یادگیری') }),
          h('div', { className: 'pcdn-wl-days-row' }, input, h('span', { className: 'pcdn-wl-unit', text: t('روز') })),
          h('p', { className: 'pcdn-help', text: t('بین ۱ تا ۳۰ روز؛ ۷ روز پیشنهادی است تا ترافیک همهٔ روزهای هفته دیده شود.') })),
        P.btn(again ? t('شروع دوبارهٔ یادگیری') : t('شروع یادگیری'), { kind: again ? null : 'primary', icon: 'play', write: true, cls: 'pcdn-wl-startbtn',
          onclick: function (e) { start(e.currentTarget); } }));
    }

    function progress() {
      var a = ms(st.started_at), b = ms(st.until), now = Date.now();
      var ratio = typeof st.progress === 'number' && isFinite(st.progress) ? st.progress : a !== null && b !== null && b > a ? (now - a) / (b - a) : 0;
      var left = b !== null ? Math.max(0, Math.round((b - now) / 1000)) : null;
      if (left !== null && left >= 3600) left = Math.round(left / 3600) * 3600;
      else if (left !== null && left > 60) left = Math.round(left / 60) * 60;
      return h('div', { className: 'pcdn-wl-progress' },
        h('div', { className: 'pcdn-wl-progress-head' },
          h('span', { className: 'pcdn-pill pcdn-tone-violet' }, h('span', { className: 'pcdn-dot' }), h('span', { text: t('در حال یادگیری') })),
          h('span', { className: 'pcdn-wl-left', text: left === null ? '' : left > 0 ? t('{0} مانده', P.dur(left)) : t('در حال پایان') })),
        P.meter(ratio, 'brand'),
        h('dl', { className: 'pcdn-wl-facts' },
          h('div', null, h('dt', { text: t('زمان شروع') }), h('dd', { text: P.date(st.started_at) })),
          h('div', null, h('dt', { text: t('زمان پایان') }), h('dd', { text: P.date(st.until) })),
          h('div', { 'data-wl-observed': '1' }, h('dt', { text: t('درخواست‌های بررسی‌شده') }), h('dd', { text: num(Number(st.requests_observed) || 0) }))));
    }

    function proposalItem(p) {
      var k = KINDS[p.kind] || [String(p.kind || '—'), 'muted', 'info'];
      var conf = confidenceOf(p), pc = Math.round(conf * 100);
      var tone = conf >= 0.8 ? 'success' : conf >= 0.5 ? 'warning' : 'danger';
      var cid = P.uid('pcdn-wl-p-');
      var done = !!p.applied;
      var box = h('input', { type: 'checkbox', id: cid, className: 'pcdn-wl-check', checked: !!picked[p.id] && !done, disabled: done,
        'aria-describedby': cid + '-c', onchange: function (e) { if (e.target.checked) picked[p.id] = true; else delete picked[p.id]; sync(); } });
      var prev = h('div', { className: 'pcdn-wl-preview', hidden: true }, diffView(p));
      var pbtn = h('button', { type: 'button', className: 'pcdn-btn pcdn-btn-sm pcdn-wl-prevbtn', 'aria-expanded': 'false', 'data-ro-ok': '1',
        onclick: function () {
          prev.hidden = !prev.hidden;
          pbtn.setAttribute('aria-expanded', String(!prev.hidden));
          pbtn.lastChild.textContent = prev.hidden ? t('پیش‌نمایش تغییر') : t('بستن پیش‌نمایش');
        } }, icon('code'), h('span', { text: t('پیش‌نمایش تغییر') }));
      return h('li', { className: 'pcdn-wl-item' + (done ? ' is-applied' : ''), 'data-proposal': p.id, 'data-kind': p.kind },
        h('div', { className: 'pcdn-wl-item-main' },
          box,
          h('label', { className: 'pcdn-wl-item-text', 'for': cid },
            h('span', { className: 'pcdn-wl-item-top' }, P.badge(k[0], k[1], k[2]), done ? P.badge(t('اعمال شده'), 'success', 'check') : null),
            h('span', { className: 'pcdn-wl-summary' }, summaryNodes(summaryOf(p))))),
        h('div', { className: 'pcdn-wl-item-side' },
          h('div', { className: 'pcdn-wl-conf', id: cid + '-c' },
            h('span', { className: 'pcdn-wl-conf-label', text: t('اطمینان: {0}', num(pc) + t('٪')) }),
            P.meter(conf, tone)),
          pbtn),
        prev);
    }

    var listEl = null, applyBtn = null, countEl = null, allBox = null;
    function sync() {
      var open = proposalsOf(st || {}).filter(function (p) { return !p.applied; });
      var n = open.filter(function (p) { return picked[p.id]; }).length;
      if (applyBtn) applyBtn.disabled = !n || !canWrite();
      if (countEl) countEl.textContent = n ? t('{0} مورد انتخاب شده', num(n)) : t('موردی انتخاب نشده');
      if (allBox) { allBox.checked = !!open.length && n === open.length; allBox.indeterminate = n > 0 && n < open.length; }
    }

    function proposalsBlock(state) {
      var list = proposalsOf(st);
      listEl = applyBtn = countEl = allBox = null;
      if (!list.length) {
        return P.empty('checkCircle', state === 'learning' ? t('هنوز پیشنهادی نیست') : t('پیشنهادی برای تغییر نیست'),
          state === 'learning' ? t('پیشنهادها با دیده شدن ترافیک کافی ساخته می‌شوند و در پایان یادگیری کامل می‌شوند.')
            : t('در مدت یادگیری مسدودسازی اشتباه یا مسیر پرترافیکی که به محدودیت نرخ نیاز داشته باشد دیده نشد؛ تنظیمات فعلی مناسب به نظر می‌رسد.'));
      }
      var open = list.filter(function (p) { return !p.applied; });
      var aid = P.uid('pcdn-wl-all-');
      allBox = h('input', { type: 'checkbox', id: aid, className: 'pcdn-wl-all', disabled: !open.length, onchange: function (e) {
        picked = {};
        if (e.target.checked) open.slice(0, MAX_APPLY).forEach(function (p) { picked[p.id] = true; });
        Array.prototype.forEach.call(listEl.querySelectorAll('.pcdn-wl-item'), function (li) {
          var cb = li.querySelector('.pcdn-wl-check');
          if (cb && !cb.disabled) cb.checked = !!picked[li.getAttribute('data-proposal')];
        });
        sync();
      } });
      countEl = h('span', { className: 'pcdn-wl-count', 'aria-live': 'polite' });
      applyBtn = P.btn(t('اعمال موارد انتخاب‌شده'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-wl-apply', onclick: function (e) { apply(e.currentTarget); } });
      listEl = h('ul', { className: 'pcdn-wl-list', 'aria-label': t('پیشنهادهای حالت یادگیری') }, list.map(proposalItem));
      var out = h('div', { className: 'pcdn-wl-proposals' },
        h('h4', { className: 'pcdn-wl-h', text: t('پیشنهادها ({0})', num(list.length)) }),
        state === 'learning' ? P.alertBox('info', t('یادگیری هنوز ادامه دارد؛ این پیشنهادها اولیه‌اند و با ترافیک بیشتر دقیق‌تر می‌شوند.')) : null,
        h('div', { className: 'pcdn-wl-bar' },
          h('label', { className: 'pcdn-wl-allbox', 'for': aid }, allBox, h('span', { text: t('انتخاب همه') })),
          countEl, applyBtn),
        listEl);
      sync();
      return out;
    }

    function draw() {
      var state = st && ['off', 'learning', 'learned'].indexOf(st.state) >= 0 ? st.state : 'off';
      el.setAttribute('data-state', state);
      clear(body);
      clear(msgBox);
      if (state === 'off') {
        append(body, [explain(),
          wafMode === 'block' ? P.alertBox('warning', t('در مدت یادگیری WAF درخواست‌های مخرب را هم مسدود نمی‌کند؛ اگر سایت زیر حمله است اول حمله را مهار کنید.')) : null,
          startForm(false), msgBox, proposalsOf(st).length ? proposalsBlock('learned') : null]);
      } else if (state === 'learning') {
        append(body, [progress(),
          P.alertBox('info', t('در این مدت WAF فقط ثبت می‌کند و چیزی را مسدود نمی‌کند؛ پایان یادگیری خودکار است و پس از آن WAF به حالت کار انتخاب‌شده برمی‌گردد.')),
          h('div', { className: 'pcdn-wl-actions' },
            P.btn(t('توقف یادگیری'), { icon: 'power', write: true, cls: 'pcdn-wl-stop', onclick: function (e) { stop(e.currentTarget); } }),
            P.btn(t('به‌روزرسانی'), { icon: 'refresh', size: 'sm', cls: 'pcdn-wl-refresh', onclick: function () { if (!loading) load(true); } })),
          msgBox, proposalsBlock('learning')]);
      } else {
        append(body, [
          P.alertBox('success', [h('strong', { text: t('یادگیری کامل شد. ') }),
            t('{0} درخواست از {1} تا {2} بررسی شد.', num(Number(st.requests_observed) || 0), P.date(st.started_at, { dateStyle: 'medium' }), P.date(st.until, { dateStyle: 'medium' }))]),
          msgBox, proposalsBlock('learned')]);
        var again = P.collapsible({ title: t('یادگیری دوباره'), icon: 'refresh', tone: 'muted', id: 'waf-learning-again', cls: 'pcdn-wl-again',
          subtitle: t('پس از تغییرات بزرگ در سایت، یادگیری را دوباره اجرا کنید.') });
        append(again.body, [explain(), startForm(true)]);
        body.appendChild(again);
      }
      lock();
    }

    var self = {
      el: el,
      /** Called on each redraw of the WAF form: keep the card, follow the chosen mode. */
      sync: function (d) {
        var m = d && d.mode;
        if (m !== wafMode) { wafMode = m; if (st && st.state === 'off') draw(); }
        lock();
      }
    };
    load();
    return self;
  }

  P.wafLearn = { card: card, diffLines: diffLines, ID_RE: ID_RE };
})();
