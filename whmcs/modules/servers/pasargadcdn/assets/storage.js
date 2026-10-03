/*
 * Pasargad CDN — client app: «فضای ذخیره‌سازی» object storage (docs/SPEC.md §16.8, docs/STORAGE.md).
 *
 * Registers PCDN.pages.storage and PCDN.storage (record-dialog hooks used by app.js):
 *   - usage of the site's storage vs the plan's storage_gb, endpoint + region;
 *   - buckets (name, full bucket name, endpoint, region, access key, usage, quota) from GET storage;
 *   - create (POST storage/buckets), new access key (POST storage/buckets/<name>/rotate-key) and delete
 *     (DELETE storage/buckets/<name>; 409 while it holds files or is a record's origin);
 *   - connection guide (aws-cli / rclone / s3cmd) and «use as CDN origin», which opens the DNS record
 *     dialog prefilled with `storage: <name>`; the record dialog offers the bucket origin itself.
 *
 * Feature detection: the page exists only when the controller's plan features carry `storage_gb` (an
 * older controller has no such key and never sees a storage call); it is locked (upsell) while
 * storage_gb is 0. The secret key is returned only by create / rotate-key and shown ONCE in a dialog:
 * it is never kept in app state, localStorage or the page after that dialog closes, and api.php masks
 * it in the WHMCS module log. Data reaches the DOM only through textContent / createElement.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  var pages = P.pages = P.pages || {};
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, num = P.num;

  function A() { return P.app; }
  function S() { return P.app.S; }
  function has(o, k) { return !!o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k); }
  function feats(s) { return (s && s.plan && s.plan.features) || {}; }
  /** The controller knows object storage (plan features carry storage_gb). */
  function known(s) { return has(feats(s), 'storage_gb'); }
  /** The plan includes storage. */
  function enabled(s) { return known(s) && Number(feats(s).storage_gb) > 0; }

  // controller/app/storage.py: validate_name (3..40, a-z 0-9 -, letter/digit at both ends)
  var NAME_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
  var NAME_MAX = 40;
  function nameProblem(v) {
    v = String(v || '').trim();
    if (!v) return t('نام باکت را وارد کنید.');
    if (v.length < 3 || v.length > NAME_MAX || !NAME_RE.test(v)) return t('نام باکت باید ۳ تا ۴۰ کاراکتر از حروف کوچک انگلیسی، رقم و - باشد و با حرف یا رقم شروع و تمام شود.');
    return '';
  }

  var GIB = 1073741824;
  function hostOf(url) { var m = /^https?:\/\/([^/:]+)(?::(\d+))?/i.exec(String(url || '')); return m ? m[1] + (m[2] ? ':' + m[2] : '') : ''; }

  // ------------------------------------------------------------------ state (never any secret)

  /** Last overview: {available, enabled, storage_gb, used_bytes, …, buckets: [...]} — GET storage only. */
  function st() { var s = S(); return s.storage || (s.storage = { data: null, at: 0, loading: null }); }
  function load(force) {
    var x = st();
    if (!force && x.data && Date.now() - x.at < 30000) return Promise.resolve({ ok: true, status: 200, data: x.data });
    if (x.loading) return x.loading;
    x.loading = P.api('GET', 'storage').then(function (res) {
      x.loading = null;
      if (res.ok && res.data && typeof res.data === 'object' && Array.isArray(res.data.buckets)) {
        // only the public overview is kept (the controller never puts a secret in it; dropped defensively anyway)
        res.data.buckets = res.data.buckets.map(function (b) { var o = Object.assign({}, b); delete o.secret_key; return o; });
        x.data = res.data;
        x.at = Date.now();
      }
      return res;
    });
    return x.loading;
  }
  function buckets() { var d = st().data; return d && Array.isArray(d.buckets) ? d.buckets : []; }

  // ------------------------------------------------------------------ snippets

  function snippets(o) {
    var ep = o.endpoint || 'https://s3.example.com', host = hostOf(ep) || 's3.example.com', region = o.region || 'us-east-1';
    var bucket = o.bucket || 'cdn-xxxxxxxx-assets', ak = o.access_key || 'ACCESS_KEY', sk = o.secret || '<SECRET_KEY>';
    return {
      aws: 'aws configure set aws_access_key_id ' + ak + ' --profile pcdn\n' +
        'aws configure set aws_secret_access_key ' + sk + ' --profile pcdn\n' +
        'aws configure set region ' + region + ' --profile pcdn\n' +
        'aws configure set s3.addressing_style path --profile pcdn\n\n' +
        'aws --profile pcdn --endpoint-url ' + ep + ' s3 cp ./logo.png s3://' + bucket + '/img/logo.png\n' +
        'aws --profile pcdn --endpoint-url ' + ep + ' s3 sync ./public s3://' + bucket + '/public\n' +
        'aws --profile pcdn --endpoint-url ' + ep + ' s3 ls s3://' + bucket + '/',
      rclone: '# ~/.config/rclone/rclone.conf\n[pcdn]\ntype = s3\nprovider = Minio\naccess_key_id = ' + ak + '\nsecret_access_key = ' + sk +
        '\nendpoint = ' + ep + '\nregion = ' + region + '\nforce_path_style = true\n\n' +
        'rclone copy ./public pcdn:' + bucket + '/public\nrclone ls pcdn:' + bucket,
      s3cmd: '# ~/.s3cfg\n[default]\naccess_key = ' + ak + '\nsecret_key = ' + sk + '\nhost_base = ' + host + '\nhost_bucket = ' + host +
        '\nbucket_location = ' + region + '\nuse_https = ' + (/^http:/i.test(ep) ? 'False' : 'True') + '\n\n' +
        's3cmd put ./logo.png s3://' + bucket + '/img/logo.png\ns3cmd ls s3://' + bucket + '/'
    };
  }
  function codeBlock(text, caption, cls) {
    return h('figure', { className: 'pcdn-codeblock' + (cls ? ' ' + cls : '') },
      h('figcaption', null, icon('terminal'), h('span', { dir: 'ltr', text: caption }),
        P.copyBtn(text, t('کپی کد ') + caption, { text: t('کپی'), cls: 'pcdn-copy-code', done: t('کد کپی شد') })),
      h('pre', { dir: 'ltr', tabindex: '0' }, h('code', { text: text })));
  }

  // ------------------------------------------------------------------ one-time secret dialog

  /** Shows the new credentials ONCE. Nothing is kept once the dialog is closed. */
  function secretDialog(cred, rotated) {
    var secret = String(cred.secret_key || ''), ak = String(cred.access_key || '');
    var d = P.dialog({ title: rotated ? t('کلید دسترسی جدید باکت') : t('باکت ساخته شد'), subtitle: String(cred.name || ''), icon: 'key', tone: 'warning', wide: true });
    d.el.classList.add('pcdn-st-secret-dlg');
    var sn = snippets({ endpoint: cred.endpoint, region: cred.region, bucket: cred.bucket, access_key: ak, secret: secret });
    append(d.body, [
      P.alertBox('warning', [h('strong', { text: t('کلید مخفی فقط همین یک بار نمایش داده می‌شود. ') }),
        t('همین حالا آن را کپی کنید و در جای امنی (مثلاً مدیر گذرواژه یا تنظیمات برنامهٔ خودتان) نگه دارید؛ ما آن را دوباره نشان نمی‌دهیم و اگر گم شود باید کلید جدید بسازید.')], { icon: 'warn' }),
      rotated ? P.alertBox('info', t('کلید قبلی همین حالا باطل شد؛ برنامه‌ها و اسکریپت‌هایی که از آن استفاده می‌کنند را با کلید جدید به‌روز کنید.')) : null,
      h('div', { className: 'pcdn-st-cred' },
        h('div', { className: 'pcdn-field' }, h('span', { className: 'pcdn-label', text: t('کلید دسترسی (Access Key)') }),
          h('div', { className: 'pcdn-key-plain pcdn-st-ak' }, h('code', { className: 'pcdn-key-value', dir: 'ltr', text: ak }),
            P.copyBtn(ak, t('کپی کلید دسترسی'), { text: t('کپی'), done: t('کلید دسترسی کپی شد') }))),
        h('div', { className: 'pcdn-field' }, h('span', { className: 'pcdn-label', text: t('کلید مخفی (Secret Key)') }),
          h('div', { className: 'pcdn-key-plain pcdn-st-secret' }, h('code', { className: 'pcdn-key-value', dir: 'ltr', text: secret }),
            P.copyBtn(secret, t('کپی کلید مخفی'), { text: t('کپی'), done: t('کلید مخفی کپی شد') })))),
      cred.bucket ? h('p', { className: 'pcdn-help' }, t('نام کامل باکت: '), ltr(String(cred.bucket)), cred.endpoint ? t(' — نشانی: ') : null, cred.endpoint ? ltr(String(cred.endpoint)) : null) : null,
      codeBlock(sn.aws, 'aws-cli', 'pcdn-st-secret-aws')]);
    var done = P.btn(t('کلید را ذخیره کردم'), { kind: 'primary', icon: 'check', cls: 'pcdn-st-secret-ok', onclick: function () { d.close(); } });
    done.setAttribute('data-ro-ok', '1');
    d.foot.appendChild(done);
    d.focusFirst();
    return d;
  }

  // ------------------------------------------------------------------ actions

  function createDialog(onDone) {
    var model = { name: '' };
    var d = P.dialog({ title: t('باکت جدید'), icon: 'plus', subtitle: t('یک فضای جدا برای فایل‌ها با کلید دسترسی مخصوص خودش'), wide: false });
    d.el.classList.add('pcdn-st-create');
    var err = h('div');
    var form = h('form', { className: 'pcdn-form', novalidate: true, onsubmit: function (e) { e.preventDefault(); submit(); } });
    append(form, [P.input(model, 'name', t('نام باکت'), { maxlength: NAME_MAX, placeholder: 'assets', cls: 'pcdn-st-name',
      help: t('۳ تا ۴۰ کاراکتر: حروف کوچک انگلیسی، رقم و خط تیره (-)، شروع و پایان با حرف یا رقم. نام کامل باکت با یک پیشوند یکتا ساخته می‌شود و بعداً قابل تغییر نیست.') }),
      h('button', { type: 'submit', hidden: true, tabindex: '-1', 'aria-hidden': 'true' })]);
    append(d.body, [err, form]);
    var ok = P.btn(t('ساخت باکت'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-st-create-ok', onclick: submit });
    append(d.foot, [ok, P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
    function submit() {
      clear(err);
      P.clearErrors(form);
      var name = String(model.name || '').trim().toLowerCase();
      var bad = nameProblem(name);
      if (bad) {
        err.appendChild(P.alertBox('danger', bad));
        var inp = form.querySelector('input');
        if (inp) { inp.setAttribute('aria-invalid', 'true'); inp.focus(); }
        return;
      }
      P.busy(ok, P.api('POST', 'storage/buckets', { name: name })).then(function (res) {
        if (!res.ok) { err.appendChild(P.errorBox(res, t('باکت ساخته نشد'))); return; }
        d.close(true);
        var cred = res.data || {};
        res = null;   // the credentials live only in the dialog below
        secretDialog(cred, false);
        cred = null;
        onDone(name);
      });
    }
    d.focusFirst();
    if (A().lockWrites) A().lockWrites(d.el);
    return d;
  }

  function rotate(b, btn, onDone) {
    P.confirm({ title: t('ساخت کلید دسترسی جدید'), danger: true, ok: t('ساخت کلید جدید'),
      body: h('div', null, h('p', { text: t('برای باکت «') + b.name + t('» کلید دسترسی و کلید مخفی تازه ساخته می‌شود و کلید فعلی بلافاصله باطل می‌شود.') }),
        h('p', { className: 'pcdn-warn-text', text: t('برنامه‌ها، اسکریپت‌ها و پشتیبان‌گیری‌هایی که از کلید فعلی استفاده می‌کنند تا وقتی کلید جدید را در آن‌ها وارد نکنید کار نمی‌کنند. فایل‌ها و نشانی‌های CDN تغییری نمی‌کنند.') })) })
      .then(function (ok) {
        if (!ok) return;
        P.busy(btn, P.api('POST', 'storage/buckets/' + encodeURIComponent(b.name) + '/rotate-key')).then(function (res) {
          if (!res.ok) { P.toast(t('کلید جدید ساخته نشد: ') + P.errorText(res), 'error'); return; }
          var cred = res.data || {};
          res = null;
          secretDialog(cred, true);
          cred = null;
          onDone();
        });
      });
  }

  function remove(b, btn, onDone) {
    P.confirm({ title: t('حذف باکت'), danger: true, ok: t('حذف باکت'),
      body: h('div', null, h('p', null, t('باکت '), ltr(b.name), t(' و کلید دسترسی آن برای همیشه حذف می‌شود.')),
        h('p', { className: 'pcdn-help', text: t('فقط باکت خالی که مبدأ هیچ رکوردی نیست حذف می‌شود؛ ابتدا فایل‌ها را پاک کنید و رکوردهایی را که از آن استفاده می‌کنند تغییر دهید.') })) })
      .then(function (ok) {
        if (!ok) return;
        P.busy(btn, P.api('DELETE', 'storage/buckets/' + encodeURIComponent(b.name))).then(function (res) {
          if (!res.ok) {
            // 409: not empty, or the origin of a record — the controller says which (in the app's language via api.php)
            P.toast((res.status === 409 ? t('باکت حذف نشد: ') : t('حذف باکت انجام نشد: ')) + P.errorText(res), 'error');
            return;
          }
          P.toast(t('باکت حذف شد.'));
          onDone();
        });
      });
  }

  /** «Use as CDN origin»: the DNS page's record dialog, prefilled with this bucket as the origin of a proxied record. */
  function useAsOrigin(b) {
    var name = b.name, recs = (S().site && S().site.records) || [];
    if (recs.some(function (r) { return String(r.name) === name; })) name = 'cdn';
    if (name === 'cdn' && recs.some(function (r) { return String(r.name) === 'cdn'; })) name = '';
    A().go('dns').then(function (went) {
      if (went === false || !A().recordModal) return;
      A().recordModal(null, { type: 'CNAME', name: name, content: '', proxied: true, storage: b.name });
    });
  }

  // ------------------------------------------------------------------ page

  function usageCard(d) {
    var limit = Number(d.limit_bytes) || (Number(d.storage_gb) || 0) * GIB, used = Number(d.used_bytes) || 0;
    var ratio = limit > 0 ? used / limit : 0, tone = d.over_quota || ratio >= 1 ? 'danger' : ratio >= 0.9 ? 'warning' : 'success';
    var c = P.card({ title: t('مصرف فضای ذخیره‌سازی'), icon: 'gauge', id: 'storage-usage',
      actions: P.btn('', { icon: 'refresh', aria: t('به‌روزرسانی'), title: t('به‌روزرسانی'), cls: 'pcdn-btn-iconic pcdn-st-refresh', onclick: function () { A().renderMain(); } }) });
    c.querySelector('.pcdn-st-refresh').setAttribute('data-ro-ok', '1');
    var bs = Array.isArray(d.buckets) ? d.buckets : [];
    append(c.body, [
      h('div', { className: 'pcdn-st-usage' },
        h('div', { className: 'pcdn-st-usage-line' },
          h('strong', { className: 'pcdn-st-used' }, h('bdi', { text: P.bytes(used) })),
          h('span', { className: 'pcdn-muted', text: t(' از ') + num(Number(d.storage_gb) || 0) + t(' گیگابایت پلن') }),
          h('span', { className: 'pcdn-st-pct pcdn-tone-' + tone, text: limit > 0 ? P.pct(used, limit) : '—' })),
        P.meter(ratio, tone)),
      d.over_quota ? P.alertBox('danger', [h('strong', { text: t('فضای ذخیره‌سازی پر است. ') }),
        t('نوشتن فایل جدید متوقف شده است (خواندن و حذف ادامه دارد) و باکت جدید ساخته نمی‌شود. فایل‌های اضافه را حذف کنید یا پلن را ارتقا دهید. '),
        h('a', { href: A().upgradeUrl, className: 'pcdn-link', 'data-ro-ok': '1', text: t('ارتقای پلن') })]) : null,
      d.usage_stale ? P.alertBox('warning', t('آمار مصرف در این لحظه از سرور ذخیره‌سازی خوانده نشد؛ آخرین مقدار ثبت‌شده نمایش داده می‌شود.')) : null,
      h('dl', { className: 'pcdn-dl pcdn-dl-cols pcdn-st-facts' },
        h('div', null, h('dt', { text: t('نشانی (Endpoint)') }), h('dd', null, d.endpoint ? P.copyable(String(d.endpoint), { label: t('کپی نشانی') }) : h('span', { text: '—' }))),
        h('div', null, h('dt', { text: t('ناحیه (Region)') }), h('dd', null, ltr(String(d.region || '—')))),
        h('div', null, h('dt', { text: t('باکت‌ها') }), h('dd', { text: num(bs.length) + t(' از ') + num(Number(d.max_buckets) || 0) }))),
      h('p', { className: 'pcdn-help', text: t('مصرف چند دقیقه یک بار از سرور ذخیره‌سازی خوانده می‌شود (نه لحظه‌ای). سهمیه برای مجموع همهٔ باکت‌های این سرویس است.') })]);
    return c;
  }

  function bucketItem(b, d, reload) {
    var u = b.usage || {};
    var rot = P.btn(t('کلید جدید'), { icon: 'key', size: 'sm', write: true, cls: 'pcdn-st-rotate', onclick: function () { rotate(b, rot, reload); } });
    var del = P.iconBtn('trash', t('حذف باکت ') + b.name, function () { remove(b, del, reload); }, { write: true, cls: 'is-danger pcdn-st-del' });
    var origin = P.btn(t('مبدأ CDN'), { icon: 'cloud', size: 'sm', write: true, cls: 'pcdn-st-origin', title: t('ساخت رکورد پروکسی‌شده که فایل‌های این باکت را از CDN تحویل می‌دهد'), onclick: function () { useAsOrigin(b); } });
    var guide = P.btn(t('راهنمای اتصال'), { icon: 'terminal', size: 'sm', cls: 'pcdn-st-guide-btn', onclick: function () {
      var g = document.querySelector('[data-card="storage-guide"]');
      if (!g) return;
      var sel = g.querySelector('select');
      if (sel) { for (var i = 0; i < sel.options.length; i++) if (sel.options[i].value === b.name) { sel.selectedIndex = i; sel.dispatchEvent(new Event('change')); } }
      if (g.setOpen) g.setOpen(true);
      g.scrollIntoView({ behavior: A().reduced && A().reduced() ? 'auto' : 'smooth', block: 'start' });
    } });
    guide.setAttribute('data-ro-ok', '1');
    var usedBy = ((S().site && S().site.records) || []).filter(function (r) { return r.proxied && r.storage === b.name; });
    var quota = Number(b.quota_bytes) || 0;
    return h('li', { className: 'pcdn-wh pcdn-st-bucket', 'data-bucket': String(b.name) },
      h('div', { className: 'pcdn-wh-main' },
        h('div', { className: 'pcdn-wh-urlline' }, h('strong', { className: 'pcdn-st-bname', dir: 'ltr', text: String(b.name) }),
          usedBy.length ? P.badge(t('مبدأ رکورد: ') + usedBy.map(function (r) { return r.name === '@' ? S().site.domain : r.name; }).join(t('، ')), 'brand', 'cloud') : null),
        h('dl', { className: 'pcdn-dl pcdn-st-bfacts' },
          h('div', null, h('dt', { text: t('نام کامل باکت') }), h('dd', null, P.copyable(String(b.bucket || ''), { label: t('کپی نام کامل باکت') }))),
          h('div', null, h('dt', { text: t('کلید دسترسی') }), h('dd', null, b.access_key ? P.copyable(String(b.access_key), { label: t('کپی کلید دسترسی') }) : h('span', { text: '—' }))),
          h('div', null, h('dt', { text: t('نشانی و ناحیه') }), h('dd', null, ltr(String(b.endpoint || d.endpoint || '—')), ' · ', ltr(String(b.region || d.region || '—'), 'pcdn-nowrap'))),
          h('div', null, h('dt', { text: t('مصرف') }), h('dd', { className: 'pcdn-st-busage' }, h('bdi', { text: P.bytes(Number(u.bytes) || 0) }), ' — ',
            h('bdi', { text: num(Number(u.objects) || 0) + t(' فایل') }))),
          h('div', null, h('dt', { text: t('سقف این باکت') }), h('dd', null, h('bdi', { text: quota > 0 ? P.bytes(quota) : '—' })))),
        b.rotated_at ? h('p', { className: 'pcdn-help', text: t('آخرین تعویض کلید: ') + P.date(b.rotated_at) }) : null),
      h('div', { className: 'pcdn-wh-ctl pcdn-st-actions' }, origin, rot, guide, del));
  }

  function guideCard(d) {
    var bs = Array.isArray(d.buckets) ? d.buckets : [];
    var c = P.collapsible({ title: t('راهنمای اتصال'), icon: 'terminal', tone: 'muted', id: 'storage-guide',
      subtitle: t('آپلود و مدیریت فایل‌ها با aws-cli، rclone یا s3cmd (سازگار با S3)') });
    var pick = { b: bs.length ? bs[0].name : '' };
    var holder = h('div', { className: 'pcdn-st-guide' });
    function draw() {
      clear(holder);
      var b = bs.filter(function (x) { return x.name === pick.b; })[0] || {};
      var sn = snippets({ endpoint: b.endpoint || d.endpoint, region: b.region || d.region, bucket: b.bucket, access_key: b.access_key });
      append(holder, [
        codeBlock(sn.aws, 'aws-cli', 'pcdn-st-aws'),
        codeBlock(sn.rclone, 'rclone', 'pcdn-st-rclone'),
        codeBlock(sn.s3cmd, 's3cmd', 'pcdn-st-s3cmd')]);
    }
    append(c.body, [
      h('p', { text: t('به‌جای <SECRET_KEY> کلید مخفی‌ای را بگذارید که هنگام ساخت باکت یا ساخت کلید جدید نمایش داده شد. آدرس‌دهی باید path-style باشد (https://endpoint/<bucket>/<key>)؛ تنظیمات زیر همین را انجام می‌دهند.') }),
      bs.length > 1 ? P.select(pick, 'b', t('باکت'), bs.map(function (x) { return [x.name, x.name]; }), { ltr: true, onchange: draw, cls: 'pcdn-st-guide-pick' }) : null,
      holder,
      h('p', { className: 'pcdn-help', text: t('کلید هر باکت فقط به همان باکت دسترسی دارد: خواندن، نوشتن و حذف فایل‌ها. تغییر دسترسی عمومی باکت یا حذف خود باکت با کلید ممکن نیست.') })]);
    var sel = c.body.querySelector('select');
    if (sel) sel.setAttribute('data-ro-ok', '1');
    draw();
    return c;
  }

  function originCard() {
    var c = P.card({ title: t('باکت به‌عنوان مبدأ CDN'), icon: 'cloud', tone: 'muted', id: 'storage-origin' });
    var recs = ((S().site && S().site.records) || []).filter(function (r) { return r.proxied && r.storage; });
    append(c.body, [
      h('p', { text: t('یک رکورد پروکسی‌شده (مثلاً cdn.دامنهٔ شما) می‌تواند فایل‌هایش را مستقیماً از یک باکت بگیرد: باکت عمومی نمی‌شود، فقط نودهای CDN آن را می‌خوانند و کش، SSL و امنیت سایت روی آن اعمال می‌شود. دکمهٔ «مبدأ CDN» کنار هر باکت پنجرهٔ رکورد را آماده باز می‌کند.') }),
      recs.length ? h('ul', { className: 'pcdn-ul pcdn-st-origin-list' }, recs.map(function (r) {
        var host = !r.name || r.name === '@' ? S().site.domain : r.name + '.' + S().site.domain;
        return h('li', null, ltr('https://' + host + '/'), ' ' + P.arrow + ' ', t('باکت '), ltr(String(r.storage)));
      })) : h('p', { className: 'pcdn-help', text: t('هنوز رکوردی از باکت‌ها استفاده نمی‌کند.') })]);
    return c;
  }

  function render(Aa) {
    var wrap = h('div', { className: 'pcdn-stack pcdn-st', 'data-storage': '1' }, P.skeleton(4));
    load(true).then(function (res) {
      if (S().page !== 'storage') return;
      clear(wrap);
      if (!res.ok) { wrap.appendChild(P.errorBox(res, t('دریافت اطلاعات فضای ذخیره‌سازی ممکن نشد'))); return; }
      var d = res.data || {};
      if (d.available === false) {
        wrap.appendChild(P.empty('package', t('فضای ذخیره‌سازی هنوز راه‌اندازی نشده است'),
          t('این سرویس روی سامانه هنوز فعال نشده است. لطفاً بعداً دوباره سر بزنید یا با پشتیبانی تماس بگیرید.')));
        return;
      }
      var bs = Array.isArray(d.buckets) ? d.buckets : [];
      var max = Number(d.max_buckets) || 0, full = max > 0 && bs.length >= max;
      function reload() { A().renderMain(); }
      var add = P.btn(t('باکت جدید'), { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-st-add', disabled: full || !!d.over_quota,
        title: full ? t('به سقف ') + num(max) + t(' باکت رسیده‌اید') : d.over_quota ? t('فضای ذخیره‌سازی پر است') : null,
        onclick: function () { createDialog(reload); } });
      var list = P.card({ title: t('باکت‌ها'), icon: 'package', id: 'storage-buckets',
        subtitle: t('هر باکت فضایی جدا با کلید دسترسی مخصوص خودش است.'), actions: [add] });
      if (!bs.length) {
        list.body.appendChild(P.empty('package', t('هنوز باکتی نساخته‌اید'),
          t('یک باکت بسازید، فایل‌های سایت (تصاویر، ویدیو، فایل‌های دانلودی، پشتیبان‌ها) را با ابزارهای S3 در آن بگذارید و در صورت نیاز آن را مبدأ CDN کنید.')));
      } else {
        list.body.appendChild(h('ul', { className: 'pcdn-whs pcdn-st-buckets' }, bs.map(function (b) { return bucketItem(b, d, reload); })));
      }
      append(wrap, [usageCard(d), list, guideCard(d), originCard()]);
      Aa.lockWrites(wrap);
    });
    return wrap;
  }

  // ------------------------------------------------------------------ record dialog (app.js recordModal)

  /**
   * «مبدأ» choice of a proxied A/AAAA/CNAME record: its value (your server) or one of the site's buckets.
   * null when the controller / plan has no storage. Fetches the bucket list once (async redraw).
   */
  function recordFields(r, redraw) {
    var s = S().site;
    if (!enabled(s) && !r.storage) return null;
    var x = st();
    if (!x.data && !x.loading) load(false).then(function () { if (document.contains(box)) redraw(); });
    var names = buckets().map(function (b) { return b.name; });
    if (r.storage && names.indexOf(r.storage) < 0) names.unshift(r.storage);
    var box = h('div', { className: 'pcdn-rec-storage' });
    if (!names.length) {
      box.appendChild(h('p', { className: 'pcdn-help' }, icon('info'), x.loading ? t(' در حال دریافت باکت‌ها…') : t(' برای تحویل فایل‌ها از فضای ذخیره‌سازی، ابتدا در بخش «فضای ذخیره‌سازی» یک باکت بسازید.')));
      return box;
    }
    var opts = [[null, t('سرور شما (مقدار رکورد)')]].concat(names.map(function (n) { return [n, t('باکت ') + n]; }));
    box.appendChild(P.select(r, 'storage', t('مبدأ این رکورد'), opts, { cls: 'pcdn-rec-origin', onchange: function (v) {
      if (v) { r.pool = null; r.origin_port = null; }
      redraw();
    }, help: r.storage ? t('فایل‌ها از باکت تحویل داده می‌شوند. «مقدار» را می‌توانید خالی بگذارید (یک CNAME به نشانی فضای ذخیره‌سازی ثبت می‌شود)؛ برای ریشهٔ دامنه (@) نوع A با یک آی‌پی عمومی بدهید.')
      : t('برای تحویل فایل‌های یک باکت از CDN، باکت را انتخاب کنید.') }));
    return box;
  }
  /** Adds `storage` to a record body only when set (a proxied record with a bucket origin). */
  function recordBodyExtra(r, b) {
    if (b.proxied && r.storage) {
      b.storage = String(r.storage);
      b.pool = null;
      b.origin_port = null;
    }
    return b;
  }

  // ------------------------------------------------------------------ registry

  pages.storage = {
    title: t('فضای ذخیره‌سازی'), icon: 'package', heading: t('فضای ذخیره‌سازی ابری (S3)'),
    desc: t('فضای ذخیرهٔ فایل سازگار با S3 برای تصاویر، ویدیو، فایل‌های دانلودی و پشتیبان‌ها — با کلید دسترسی جدا برای هر باکت و امکان تحویل مستقیم از CDN.'),
    guide: {
      what: t('هر باکت فضایی جدا برای فایل‌هاست که با ابزارهای استاندارد S3 (aws-cli، rclone، s3cmd و SDKها) مدیریت می‌شود و می‌تواند مبدأ یک رکورد CDN باشد.'),
      when: t('وقتی می‌خواهید فایل‌های حجیم یا ایستا را از سرور سایت جدا کنید، پشتیبان بگیرید یا فایل‌ها را بدون سرور جداگانه از CDN تحویل دهید.'),
      rec: t('برای هر برنامه یا هدف یک باکت جدا بسازید، کلید مخفی را همان لحظه در جای امن ذخیره کنید و برای انتشار عمومی از «مبدأ CDN» استفاده کنید نه از نشانی مستقیم.'),
      mistakes: [t('گم کردن کلید مخفی (فقط یک بار نمایش داده می‌شود؛ کلید جدید بسازید).'), t('آدرس‌دهی virtual-host به‌جای path-style در ابزار S3.'),
        t('پر شدن سهمیه (نوشتن متوقف می‌شود تا فایل حذف یا پلن ارتقا داده شود).')]
    },
    upsell: t('با ارتقای پلن، فضای ذخیره‌سازی سازگار با S3 برای فایل‌های سایت می‌گیرید که مستقیماً از CDN هم تحویل داده می‌شود.'),
    hidden: function (s) { return !known(s); },
    lock: function (f) { return !(Number(f.storage_gb) > 0); },
    render: function (Aa) { return render(Aa); }
  };

  P.storage = {
    known: known, enabled: enabled, recordFields: recordFields, recordBodyExtra: recordBodyExtra,
    // exported for tests
    nameProblem: nameProblem, snippets: snippets
  };
})();
