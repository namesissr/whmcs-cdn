/*
 * Pasargad CDN — client app: file manager for a storage bucket (SPEC §16.8, docs/STORAGE.md).
 *
 * Exposes PCDN.fileManager(bucket, overview) — a wide drawer with the bucket's files:
 *   - browse: folders and files of one prefix at a time (GET storage/buckets/<b>/objects), paged by
 *     the controller's continuation token, with a breadcrumb and «up»;
 *   - upload: the browser PUTs to the storage server DIRECTLY with a presigned URL the controller
 *     signs (POST .../objects/upload, or .../objects/multipart + /parts + /complete above
 *     MULTIPART_FROM). Nothing passes through WHMCS or the controller, so a 7 GB file costs them
 *     nothing; progress comes from the XHR itself and an upload can be cancelled (abort);
 *   - download: a presigned GET (POST .../objects/download), opened in a new tab with the file's own
 *     name forced by the controller;
 *   - link: the permanent CDN link when a proxied record serves this bucket (and a one-click way to
 *     create that record when none does), or an expiring presigned link (1 hour / 1 day / 7 days);
 *   - new folder, rename, delete (one, several, or a whole folder — POST .../objects/delete).
 *
 * No credential ever reaches this code: the only thing it holds is a URL for one object, good for
 * minutes. Names reach the DOM through textContent / createElement only (no innerHTML anywhere), and
 * every write button carries `write: true` so a read-only domain member sees them disabled.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, num = P.num;

  function A() { return P.app; }
  function S() { return P.app.S; }

  var MIB = 1048576;
  var MULTIPART_FROM = 32 * MIB;   // above this a file goes up in parts
  var PART = 32 * MIB;             // 7 GB / 32 MiB = 224 parts, well under the 1000 S3 allows
  var PART_URLS = 100;             // part URLs asked for per call (controller cap)
  var PARALLEL = 3;                // parts in flight
  var PAGE = 200;

  /** A file name as a key segment: no path separators, no control characters, never empty. */
  function safeName(name) {
    var n = String(name || '').replace(/[\\/\x00-\x1f\x7f]/g, '_').replace(/^\.+$/, '_').trim();
    return n || 'file';
  }
  function joinKey(prefix, name) { return String(prefix || '') + safeName(name); }
  function base(bucket) { return 'storage/buckets/' + encodeURIComponent(bucket) + '/objects'; }
  function extOf(key) { var m = /\.([A-Za-z0-9]{1,8})$/.exec(String(key || '')); return m ? m[1].toLowerCase() : ''; }

  // only icons ui.js actually has (ICONS)
  var ICON_BY_EXT = {
    jpg: 'image', jpeg: 'image', png: 'image', gif: 'image', webp: 'image', avif: 'image', svg: 'image',
    mp4: 'play', webm: 'play', mkv: 'play', mov: 'play', mp3: 'play', wav: 'play', ogg: 'play',
    pdf: 'fileText', txt: 'fileText', md: 'fileText', csv: 'fileText', json: 'code', xml: 'code',
    js: 'code', css: 'code', html: 'code', zip: 'package', gz: 'package', tar: 'package', rar: 'package',
    '7z': 'package'
  };
  function fileIcon(key) { return ICON_BY_EXT[extOf(key)] || 'fileText'; }

  // ------------------------------------------------------------------ uploads

  /** One PUT with progress and cancellation. Resolves {ok, status, etag}. */
  function put(url, body, onProgress, register) {
    return new Promise(function (resolve) {
      var xhr = new XMLHttpRequest();
      xhr.open('PUT', url, true);
      if (xhr.upload && onProgress) {
        xhr.upload.onprogress = function (e) { if (e.lengthComputable) onProgress(e.loaded, e.total); };
      }
      xhr.onload = function () {
        resolve({ ok: xhr.status >= 200 && xhr.status < 300, status: xhr.status,
          etag: String(xhr.getResponseHeader('ETag') || '').replace(/"/g, '') });
      };
      xhr.onerror = function () { resolve({ ok: false, status: 0 }); };
      xhr.onabort = function () { resolve({ ok: false, status: 0, aborted: true }); };
      if (register) register(xhr);
      xhr.send(body);
    });
  }

  /**
   * One upload job: {file, key, done, total, state, error, cancel()}. `tick` is called on progress so
   * the drawer can redraw one row without re-rendering the listing.
   */
  function uploadJob(bucket, key, file, tick) {
    var job = { key: key, name: file.name, total: file.size, done: 0, state: 'wait', error: '',
      xhrs: [], cancelled: false, upload_id: '' };
    job.cancel = function () {
      job.cancelled = true;
      job.state = 'cancelled';
      job.xhrs.forEach(function (x) { try { x.abort(); } catch (e) { /* ignore */ } });
      if (job.upload_id) {
        P.api('POST', base(bucket) + '/multipart/abort', { key: job.key, upload_id: job.upload_id });
      }
      tick();
    };
    function fail(msg) { job.state = 'error'; job.error = msg || t('آپلود ناموفق بود'); tick(); return job; }
    function reg(x) { job.xhrs.push(x); }

    job.run = function () {
      job.state = 'running';
      tick();
      if (file.size <= MULTIPART_FROM) {
        return P.api('POST', base(bucket) + '/upload',
          { key: job.key, size: file.size, content_type: file.type || '' }).then(function (res) {
          if (job.cancelled) return job;
          if (!res.ok || !res.data || !res.data.url) return fail(P.errorText(res));
          return put(res.data.url, file, function (loaded) { job.done = loaded; tick(); }, reg)
            .then(function (r) {
              if (job.cancelled) return job;
              if (!r.ok) return fail(r.status ? t('سرور ذخیره‌سازی آپلود را نپذیرفت (کد ') + num(r.status) + ')'
                : t('اتصال به سرور ذخیره‌سازی قطع شد'));
              job.done = job.total;
              job.state = 'done';
              tick();
              return job;
            });
        });
      }
      // multipart: ask for the first batch of part URLs, upload PARALLEL at a time, ask for more
      var parts = Math.ceil(file.size / PART);
      return P.api('POST', base(bucket) + '/multipart',
        { key: job.key, size: file.size, content_type: file.type || '', parts: Math.min(PART_URLS, parts) })
        .then(function (res) {
          if (job.cancelled) return job;
          if (!res.ok || !res.data || !res.data.upload_id) return fail(P.errorText(res));
          job.key = res.data.key || job.key;
          job.upload_id = res.data.upload_id;
          var urls = {};
          (res.data.urls || []).forEach(function (u) { urls[u.part] = u.url; });
          var etags = [], loaded = {}, next = 1, failed = '';

          function progress() {
            var sum = 0;
            Object.keys(loaded).forEach(function (k) { sum += loaded[k]; });
            job.done = Math.min(job.total, sum);
            tick();
          }
          function urlFor(n) {
            if (urls[n]) return Promise.resolve(urls[n]);
            return P.api('POST', base(bucket) + '/multipart/parts',
              { key: job.key, upload_id: job.upload_id, first: n, count: Math.min(PART_URLS, parts - n + 1) })
              .then(function (r) {
                if (!r.ok || !r.data) return '';
                (r.data.urls || []).forEach(function (u) { urls[u.part] = u.url; });
                return urls[n] || '';
              });
          }
          function one() {
            if (failed || job.cancelled || next > parts) return Promise.resolve();
            var n = next++;
            return urlFor(n).then(function (url) {
              if (!url) { failed = t('گرفتن نشانی بخش آپلود ناموفق بود'); return; }
              var chunk = file.slice((n - 1) * PART, Math.min(file.size, n * PART));
              return put(url, chunk, function (x) { loaded[n] = x; progress(); }, reg).then(function (r) {
                if (job.cancelled) return;
                if (!r.ok || !r.etag) { failed = r.status ? t('بخشی از فایل آپلود نشد (کد ') + num(r.status) + ')' : t('اتصال به سرور ذخیره‌سازی قطع شد'); return; }
                loaded[n] = chunk.size;
                progress();
                etags.push({ part: n, etag: r.etag });
                return one();
              });
            });
          }
          var lanes = [];
          for (var i = 0; i < PARALLEL; i++) lanes.push(one());
          return Promise.all(lanes).then(function () {
            if (job.cancelled) return job;
            if (failed) {
              P.api('POST', base(bucket) + '/multipart/abort', { key: job.key, upload_id: job.upload_id });
              return fail(failed);
            }
            return P.api('POST', base(bucket) + '/multipart/complete',
              { key: job.key, upload_id: job.upload_id, parts: etags }).then(function (r) {
              if (!r.ok) return fail(P.errorText(r));
              job.done = job.total;
              job.state = 'done';
              job.upload_id = '';
              tick();
              return job;
            });
          });
        });
    };
    return job;
  }

  // ------------------------------------------------------------------ the drawer

  function fileManager(bucket, overview) {
    var name = String((bucket && bucket.name) || bucket || '');
    var st = { prefix: '', page: null, token: null, loading: false, error: null, sel: {},
      jobs: [], publicBase: null, maxUpload: 0 };
    var listHolder = h('div', { className: 'pcdn-fm-list' });
    var upHolder = h('div', { className: 'pcdn-fm-uploads' });
    var crumbs = h('nav', { className: 'pcdn-fm-crumbs', 'aria-label': t('مسیر') });
    var tools = h('div', { className: 'pcdn-fm-tools' });
    var fileInput = h('input', { type: 'file', multiple: true, className: 'pcdn-hidden',
      onchange: function () { addFiles(this.files); this.value = ''; } });

    var d = P.dialog({
      title: t('فایل‌های باکت ') + name, icon: 'package', kind: 'drawer', wide: true,
      subtitle: t('آپلود، دانلود و ساخت لینک — فایل‌ها مستقیم بین مرورگر شما و سرور ذخیره‌سازی جابه‌جا می‌شوند.')
    });
    append(d.body, [tools, crumbs, upHolder, listHolder, fileInput]);
    d.foot.appendChild(P.btn(t('بستن'), { onclick: function () { d.close(); } }));
    if (A().lockWrites) A().lockWrites(d.el);

    // -- data

    function fetchPage(prefix, token) {
      st.loading = true;
      st.error = null;
      draw();
      var q = 'prefix=' + encodeURIComponent(prefix || '') + '&limit=' + PAGE + (token ? '&token=' + encodeURIComponent(token) : '');
      return P.api('GET', base(name) + '?' + q).then(function (res) {
        st.loading = false;
        if (!res.ok || !res.data) { st.error = res; draw(); return; }
        var data = res.data;
        if (token && st.page) {   // another page of the same folder
          st.page.folders = (st.page.folders || []).concat(data.folders || []);
          st.page.objects = (st.page.objects || []).concat(data.objects || []);
          st.page.next_token = data.next_token;
        } else {
          st.page = data;
          st.sel = {};
        }
        st.prefix = data.prefix || '';
        st.token = data.next_token || null;
        st.publicBase = data.public_base || null;
        st.maxUpload = Number(data.max_upload_bytes) || 0;
        draw();
      });
    }
    function reload() { return fetchPage(st.prefix, ''); }
    function go(prefix) { st.token = null; return fetchPage(prefix, ''); }

    // -- actions

    function addFiles(files) {
      var list = Array.prototype.slice.call(files || []);
      if (!list.length) return;
      var tooBig = st.maxUpload ? list.filter(function (f) { return f.size > st.maxUpload; }) : [];
      if (tooBig.length) {
        P.toast(t('این فایل‌ها از سقف ') + P.bytes(st.maxUpload) + t(' بزرگ‌ترند و آپلود نمی‌شوند: ')
          + tooBig.map(function (f) { return f.name; }).join('، '), 'error');
        list = list.filter(function (f) { return f.size <= st.maxUpload; });
      }
      list.forEach(function (f) {
        var job = uploadJob(name, joinKey(st.prefix, f.name), f, drawUploads);
        st.jobs.push(job);
      });
      drawUploads();
      runQueue();
    }
    var running = false;
    function runQueue() {
      if (running) return;
      var next = st.jobs.filter(function (j) { return j.state === 'wait'; })[0];
      if (!next) {
        if (st.jobs.some(function (j) { return j.state === 'done'; })) reload();
        return;
      }
      running = true;
      next.run().then(function () {
        running = false;
        runQueue();
      });
    }

    function newFolder() {
      var model = { name: '' };
      var dd = P.dialog({ title: t('پوشهٔ جدید'), icon: 'plus' });
      var err = h('div');
      var input = P.input(model, 'name', t('نام پوشه'), { ltr: true, maxlength: 120, placeholder: 'images' });
      append(dd.body, [input, err]);
      var ok = P.btn(t('ساخت پوشه'), { kind: 'primary', write: true, onclick: function () {
        clear(err);
        var v = safeName(model.name);
        if (!model.name.trim()) { err.appendChild(P.alertBox('danger', t('نام پوشه را وارد کنید.'))); return; }
        P.busy(ok, P.api('POST', base(name) + '/folder', { key: st.prefix + v })).then(function (res) {
          if (!res.ok) { err.appendChild(P.errorBox(res, t('پوشه ساخته نشد'))); return; }
          dd.close(true);
          P.toast(t('پوشه ساخته شد.'));
          reload();
        });
      } });
      append(dd.foot, [P.btn(t('انصراف'), { onclick: function () { dd.close(); } }), ok]);
      dd.focusFirst();
      if (A().lockWrites) A().lockWrites(dd.el);
    }

    function rename(obj) {
      var model = { name: obj.name };
      var dd = P.dialog({ title: t('تغییر نام'), icon: 'edit' });
      var err = h('div');
      append(dd.body, [P.input(model, 'name', t('نام تازه'), { ltr: true, maxlength: 255 }), err]);
      var ok = P.btn(t('تغییر نام'), { kind: 'primary', write: true, onclick: function () {
        clear(err);
        var v = safeName(model.name);
        if (!model.name.trim() || v === obj.name) { dd.close(); return; }
        P.busy(ok, P.api('POST', base(name) + '/rename', { key: obj.key, to: st.prefix + v })).then(function (res) {
          if (!res.ok) { err.appendChild(P.errorBox(res, t('نام تغییر نکرد'))); return; }
          dd.close(true);
          reload();
        });
      } });
      append(dd.foot, [P.btn(t('انصراف'), { onclick: function () { dd.close(); } }), ok]);
      dd.focusFirst();
      if (A().lockWrites) A().lockWrites(dd.el);
    }

    function download(obj, btn) {
      P.busy(btn, P.api('POST', base(name) + '/download', { key: obj.key })).then(function (res) {
        if (!res.ok || !res.data || !res.data.url) { P.toast(t('نشانی دانلود ساخته نشد: ') + P.errorText(res), 'error'); return; }
        var w = window.open(res.data.url, '_blank');
        if (!w) P.toast(t('مرورگر پنجرهٔ دانلود را بست؛ از «لینک» استفاده کنید.'), 'warning');
      });
    }

    /** Permanent CDN link when a record serves the bucket, otherwise an expiring signed link. */
    function linkDialog(obj) {
      var dd = P.dialog({ title: t('لینک دانلود'), icon: 'link', subtitle: obj.name });
      var holder = h('div');
      append(dd.body, holder);
      function drawLink() {
        clear(holder);
        if (st.publicBase) {
          append(holder, [
            P.alertBox('success', t('این باکت مبدأ CDN است، پس لینک زیر دائمی است و از لبه‌ها (با کش) تحویل داده می‌شود.')),
            P.copyable(st.publicBase + '/' + obj.key, { label: t('کپی لینک دائمی') })]);
        } else {
          append(holder, [
            P.alertBox('info', [t('برای لینک دائمی، این باکت را مبدأ یک زیردامنه کنید (مثلاً '),
              h('code', { text: 'files.' + ((S().site && S().site.domain) || 'example.com') }),
              t('). تا آن زمان می‌توانید لینک موقت بسازید.')]),
            P.btn(t('ساخت زیردامنه برای این باکت'), { icon: 'cloud', write: true, cls: 'pcdn-fm-mkorigin',
              onclick: function () {
                dd.close(true);
                d.close(true);
                if (P.storage && P.storage.useAsOrigin) P.storage.useAsOrigin({ name: name });
              } })]);
        }
        var pick = { ttl: '3600' };
        var row = h('div', { className: 'pcdn-fm-ttl' });
        var out = h('div');
        var make = P.btn(t('ساخت لینک موقت'), { icon: 'key', onclick: function () {
          clear(out);
          P.busy(make, P.api('POST', base(name) + '/download',
            { key: obj.key, expires_in: Number(pick.ttl), attachment: false })).then(function (res) {
            if (!res.ok || !res.data) { out.appendChild(P.errorBox(res, t('لینک ساخته نشد'))); return; }
            append(out, [P.copyable(res.data.url, { label: t('کپی لینک موقت') }),
              h('p', { className: 'pcdn-help', text: t('این لینک پس از ') + P.dur(Number(res.data.expires_in) || 0) + t(' از کار می‌افتد و فقط همین یک فایل را می‌دهد.') })]);
          });
        } });
        append(row, [P.select(pick, 'ttl', t('اعتبار لینک موقت'),
          [['3600', t('۱ ساعت')], ['86400', t('۱ روز')], ['604800', t('۷ روز')]], { cls: 'pcdn-fm-ttl-pick' }), make]);
        append(holder, [h('hr', { className: 'pcdn-sep' }), row, out]);
      }
      drawLink();
      dd.foot.appendChild(P.btn(t('بستن'), { onclick: function () { dd.close(); } }));
      dd.focusFirst();
      if (A().lockWrites) A().lockWrites(dd.el);
    }

    function removeItems(keys, prefixes, label) {
      var count = keys.length + prefixes.length;
      P.confirm({ title: t('حذف'), danger: true, ok: t('حذف'),
        body: h('div', null,
          h('p', { text: prefixes.length ? t('پوشه و همهٔ فایل‌های داخلش برای همیشه حذف می‌شود: ') + label
            : t('این فایل‌ها برای همیشه حذف می‌شوند: ') + label }),
          h('p', { className: 'pcdn-warn-text', text: t('این کار قابل بازگشت نیست.') })) })
        .then(function (ok) {
          if (!ok) return;
          P.api('POST', base(name) + '/delete', { keys: keys, prefixes: prefixes }).then(function (res) {
            if (!res.ok || !res.data) { P.toast(t('حذف ناموفق بود: ') + P.errorText(res), 'error'); return; }
            var deleted = Number(res.data.deleted) || 0;
            P.toast(deleted ? num(deleted) + t(' مورد حذف شد.') : t('چیزی حذف نشد.'),
              deleted ? 'success' : 'warning');
            if (res.data.truncated) P.toast(t('پوشه فایل‌های بیشتری داشت؛ برای حذف کامل دوباره بزنید.'), 'warning');
            reload();
          });
        });
      return count;
    }

    // -- rendering

    function drawTools() {
      clear(tools);
      var up = P.btn(t('آپلود فایل'), { kind: 'primary', icon: 'upload', write: true, cls: 'pcdn-fm-upload',
        onclick: function () { fileInput.click(); } });
      var mk = P.btn(t('پوشهٔ جدید'), { icon: 'plus', write: true, cls: 'pcdn-fm-mkdir', onclick: newFolder });
      var ref = P.iconBtn('refresh', t('به‌روزرسانی'), function () { reload(); });
      ref.setAttribute('data-ro-ok', '1');
      var selected = Object.keys(st.sel).filter(function (k) { return st.sel[k]; });
      var del = selected.length ? P.btn(t('حذف ') + num(selected.length) + t(' مورد'),
        { icon: 'trash', kind: 'danger', write: true, cls: 'pcdn-fm-delsel',
          onclick: function () { removeItems(selected, [], selected.map(function (k) { return k.split('/').pop(); }).join('، ')); } }) : null;
      append(tools, [up, mk, del, ref,
        st.maxUpload ? h('span', { className: 'pcdn-muted pcdn-fm-cap',
          text: t('سقف هر فایل: ') + P.bytes(st.maxUpload) }) : null]);
    }

    function drawCrumbs() {
      clear(crumbs);
      var parts = st.prefix ? st.prefix.replace(/\/$/, '').split('/') : [];
      var root = P.btn(t('ریشه'), { size: 'sm', cls: 'pcdn-fm-crumb', onclick: function () { go(''); } });
      root.setAttribute('data-ro-ok', '1');
      append(crumbs, root);
      var acc = '';
      parts.forEach(function (seg, i) {
        acc += seg + '/';
        var here = acc;
        crumbs.appendChild(h('span', { className: 'pcdn-fm-sep', text: ' / ' }));
        if (i === parts.length - 1) {
          crumbs.appendChild(h('strong', { className: 'pcdn-fm-crumb is-current', dir: 'ltr', text: seg }));
        } else {
          var b = P.btn(seg, { size: 'sm', cls: 'pcdn-fm-crumb', onclick: function () { go(here); } });
          b.setAttribute('data-ro-ok', '1');
          crumbs.appendChild(b);
        }
      });
    }

    function drawUploads() {
      clear(upHolder);
      var jobs = st.jobs.filter(function (j) { return j.state !== 'done' || j.keepVisible; });
      if (!st.jobs.length) return;
      var active = st.jobs.filter(function (j) { return j.state === 'running' || j.state === 'wait'; });
      var card = P.card({ title: t('آپلودها'), icon: 'upload', id: 'fm-uploads',
        actions: active.length ? null : P.btn(t('پاک‌کردن فهرست'), { size: 'sm', cls: 'pcdn-fm-clearq',
          onclick: function () { st.jobs = []; drawUploads(); } }) });
      st.jobs.forEach(function (j) {
        var pctv = j.total ? Math.min(1, j.done / j.total) : 0;
        var tone = j.state === 'error' ? 'danger' : j.state === 'done' ? 'success' : j.state === 'cancelled' ? 'muted' : 'brand';
        var label = j.state === 'done' ? t('انجام شد') : j.state === 'error' ? j.error
          : j.state === 'cancelled' ? t('لغو شد') : j.state === 'wait' ? t('در نوبت')
            : P.bytes(j.done) + t(' از ') + P.bytes(j.total) + ' · ' + P.pct(j.done, j.total || 1);
        append(card.body, h('div', { className: 'pcdn-fm-job pcdn-tone-' + tone },
          h('div', { className: 'pcdn-fm-job-head' },
            h('span', { className: 'pcdn-fm-job-name', dir: 'ltr', text: j.name }),
            h('span', { className: 'pcdn-muted', text: label }),
            j.state === 'running' || j.state === 'wait'
              ? P.iconBtn('x', t('لغو آپلود ') + j.name, function () { j.cancel(); }, { cls: 'pcdn-fm-cancel' }) : null),
          j.state === 'running' || j.state === 'wait' ? P.meter(pctv, 'brand') : null));
      });
      upHolder.appendChild(card);
      void jobs;
    }

    function row(item, isFolder) {
      var key = item.key;
      var cb = h('input', { type: 'checkbox', className: 'pcdn-fm-cb', 'aria-label': t('انتخاب ') + item.name,
        checked: !!st.sel[key], onchange: function () { st.sel[key] = this.checked; drawTools(); } });
      var cells = [h('span', { className: 'pcdn-fm-ico' }, icon(isFolder ? 'package' : fileIcon(key)))];
      if (isFolder) {
        var open = P.btn(item.name, { size: 'sm', cls: 'pcdn-fm-name is-folder', onclick: function () { go(key); } });
        open.setAttribute('data-ro-ok', '1');
        open.setAttribute('dir', 'ltr');
        cells.push(open, h('span', { className: 'pcdn-muted pcdn-fm-meta', text: t('پوشه') }));
      } else {
        cells.push(h('span', { className: 'pcdn-fm-name', dir: 'ltr', text: item.name }),
          h('span', { className: 'pcdn-muted pcdn-fm-meta' },
            h('bdi', { text: P.bytes(Number(item.size) || 0) }),
            item.modified ? h('span', { text: ' · ' + P.date(item.modified) }) : null));
      }
      var acts = h('div', { className: 'pcdn-fm-acts' });
      if (isFolder) {
        var dfl = P.iconBtn('trash', t('حذف پوشهٔ ') + item.name, function () {
          removeItems([], [key], item.name);
        }, { write: true, cls: 'is-danger' });
        acts.appendChild(dfl);
      } else {
        var dl = P.iconBtn('download', t('دانلود ') + item.name, function () { download(item, dl); }, { cls: 'pcdn-fm-dl' });
        dl.setAttribute('data-ro-ok', '1');
        var lk = P.iconBtn('link', t('لینک ') + item.name, function () { linkDialog(item); }, { cls: 'pcdn-fm-link' });
        lk.setAttribute('data-ro-ok', '1');
        var rn = P.iconBtn('edit', t('تغییر نام ') + item.name, function () { rename(item); }, { write: true });
        var df = P.iconBtn('trash', t('حذف ') + item.name, function () { removeItems([key], [], item.name); },
          { write: true, cls: 'is-danger' });
        append(acts, [dl, lk, rn, df]);
      }
      return h('div', { className: 'pcdn-fm-row' + (isFolder ? ' is-folder' : ''), 'data-key': key },
        h('label', { className: 'pcdn-fm-pick' }, cb), h('div', { className: 'pcdn-fm-cells' }, cells), acts);
    }

    function drawList() {
      clear(listHolder);
      if (st.error) { listHolder.appendChild(P.errorBox(st.error, t('فهرست فایل‌ها خوانده نشد'))); return; }
      if (!st.page) { listHolder.appendChild(P.skeleton(3)); return; }
      var folders = st.page.folders || [], objects = st.page.objects || [];
      if (!folders.length && !objects.length) {
        listHolder.appendChild(P.empty('package', t('این پوشه خالی است'),
          t('با «آپلود فایل» اولین فایل را بگذارید؛ می‌توانید فایل‌ها را روی همین پنجره هم رها کنید.')));
        return;
      }
      folders.forEach(function (f) { listHolder.appendChild(row(f, true)); });
      objects.forEach(function (o) { listHolder.appendChild(row(o, false)); });
      if (st.token) {
        var more = P.btn(t('نمایش فایل‌های بیشتر'), { cls: 'pcdn-fm-more',
          onclick: function () { P.busy(more, fetchPage(st.prefix, st.token)); } });
        more.setAttribute('data-ro-ok', '1');
        listHolder.appendChild(more);
      }
      if (st.loading) listHolder.appendChild(P.skeleton(1));
    }

    function draw() {
      drawTools();
      drawCrumbs();
      drawUploads();
      drawList();
    }

    // drag & drop onto the drawer
    ['dragenter', 'dragover'].forEach(function (ev) {
      d.el.addEventListener(ev, function (e) { e.preventDefault(); d.el.classList.add('is-dropping'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      d.el.addEventListener(ev, function (e) {
        e.preventDefault();
        d.el.classList.remove('is-dropping');
        if (ev === 'drop' && e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
      });
    });

    st.maxUpload = Number(overview && overview.max_upload_bytes) || 0;
    draw();
    go('');
    return d;
  }

  P.fileManager = fileManager;
  P.fmInternals = { safeName: safeName, joinKey: joinKey, fileIcon: fileIcon, MULTIPART_FROM: MULTIPART_FROM, PART: PART };
})();
