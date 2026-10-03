/* Pasargad CDN real user monitoring (SPEC §23.7). No cookies, no storage, no identifiers: one beacon
   per sampled page view to /__pcdn/rum on this site. data-s = sample rate, data-spa="1" = soft navigations. */
(function (w, d) {
  var s = d.currentScript, P = w.performance, O = w.PerformanceObserver;
  var rate = parseFloat(s && s.getAttribute('data-s'));
  if (!(rate > 0) || Math.random() >= rate || !P || !O || !P.getEntriesByType) return;
  var spa = s.getAttribute('data-spa') === '1', soft = 0, sent = 0, lcpOn = 1;
  var m = {}, inp = 0, cls = 0, win = 0, wFirst = 0, wLast = 0, act = 0;
  var path = function () { return String(location.pathname || '/').slice(0, 200); }, p = path();
  var r = function (v) { return Math.max(0, Math.round(v)); };
  var nav = P.getEntriesByType('navigation')[0];
  if (nav) {
    act = nav.activationStart || 0;
    m.ttfb = r(nav.responseStart - act);
    m.dns = r(nav.domainLookupEnd - nav.domainLookupStart);
    m.tcp = r(nav.connectEnd - nav.connectStart);
    m.tls = nav.secureConnectionStart > 0 ? r(nav.connectEnd - nav.secureConnectionStart) : 0;
    m.dom = r(nav.domInteractive - act);
    m.nt = act > 0 ? 'prerender' : (nav.type || 'navigate').replace('-', '_');
    (nav.serverTiming || []).forEach(function (t) {
      var c = String(t.description || '').toUpperCase();
      if (t.name === 'cdn-cache' && /^(HIT|MISS|BYPASS|EXPIRED|STALE)$/.test(c)) m.cs = c;
    });
  }
  var obs = function (type, fn, opt) {
    try {
      var o = new O(function (l) { l.getEntries().forEach(fn); });
      opt = opt || {};
      opt.type = type;
      opt.buffered = true;
      o.observe(opt);
    } catch (e) { /* entry type not supported */ }
  };
  obs('paint', function (e) { if (e.name === 'first-contentful-paint') m.fcp = r(e.startTime - act); });
  obs('largest-contentful-paint', function (e) { if (lcpOn) m.lcp = r(e.startTime - act); });
  obs('layout-shift', function (e) {
    if (e.hadRecentInput) return;
    if (win && e.startTime - wLast < 1000 && e.startTime - wFirst < 5000) win += e.value;
    else { win = e.value; wFirst = e.startTime; }
    wLast = e.startTime;
    if (win > cls) cls = win;
  });
  obs('event', function (e) { if (e.interactionId && e.duration > inp) inp = e.duration; }, { durationThreshold: 40 });
  ['keydown', 'pointerdown'].forEach(function (t) {
    d.addEventListener(t, function () { lcpOn = 0; }, { once: true, capture: true });
  });
  var send = function () {
    lcpOn = 0;
    if (sent) return;
    sent = 1;
    var mm = w.matchMedia, b = { v: 1, p: p, dev: mm && mm('(max-width: 767px)').matches ? 'm'
      : mm && mm('(max-width: 1024px)').matches ? 't' : 'd' };
    if (soft) b.nt = 'soft';
    else {
      for (var k in m) b[k] = m[k];
      if (nav && nav.loadEventEnd > 0) b.load = r(nav.loadEventEnd - act);
    }
    if (inp) b.inp = r(inp);
    b.cls = Math.round(cls * 10000) / 10000;
    var body = JSON.stringify(b);
    try { if (navigator.sendBeacon && navigator.sendBeacon('/__pcdn/rum', body)) return; } catch (e) { /* fall back */ }
    try {
      fetch('/__pcdn/rum', { method: 'POST', body: body, keepalive: true, credentials: 'omit',
        headers: { 'Content-Type': 'text/plain' } });
    } catch (e) { /* best effort */ }
  };
  var next = function () {
    if (path() === p) return;
    send();
    soft = 1; sent = 0; inp = 0; cls = 0; win = 0; p = path();
  };
  d.addEventListener('visibilitychange', function () { if (d.visibilityState === 'hidden') send(); });
  w.addEventListener('pagehide', send);
  if (spa && w.history && history.pushState) {
    var push = history.pushState;
    history.pushState = function () { var x = push.apply(this, arguments); next(); return x; };
    w.addEventListener('popstate', next);
  }
})(window, document);
