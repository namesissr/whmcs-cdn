{* Pasargad CDN — client area. Everything is rendered by assets/app.js from the
   JSON below; all values are prepared (and JSON-escaped) in pasargadcdn_ClientArea(). *}
<link rel="stylesheet" href="{$pcdnCssUrl|escape}">
<div id="pcdn-app" class="pcdn" dir="rtl" data-api="{$pcdnApiUrl|escape}" data-csrf="{$pcdnCsrf|escape}">
  <noscript><div class="pcdn-alert pcdn-alert-danger">برای مدیریت CDN، جاوااسکریپت مرورگر را فعال کنید.</div></noscript>
  <div class="pcdn-loading">در حال بارگذاری…</div>
</div>
<script type="application/json" id="pcdn-boot">{$pcdnBoot nofilter}</script>
<script src="{$pcdnJsUrl|escape}" defer></script>
