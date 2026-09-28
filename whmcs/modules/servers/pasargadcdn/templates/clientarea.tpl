{* Pasargad CDN — client area. Everything is rendered by the scripts below from the
   JSON boot blob; all values are prepared (and JSON-escaped) in pasargadcdn_ClientArea().
   Fonts are bundled (assets/fonts, SIL OFL) — no external resources are loaded.
   Theme: the app adapts to the WHMCS theme automatically (light/dark, surfaces, primary
   colour, Persian font). To force one, add data-theme="light" or data-theme="dark" to the
   #pcdn-app div below (default: auto). *}
<link rel="stylesheet" href="{$pcdnCssUrl|escape}">
<div id="pcdn-app" class="pcdn" dir="rtl" lang="fa" data-api="{$pcdnApiUrl|escape}" data-csrf="{$pcdnCsrf|escape}">
  <noscript><div class="pcdn-alert pcdn-alert-danger">برای مدیریت CDN، جاوااسکریپت مرورگر را فعال کنید.</div></noscript>
  <div class="pcdn-boot-loading" role="status">در حال بارگذاری پنل CDN…</div>
</div>
<script type="application/json" id="pcdn-boot">{$pcdnBoot nofilter}</script>
{foreach $pcdnScripts as $pcdnScript}
<script src="{$pcdnScript|escape}" defer></script>
{/foreach}
