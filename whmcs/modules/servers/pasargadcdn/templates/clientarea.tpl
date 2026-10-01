{* Pasargad CDN — client area. Everything is rendered by the scripts below from the
   JSON boot blob; all values are prepared (and JSON-escaped) in pasargadcdn_ClientArea().
   Fonts are bundled (assets/fonts, SIL OFL) — no external resources are loaded.
   Theme: the app adapts to the WHMCS theme automatically (light/dark, surfaces, primary
   colour, Persian font). To force one, add data-theme="light" or data-theme="dark" to the
   #pcdn-app div below (default: auto).
   Language (SPEC §16.10): Persian (RTL) or English (LTR) from the WHMCS client language or the
   viewer's in-app choice — pasargadcdn_lang(); the app's strings live in assets/i18n*.js. *}
<link rel="stylesheet" href="{$pcdnCssUrl|escape}">
<div id="pcdn-app" class="pcdn" dir="{$pcdnDir|escape}" lang="{$pcdnLang|escape}" data-api="{$pcdnApiUrl|escape}" data-csrf="{$pcdnCsrf|escape}">
  <noscript><div class="pcdn-alert pcdn-alert-danger">{$pcdnNoJs|escape}</div></noscript>
  <div class="pcdn-boot-loading" role="status">{$pcdnLoading|escape}</div>
</div>
<script type="application/json" id="pcdn-boot">{$pcdnBoot nofilter}</script>
{foreach $pcdnScripts as $pcdnScript}
<script src="{$pcdnScript|escape}" defer></script>
{/foreach}
