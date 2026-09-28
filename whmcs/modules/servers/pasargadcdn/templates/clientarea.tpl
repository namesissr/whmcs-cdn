{* Pasargad CDN — client area (RTL, Bootstrap 4 / twenty-one theme) *}
{assign var=action value="clientarea.php?action=productdetails&id=`$serviceid`&modop=custom&a="}

<style>
  .pcdn { direction: rtl; text-align: right; }
  .pcdn .ltr { direction: ltr; text-align: left; unicode-bidi: embed; }
  .pcdn .stat { border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px; height: 100%; }
  .pcdn .stat b { display: block; font-size: 1.25rem; margin-top: 4px; }
  .pcdn table td, .pcdn table th { vertical-align: middle; }
  .pcdn .cloud-on { color: #f97316; font-weight: bold; }
  .pcdn .cloud-off { color: #9ca3af; }
  .pcdn .card { margin-bottom: 18px; }
  .pcdn code { word-break: break-all; }
</style>

<div class="pcdn">
{if $error}
  <div class="alert alert-danger">خطا در دریافت اطلاعات CDN: {$error|escape}</div>
{elseif $site}

  {* ---------- status ---------- *}
  {if $site.status == 'pending_ns'}
    <div class="alert alert-warning">
      <strong>در انتظار تغییر نیم‌سرورها.</strong>
      برای فعال شدن CDN، نیم‌سرورهای (NS) دامنه <span class="ltr">{$site.domain|escape}</span> را در پنل ثبت‌کننده دامنه به موارد زیر تغییر دهید:
      <ul class="ltr mb-2 mt-2">
        {foreach $site.nameservers as $ns}<li><code>{$ns|escape}</code></li>{/foreach}
      </ul>
      {if $view.nsFound}<small>نیم‌سرورهای فعلی: <span class="ltr">{$view.nsFound|escape}</span></small><br>{/if}
      <small>پیش از تغییر، رکوردهای DNS فعلی خود (ایمیل، زیردامنه‌ها و ...) را در بخش «رکوردهای DNS» وارد کنید.</small>
      {if $active}
      <form method="post" action="{$action}checkNs" class="mt-2">
        <input type="hidden" name="pcdn_csrf" value="{$csrf}">{if $token}<input type="hidden" name="token" value="{$token}">{/if}
        <button class="btn btn-sm btn-warning">بررسی مجدد</button>
      </form>
      {/if}
    </div>
  {elseif $site.status == 'suspended'}
    <div class="alert alert-danger">این سرویس معلق است و بازدیدکنندگان صفحه تعلیق را می‌بینند.</div>
  {elseif $site.status == 'over_quota'}
    <div class="alert alert-danger">ترافیک ماهانه این سرویس تمام شده است. برای ادامه، سرویس را ارتقا دهید.</div>
  {else}
    <div class="alert alert-success">CDN برای <span class="ltr">{$site.domain|escape}</span> فعال است.</div>
  {/if}

  {* ---------- stats ---------- *}
  <div class="row mb-3">
    <div class="col-md-3 col-6 mb-2"><div class="stat">ترافیک این ماه
      <b class="ltr">{$site.usage_month.gb} GB</b>
      <small>{if $site.plan.bandwidth_limit_gb > 0}از {$site.plan.bandwidth_limit_gb} GB{else}نامحدود{/if}</small>
      {if $site.plan.bandwidth_limit_gb > 0}
      <div class="progress mt-1" style="height:6px"><div class="progress-bar {if $view.usagePercent >= 90}bg-danger{/if}" style="width:{$view.usagePercent}%"></div></div>
      {/if}
    </div></div>
    <div class="col-md-3 col-6 mb-2"><div class="stat">درخواست‌ها<b class="ltr">{$view.requests}</b></div></div>
    <div class="col-md-3 col-6 mb-2"><div class="stat">نرخ کش
      <b class="ltr">{$view.hitRatio}</b></div></div>
    <div class="col-md-3 col-6 mb-2"><div class="stat">SSL
      <b>{if $site.ssl.status == 'active'}فعال{elseif $site.ssl.status == 'pending'}در حال صدور{elseif $site.ssl.status == 'failed'}ناموفق{else}غیرفعال{/if}</b>
      {if $view.sslExpires}<small class="ltr">{$view.sslExpires}</small>{/if}
    </div></div>
  </div>

  {* ---------- DNS records ---------- *}
  <div class="card">
    <div class="card-header"><strong>رکوردهای DNS</strong>
      <small class="text-muted">({$view.recordCount} از {$site.plan.max_records})</small></div>
    <div class="card-body">
      <p class="text-muted small mb-2">
        <span class="cloud-on">☁ پروکسی (CDN)</span>: ترافیک از طریق سرورهای CDN عبور می‌کند و IP اصلی سرور شما مخفی می‌ماند (فقط برای A، AAAA و CNAME).
        <span class="cloud-off">☁ فقط DNS</span>: رکورد بدون تغییر پاسخ داده می‌شود.
      </p>
      <div class="table-responsive">
      <table class="table table-sm table-striped">
        <thead><tr><th>نوع</th><th>نام</th><th>مقدار</th><th>TTL</th><th>CDN</th><th></th></tr></thead>
        <tbody>
        {foreach $site.records as $r}
          <tr>
            <td><span class="badge badge-secondary">{$r.type}</span></td>
            <td class="ltr">{$r.name|escape}</td>
            <td class="ltr"><code>{if $r.priority !== null}{$r.priority} {/if}{$r.content|escape}</code></td>
            <td class="ltr">{$r.ttl}</td>
            <td>{if $r.proxied}<span class="cloud-on" title="Proxied">☁</span>{else}<span class="cloud-off" title="DNS only">☁</span>{/if}</td>
            <td class="text-nowrap">
              {if $active}
              <button type="button" class="btn btn-xs btn-sm btn-outline-primary" data-toggle="collapse" data-target="#pcdn-edit-{$r.id}">ویرایش</button>
              <form method="post" action="{$action}deleteRecord" class="d-inline" onsubmit="return confirm('حذف این رکورد؟')">
                <input type="hidden" name="pcdn_csrf" value="{$csrf}">{if $token}<input type="hidden" name="token" value="{$token}">{/if}
                <input type="hidden" name="record_id" value="{$r.id}">
                <button class="btn btn-sm btn-outline-danger">حذف</button>
              </form>
              {/if}
            </td>
          </tr>
          {if $active}
          <tr class="collapse" id="pcdn-edit-{$r.id}"><td colspan="6">
            <form method="post" action="{$action}updateRecord" class="form-row">
              <input type="hidden" name="pcdn_csrf" value="{$csrf}">{if $token}<input type="hidden" name="token" value="{$token}">{/if}
              <input type="hidden" name="record_id" value="{$r.id}">
              <div class="col-md-2 mb-1"><select name="type" class="form-control form-control-sm">
                {foreach $recordTypes as $t}<option {if $t == $r.type}selected{/if}>{$t}</option>{/foreach}</select></div>
              <div class="col-md-2 mb-1"><input name="name" class="form-control form-control-sm ltr" value="{$r.name|escape}"></div>
              <div class="col-md-3 mb-1"><input name="content" class="form-control form-control-sm ltr" value="{$r.content|escape}"></div>
              <div class="col-md-1 mb-1"><input name="priority" class="form-control form-control-sm ltr" value="{$r.priority}" placeholder="Prio"></div>
              <div class="col-md-1 mb-1"><input name="ttl" type="number" min="60" class="form-control form-control-sm ltr" value="{$r.ttl}"></div>
              <div class="col-md-2 mb-1 pt-1"><label class="mb-0"><input type="checkbox" name="proxied" value="1" {if $r.proxied}checked{/if}> پروکسی CDN</label></div>
              <div class="col-md-1 mb-1"><button class="btn btn-sm btn-primary btn-block">ذخیره</button></div>
            </form>
          </td></tr>
          {/if}
        {foreachelse}
          <tr><td colspan="6" class="text-center text-muted">هنوز رکوردی ثبت نشده است.</td></tr>
        {/foreach}
        </tbody>
      </table>
      </div>

      {if $active}
      <form method="post" action="{$action}addRecord" class="form-row border-top pt-3">
        <input type="hidden" name="pcdn_csrf" value="{$csrf}">{if $token}<input type="hidden" name="token" value="{$token}">{/if}
        <div class="col-md-2 mb-1"><select name="type" class="form-control form-control-sm">
          {foreach $recordTypes as $t}<option>{$t}</option>{/foreach}</select></div>
        <div class="col-md-2 mb-1"><input name="name" class="form-control form-control-sm ltr" placeholder="@ یا www"></div>
        <div class="col-md-3 mb-1"><input name="content" class="form-control form-control-sm ltr" placeholder="1.2.3.4" required></div>
        <div class="col-md-1 mb-1"><input name="priority" class="form-control form-control-sm ltr" placeholder="Prio"></div>
        <div class="col-md-1 mb-1"><input name="ttl" type="number" min="60" value="300" class="form-control form-control-sm ltr"></div>
        <div class="col-md-2 mb-1 pt-1"><label class="mb-0"><input type="checkbox" name="proxied" value="1" checked> پروکسی CDN</label></div>
        <div class="col-md-1 mb-1"><button class="btn btn-sm btn-success btn-block">افزودن</button></div>
      </form>
      <small class="text-muted">برای MX و SRV مقدار «Prio» را وارد کنید. فرمت SRV: <span class="ltr">weight port target</span></small>
      {/if}
    </div>
  </div>

  {if $active}
  <div class="row">
    {* ---------- cache ---------- *}
    <div class="col-md-6">
      <div class="card">
        <div class="card-header"><strong>پاکسازی کش</strong></div>
        <div class="card-body">
          <form method="post" action="{$action}purgeCache">
            <input type="hidden" name="pcdn_csrf" value="{$csrf}">{if $token}<input type="hidden" name="token" value="{$token}">{/if}
            <textarea name="urls" rows="4" class="form-control ltr mb-2" placeholder="https://{$site.domain|escape}/style.css&#10;(هر آدرس در یک خط)"></textarea>
            <button class="btn btn-sm btn-primary">پاکسازی آدرس‌ها</button>
            <button class="btn btn-sm btn-outline-danger" name="purge_all" value="1" onclick="return confirm('کل کش دامنه پاک شود؟')">پاکسازی کامل</button>
          </form>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><strong>گواهی SSL</strong></div>
        <div class="card-body">
          {if !$site.plan.ssl_allowed}
            <p class="text-muted mb-0">SSL رایگان در این پلن فعال نیست.</p>
          {else}
            <p class="mb-2">گواهی رایگان Let's Encrypt برای <span class="ltr">{$site.domain|escape}</span> و <span class="ltr">*.{$site.domain|escape}</span>
              پس از تغییر نیم‌سرورها به‌صورت خودکار صادر و تمدید می‌شود.</p>
            {if $site.ssl.status == 'failed' && $site.ssl.error}<pre class="ltr small text-danger" style="white-space:pre-wrap;max-height:120px;overflow:auto">{$site.ssl.error|escape|truncate:600}</pre>{/if}
            {if $site.ns_verified && $site.ssl.status != 'pending'}
            <form method="post" action="{$action}requestSsl">
              <input type="hidden" name="pcdn_csrf" value="{$csrf}">{if $token}<input type="hidden" name="token" value="{$token}">{/if}
              <button class="btn btn-sm btn-outline-success">{if $site.ssl.status == 'active'}صدور مجدد{else}درخواست صدور{/if}</button>
            </form>
            {/if}
          {/if}
        </div>
      </div>
    </div>

    {* ---------- settings ---------- *}
    <div class="col-md-6">
      <div class="card">
        <div class="card-header"><strong>تنظیمات</strong></div>
        <div class="card-body">
          <form method="post" action="{$action}saveSettings">
            <input type="hidden" name="pcdn_csrf" value="{$csrf}">{if $token}<input type="hidden" name="token" value="{$token}">{/if}
            <div class="form-check"><label><input type="checkbox" name="cache_enabled" value="1" {if $site.settings.cache_enabled}checked{/if}> فعال‌سازی کش</label></div>
            <div class="form-check"><label><input type="checkbox" name="dev_mode" value="1" {if $site.settings.dev_mode}checked{/if}> حالت توسعه (غیرفعال کردن موقت کش)</label></div>
            <div class="form-check"><label><input type="checkbox" name="force_https" value="1" {if $site.settings.force_https}checked{/if}> انتقال خودکار HTTP به HTTPS</label></div>
            <div class="form-group mt-2"><label>پروتکل اتصال به سرور اصلی</label>
              <select name="origin_protocol" class="form-control form-control-sm">
                <option value="http" {if $site.settings.origin_protocol == 'http'}selected{/if}>HTTP (پورت 80)</option>
                <option value="https" {if $site.settings.origin_protocol == 'https'}selected{/if}>HTTPS (پورت 443)</option>
              </select></div>
            <div class="form-group"><label>مدت کش فایل‌های ثابت در CDN</label>
              <select name="edge_cache_ttl" class="form-control form-control-sm">
                {foreach [3600=>'۱ ساعت', 14400=>'۴ ساعت', 86400=>'۱ روز', 604800=>'۷ روز', 2592000=>'۳۰ روز'] as $v => $l}
                  <option value="{$v}" {if $site.settings.edge_cache_ttl == $v}selected{/if}>{$l}</option>{/foreach}
              </select></div>
            <div class="form-group"><label>مدت کش در مرورگر کاربر</label>
              <select name="browser_cache_ttl" class="form-control form-control-sm">
                {foreach [0=>'طبق تنظیمات سرور اصلی', 3600=>'۱ ساعت', 86400=>'۱ روز', 604800=>'۷ روز', 2592000=>'۳۰ روز'] as $v => $l}
                  <option value="{$v}" {if $site.settings.browser_cache_ttl == $v}selected{/if}>{$l}</option>{/foreach}
              </select></div>
            <div class="form-group"><label>IPهای مسدود (هر مورد در یک خط، CIDR مجاز است)</label>
              <textarea name="blocked_ips" rows="3" class="form-control form-control-sm ltr">{$view.blockedIps|escape}</textarea></div>
            <button class="btn btn-sm btn-primary">ذخیره تنظیمات</button>
          </form>
        </div>
      </div>
    </div>
  </div>
  {/if}

  {* ---------- daily usage ---------- *}
  {if $daily}
  <div class="card">
    <div class="card-header"><strong>مصرف ۱۴ روز اخیر</strong></div>
    <div class="card-body p-0"><div class="table-responsive">
      <table class="table table-sm mb-0">
        <thead><tr><th>تاریخ</th><th>ترافیک</th><th>درخواست</th><th>کش</th></tr></thead>
        <tbody>
        {foreach $daily as $d}
          <tr><td class="ltr">{$d.date}</td>
            <td class="ltr">{$d.mb} MB</td>
            <td class="ltr">{$d.requests}</td>
            <td class="ltr">{$d.hitRatio}</td></tr>
        {/foreach}
        </tbody>
      </table>
    </div></div>
  </div>
  {/if}

{/if}
</div>
