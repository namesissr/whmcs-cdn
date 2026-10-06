{* Pasargad CDN — Wave 10 (SPEC §18.5): the addon's client-area pages (public pricing, referral card).
   pcdn_html is built and escaped in lib/Pricing.php / lib/Referrals.php; nofilter keeps it intact when
   the theme turns Smarty auto-escaping on. *}
{$pcdn_html nofilter}
