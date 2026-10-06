<?php

namespace PasargadCdn\Admin;

// Only on WHMCS versions that have admin home widgets (8.0+).
if (!class_exists('\\WHMCS\\Module\\AbstractWidget') || class_exists(__NAMESPACE__ . '\\Widget', false)) {
    return;
}

/**
 * Admin home widget «CDN پاسارگاد». Caching is done by WidgetData (5 min),
 * so WHMCS's own widget cache is left off to avoid a second layer of staleness.
 */
class Widget extends \WHMCS\Module\AbstractWidget
{
    protected $title = 'CDN پاسارگاد';
    protected $description = 'وضعیت سایت‌ها، نودها و ترافیک CDN';
    protected $weight = 150;
    protected $columns = 1;
    protected $cache = false;
    protected $cacheExpiry = 300;
    protected $requiredPermission = '';

    public function getData()
    {
        return WidgetData::get();
    }

    public function generateOutput($data)
    {
        return WidgetData::render(is_array($data) ? $data : []);
    }
}
