<?php

namespace Iapps\PaymentService\Common;

use Iapps\Common\SystemCode\SystemCodeInterface;

class ChannelType implements SystemCodeInterface{

    const CODE_PUBLIC_APP_IOS       = 'pub_app_ios';
    const CODE_PUBLIC_APP_ANDROID   = 'pub_app_android';
    const CODE_AGENT_APP            = 'agent_app';
    const CODE_ADMIN_PANEL          = 'admin_panel';
    const CODE_CORPORATE_PANEL      = 'corp_panel';
    const CODE_PARTNER_PANEL        = 'partner_panel';
    const CODE_PUBLIC_APP           = 'pub_app';

    public static function getSystemGroupCode()
    {
        return 'channel';
    }
}