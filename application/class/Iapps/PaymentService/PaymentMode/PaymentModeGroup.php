<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\SystemCode\SystemCodeInterface;

class PaymentModeGroup implements SystemCodeInterface
{
    const CASH   = 'cash';
    const EWALLET   = 'ewallet';
    const KIOSK   = 'kiosk';
    const BANK   = 'bank';
    const OTHER   = 'other';
    const HOLDING_ACCOUNT   = 'holding_account';

    public static function getSystemGroupCode()
    {
        return 'payment_mode_group';
    }
}