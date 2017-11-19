<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\SystemCode\SystemCodeInterface;

class PaymentModeRequestType implements SystemCodeInterface{

    const ATM = 'atm';
    const IBANKING = 'ibanking';

    public static function getSystemGroupCode()
    {
        return 'payment_mode_request_type';
    }
}