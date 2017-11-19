<?php

namespace Iapps\PaymentService\Payment;

use Iapps\Common\SystemCode\SystemCodeInterface;

class PaymentStatus implements SystemCodeInterface{

    const PENDING = 'pending';
    const COMPLETE = 'complete';
    const VOID = 'void';

    public static function getSystemGroupCode()
    {
        return 'payment_status';
    }
}