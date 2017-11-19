<?php

namespace Iapps\PaymentService\PaymentAccess;

class AdminBTPaymentAccessChecker extends AdminCashPaymentAccessChecker{

    public static function checkDirectionIn($token)
    {//cannot use this to cash in as of 18 Aug 2016
        return false;
    }
}