<?php

namespace Iapps\PaymentService\PaymentAccess;

class PaymentAccessChecker {

    public static function checkDirectionIn($token)
    {
        return false;
    }

    public static function checkDirectionOut($token)
    {
        return false;
    }
}