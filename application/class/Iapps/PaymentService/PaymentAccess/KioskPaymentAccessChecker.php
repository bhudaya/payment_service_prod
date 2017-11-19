<?php

namespace Iapps\PaymentService\PaymentAccess;

use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Microservice\AccountService\AccountService;
use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\Common\Microservice\AccountService\SessionType;

class KioskPaymentAccessChecker extends PaymentAccessChecker
{
    public static function checkDirectionIn($token)
    {//todo what to check?
        return true;
    }

    public static function checkDirectionOut($token)
    {
        return false;
    }
}