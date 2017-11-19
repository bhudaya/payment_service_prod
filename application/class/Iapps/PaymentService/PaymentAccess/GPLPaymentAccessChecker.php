<?php

namespace Iapps\PaymentService\PaymentAccess;

use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Microservice\AccountService\AccountService;
use Iapps\Common\Microservice\AccountService\FunctionCode;

class GPLPaymentAccessChecker extends PaymentAccessChecker
{
    public static function checkDirectionIn($token)
    {
        return false;
    }

    public static function checkDirectionOut($token)
    {
        return true;
    }
}