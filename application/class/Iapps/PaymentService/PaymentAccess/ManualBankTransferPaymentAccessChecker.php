<?php

namespace Iapps\PaymentService\PaymentAccess;

use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Microservice\AccountService\AccountService;
use Iapps\Common\Microservice\AccountService\FunctionCode;

class ManualBankTransferPaymentAccessChecker extends PaymentAccessChecker
{
    public static function checkDirectionIn($token)
    {
        return true;
    }

    public static function checkDirectionOut($token)
    {
        return false;
    }
}