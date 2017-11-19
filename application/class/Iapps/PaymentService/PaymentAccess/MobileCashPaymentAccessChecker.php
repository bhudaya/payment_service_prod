<?php

namespace Iapps\PaymentService\PaymentAccess;

use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Microservice\AccountService\AccountService;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\Common\Microservice\AccountService\SessionType;

class MobileCashPaymentAccessChecker extends PaymentAccessChecker
{
    public static function checkDirectionIn($token)
    {
        $acc_serv = AccountServiceFactory::build();
        return $acc_serv->checkAccess($token, FunctionCode::MOBILE_CASHIN, AccessType::WRITE, SessionType::TRANSACTION);
    }

    public static function checkDirectionOut($token)
    {
        $acc_serv = AccountServiceFactory::build();
        return $acc_serv->checkAccess($token, FunctionCode::MOBILE_CASHOUT, AccessType::WRITE, SessionType::TRANSACTION);
    }
}