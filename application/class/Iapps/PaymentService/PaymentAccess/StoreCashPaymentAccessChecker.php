<?php

namespace Iapps\PaymentService\PaymentAccess;

use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Microservice\AccountService\AccountService;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\Common\Microservice\AccountService\SessionType;

class StoreCashPaymentAccessChecker extends PaymentAccessChecker
{
    public static function checkDirectionIn($token)
    {
        $acc_serv = AccountServiceFactory::build();
        return $acc_serv->checkAccess($token, FunctionCode::COUNTER_CASHIN, AccessType::WRITE, SessionType::TRANSACTION);
    }

    public static function checkDirectionOut($token)
    {
        $acc_serv = AccountServiceFactory::build();
        return $acc_serv->checkAccess($token, FunctionCode::COUNTER_CASHOUT, AccessType::WRITE, SessionType::TRANSACTION);
    }
}