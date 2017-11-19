<?php

namespace Iapps\PaymentService\PaymentAccess;

use Iapps\Common\Microservice\AccountService\AccountServiceFactory;

class HoldingAccountPaymentAccessChecker extends PaymentAccessChecker
{
    /*
     * Only APP Public users are allow to utilize holding account
     */
    public static function checkDirectionIn($token)
    {
        return true;
    }

    public static function checkDirectionOut($token)
    {
        $acc_serv = AccountServiceFactory::build();
        return $acc_serv->checkAccess($token);
    }
}