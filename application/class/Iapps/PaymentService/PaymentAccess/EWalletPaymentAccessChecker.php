<?php

namespace Iapps\PaymentService\PaymentAccess;

use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Microservice\AccountService\AccountService;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\Common\Microservice\AccountService\SessionType;

class EWalletPaymentAccessChecker extends PaymentAccessChecker
{
    /*
     * Only APP Public users are allow to utilize eWallet
     */
    public static function checkDirectionIn($token)
    {
        return true;//the access will be controlled by ewallet service
        //$acc_serv = AccountServiceFactory::build();
        //return $acc_serv->checkAccess($token, FunctionCode::APP_PUBLIC_FUNCTIONS, AccessType::WRITE, SessionType::TRANSACTION);
    }

    public static function checkDirectionOut($token)
    {
        // anyone with access token can credit money to user's ewallet??
        $acc_serv = AccountServiceFactory::build();
        return $acc_serv->checkAccess($token);
        /*
        return
            (
                $acc_serv->checkAccess($token, FunctionCode::APP_PUBLIC_FUNCTIONS, AccessType::WRITE, SessionType::TRANSACTION) OR
                $acc_serv->checkAccess($token, \Iapps\PaymentService\Common\FunctionCode::ADMIN_PAYMENT_OUT, AccessType::WRITE, SessionType::LOGIN) OR
                $acc_serv->checkAccess($token, \Iapps\PaymentService\Common\FunctionCode::PARTNER_PAYMENT_OUT, AccessType::WRITE, SessionType::LOGIN)
            );
        */
    }
}