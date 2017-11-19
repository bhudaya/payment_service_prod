<?php

namespace Iapps\PaymentService\Currency;

require_once './application/modules/currency/models/Currency_model.php';

class CurrencyServiceFactory{

    protected static $_instance = NULL;

    public static function build()
    {
        if( CurrencyServiceFactory::$_instance == NULL )
        {
            $dm = new \Currency_model();
            $repo = new CurrencyRepository($dm);
            CurrencyServiceFactory::$_instance = new CurrencyService($repo);
        }

        return CurrencyServiceFactory::$_instance;
    }
}