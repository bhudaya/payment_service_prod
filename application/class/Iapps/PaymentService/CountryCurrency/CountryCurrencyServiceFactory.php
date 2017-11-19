<?php

namespace Iapps\PaymentService\CountryCurrency;

require_once './application/modules/countrycurrency/models/Country_currency_model.php';

class CountryCurrencyServiceFactory {

    protected static $_instance;

    public static function build()
    {
        if( self::$_instance == NULL )
        {
            $dm = new \Country_currency_model();
            $repo = new CountryCurrencyRepository($dm);
            self::$_instance = new CountryCurrencyService($repo);
        }

        return self::$_instance;
    }
}