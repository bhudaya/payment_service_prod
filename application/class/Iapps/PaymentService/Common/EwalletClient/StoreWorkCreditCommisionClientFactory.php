<?php

namespace Iapps\PaymentService\Common\EwalletClient;

use Iapps\Common\Helper\RequestHeader;

class StoreWorkCreditCommisionClientFactory{

    protected static $_instance;
    public static function build()
    {
        if( self::$_instance == NULL )
        {
            if( !$url = getenv('EWALLET_SERVICE_URL') )
                throw new \Exception('Ewallet Service URL Is Not Defined');

            self::$_instance = new StoreWorkCreditCommisionClient(array(
                'base_url' => $url,
                'header' => RequestHeader::get()
            ));
        }

        return self::$_instance;
    }
}