<?php

namespace Iapps\PaymentService\Common\EwalletClient;

use Iapps\Common\Helper\RequestHeader;

class PartnerWorkCreditCashClientFactory{

    protected static $_instance_in;
    protected static $_instance_out;
    public static function build($amount)
    {
        if( $amount < 0 )
            return self::buildCashOutClient();
        else
            return self::buildCashInClient();
    }

    public static function buildCashInClient()
    {
        if( self::$_instance_in == NULL )
        {
            if( !$url = getenv('EWALLET_SERVICE_URL') )
                throw new \Exception('Ewallet Service URL Is Not Defined');

            self::$_instance_in = new PartnerWorkCreditCashInClient(array(
                'base_url' => $url,
                'header' => RequestHeader::get()
            ));
        }

        return self::$_instance_in;
    }

    public static function buildCashOutClient()
    {
        if( self::$_instance_out == NULL )
        {
            if( !$url = getenv('EWALLET_SERVICE_URL') )
                throw new \Exception('Ewallet Service URL Is Not Defined');

            self::$_instance_out = new PartnerWorkCreditCashOutClient(array(
                'base_url' => $url,
                'header' => RequestHeader::get()
            ));
        }

        return self::$_instance_out;
    }
}