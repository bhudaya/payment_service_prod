<?php

namespace Iapps\PaymentService\Common\EwalletClient;

use Iapps\PaymentService\PaymentRequest\PaymentRequestClient;
use Iapps\Common\Helper\RequestHeader;

class EwalletVoidClientFactory {

    protected static $_instance = array();
    public static function build($client)
    {
        if( !in_array($client, self::$_instance ) )
        {
            if( !$url = getenv('EWALLET_SERVICE_URL') )
                throw new \Exception('Ewallet Service URL Is Not Defined');

            switch($client)
            {
                case PaymentRequestClient::ADMIN:
                    self::$_instance[$client] = new AdminEwalletVoidClient(array(
                        'base_url' => $url,
                        'header' => RequestHeader::get()
                    ));
                    break;
                default:
                    throw new \Exception('Client is not supported to void ewallet');
            }
        }

        return self::$_instance[$client];
    }
}