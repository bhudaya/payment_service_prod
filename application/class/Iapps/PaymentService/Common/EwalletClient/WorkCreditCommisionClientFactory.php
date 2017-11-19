<?php

namespace Iapps\PaymentService\Common\EwalletClient;

use Iapps\Common\Helper\RequestHeader;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClient;

class WorkCreditCommisionClientFactory{

    protected static $_instance;
    public static function build($payment_request_client = NULL)
    {
        if( self::$_instance == NULL ) {
            if (!$url = getenv('EWALLET_SERVICE_URL'))
                throw new \Exception('Ewallet Service URL Is Not Defined');

            if ($payment_request_client == PaymentRequestClient::SYSTEM) {
                self::$_instance = new SystemWorkCreditCommisionClient(array(
                    'base_url' => $url,
                    'header' => RequestHeader::get()
                ));
            } else {
                self::$_instance = new WorkCreditCommisionClient(array(
                    'base_url' => $url,
                    'header' => RequestHeader::get()
                ));
            }
        }

        return self::$_instance;
    }
}