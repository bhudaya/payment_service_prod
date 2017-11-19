<?php

namespace Iapps\PaymentService\Common\HoldingAccountClient;

use Iapps\Common\Helper\RequestHeader;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClient;

class HoldingAccountUtilizationClientFactory{

    protected static $_instance = array();
    public static function build($amount, $payment_request_client = NULL, $user_id = NULL)
    {
        $type = 'utilise';
        if( $amount < 0 )
            $type = 'collection';

        if( !array_key_exists($type, self::$_instance) )
        {
            if( !$url = getenv('HOLDING_ACCOUNT_SERVICE_URL') )
                throw new \Exception('Holding account Service URL Is Not Defined');

            if( $type == 'utilise' )
            {
                if($payment_request_client == PaymentRequestClient::SYSTEM) {
                    self::$_instance[$type] = new SystemHoldingAccountUtilizationClient(array(
                        'base_url' => $url,
                        'header' => RequestHeader::get()
                    ));
                }
                else {
                    self::$_instance[$type] = new HoldingAccountUtilizationClient(array(
                        'base_url' => $url,
                        'header' => RequestHeader::get()
                    ));
                }
            }
            else
            {
                self::$_instance[$type] = new HoldingAccountCollectionClient(array(
                    'base_url' => $url,
                    'header' => RequestHeader::get()
                ));
            }
        }

        if( self::$_instance[$type] instanceof HoldingAccountCollectionClient )
            self::$_instance[$type]->setUserProfileId($user_id);

        return self::$_instance[$type];
    }
}