<?php

namespace Iapps\PaymentService\Common\EwalletClient;

use Iapps\Common\Helper\RequestHeader;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClient;

class EwalletUtilizationClientFactory{

    protected static $_instance = array();
    public static function build($amount, $payment_request_client = NULL, $user_id = NULL)
    {
        $type = 'utilise';
        if( $amount < 0 )
            $type = 'collection';

        if( !array_key_exists($type, self::$_instance) )
        {
            if( !$url = getenv('EWALLET_SERVICE_URL') )
                throw new \Exception('Ewallet Service URL Is Not Defined');

            if( $type == 'utilise' )
            {
                if($payment_request_client == PaymentRequestClient::SYSTEM) {
                    self::$_instance[$type] = new SystemEwalletUtilizationClient(array(
                        'base_url' => $url,
                        'header' => RequestHeader::get()
                    ));
                }
                elseif($payment_request_client == PaymentRequestClient::AGENT)
                {
                    self::$_instance[$type] = new AgentEwalletUtilizationClient(array(
                        'base_url' => $url,
                        'header' => RequestHeader::get()
                    ));
                }
                else {
                    self::$_instance[$type] = new EwalletUtilizationClient(array(
                        'base_url' => $url,
                        'header' => RequestHeader::get()
                    ));
                }
            }
            else
            {
                self::$_instance[$type] = new EwalletCollectionClient(array(
                    'base_url' => $url,
                    'header' => RequestHeader::get()
                ));
            }
        }

        if( self::$_instance[$type] instanceof AgentEwalletUtilizationClient OR
            self::$_instance[$type] instanceof EwalletCollectionClient )
            self::$_instance[$type]->setUserProfileId($user_id);

        return self::$_instance[$type];
    }
}