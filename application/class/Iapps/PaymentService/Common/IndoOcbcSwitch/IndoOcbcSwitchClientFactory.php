<?php

namespace Iapps\PaymentService\Common\IndoOcbcSwitch;

use Iapps\PaymentService\Common\CoreConfigDataServiceFactory;
use Iapps\PaymentService\Common\CoreConfigType;

class IndoOcbcSwitchClientFactory{

    protected static $_instance;
    public static function build(array $option = array())
    {
        if( self::$_instance == NULL )
        {
            $core_config = CoreConfigDataServiceFactory::build();
            if( !$user_name = $core_config->getConfig(CoreConfigType::INDO_SWITCH_USERID) )
                throw new \Exception('Indo Switch User ID Is Not Defined');
            if( !$user_key = $core_config->getConfig(CoreConfigType::INDO_SWITCH_USERKEY) )
                throw new \Exception('Indo Switch User KEY Is Not Defined');
            if( !$url = getenv('INDO_SWITCH_URL') )
                throw new \Exception('Indo Switch URL Is Not Defined');

            if( count($option) > 0 )
            {
                self::$_instance = IndoOcbcSwitchClient::fromOption(array(
                                                    'username' => $user_name,
                                                    'password' => $user_key,
                                                    'url' => $url
                                                    ),
                                                    $option);
            }
            else
            {
                self::$_instance = new IndoOcbcSwitchClient(array(
                    'username' => $user_name,
                    'password' => $user_key,
                    'url' => $url
                ));
            }
        }

        return self::$_instance;
    }

    public static function buildFromOption(array $option)
    {
        $client = IndoOcbcSwitchClientFactory::build();

        if( isset($option['product_code']) )
            $client->setProductCode($option['product_code']);
        if( isset($option['merchant_code']) )
            $client->setMerchantCode($option['merchant_code']);
        if( isset($option['terminal_code']) )
            $client->setTerminalCode($option['terminal_code']);
        if( isset($option['dest_refnumber']) )
            $client->setDestRefNumber($option['dest_refnumber']);
        if( isset($option['dest_bankcode']) )
            $client->setDestBankCode($option['dest_bankcode']);
        if( isset($option['dest_bankacc']) )
            $client->setDestBankAccount($option['dest_bankacc']);
        if( isset($option['dest_amount']) )
            $client->setDestAmount($option['dest_amount']);

        return $client;
    }
}