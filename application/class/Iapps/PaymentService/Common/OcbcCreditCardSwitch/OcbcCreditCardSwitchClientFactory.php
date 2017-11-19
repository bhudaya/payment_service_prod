<?php

namespace Iapps\PaymentService\Common\OcbcCreditCardSwitch;

use Iapps\PaymentService\Common\CoreConfigDataServiceFactory;
use Iapps\PaymentService\Common\CoreConfigType;

class OcbcCreditCardSwitchClientFactory{

    protected static $_instance;

    public static function build(array $option = array(), array $response = array())
    {
        $core_config = CoreConfigDataServiceFactory::build();
        
        if( !$merchant_no = $core_config->getConfig(CoreConfigType::OCBC_CREDIT_CARD_MERCHANT_NO) ) //get from db
            throw new \Exception('OCBC BPG Merchant Number Is Not Defined');

        if( !$tranx_password = $core_config->getConfig(CoreConfigType::OCBC_CREDIT_CARD_TRANSACTION_PASSWORD) )
            throw new \Exception('OCBC BPG Transaction Password Is Not Defined');

        if( !$url = getenv('OCBC_BPG_URL') ) { //get env file
            throw new \Exception('OCBC BPG URL Is Not Defined In ENV File');
        }

        if ( !$direct_url = getenv('OCBC_BPG_DIRECT_URL') ) {
            throw new \Exception('OCBC BPG DIRECT URL Is Not Defined In ENV File');
        }

        if( !$return_url = getenv('OCBC_BPG_RETURN_URL') ) { //get env file
            throw new \Exception('OCBC BPG RETURN URL Is Not Defined In ENV File');
        }    

        if( count($option) > 0 )
        {
            self::$_instance = OcbcCreditCardSwitchClient::fromOption(array(
                'merchant_no' => $merchant_no,
                'tranx_password' => $tranx_password,
                'url' => $url,
                'direct_url' => $direct_url,
                'return_url' => $return_url
            ),
                $option);
        }
        elseif ( count($response) > 0 )
        {
            self::$_instance = OcbcCreditCardSwitchClient::fromResponse(array(
                'merchant_no' => $merchant_no,
                'tranx_password' => $tranx_password,
                'url' => $url,
                'direct_url' => $direct_url,
                'return_url' => $return_url
            ),
                $response);
        }
        else
        {
            self::$_instance = new OcbcCreditCardSwitchClient(array(
                'merchant_no' => $merchant_no,
                'tranx_password' => $tranx_password,
                'url' => $url,
                'direct_url' => $direct_url,
                'return_url' => $return_url
            ));
        }
  
        return self::$_instance;
    }

    public static function buildFromOption(array $option)
    {
        $client = OcbcCreditCardSwitchClientFactory::build();
        
        if( isset($option['user_profile_id']) )
            $client->setUserProfileID($option['user_profile_id']);
        if( isset($option['transactionID']) )
            $client->setTransactionID($option['transactionID']);
        if( isset($option['transaction_description']) )
            $client->setTransactionDescription($option['transaction_description']);
        if( isset($option['transaction_currency']) )
            $client->setTransactionCurrency($option['transaction_currency']);
        if( isset($option['transaction_amount']) )
            $client->setTransactionAmount($option['transaction_amount']);

        return $client;
    }

    public static function buildFromResponse(array $response)
    {
        $client = OcbcCreditCardSwitchClientFactory::build();

        if ( isset($response['TRANSACTION_ID']) )
            $client->setBankTransactionID($response['TRANSACTION_ID']);
        if ( isset($response['TXN_STATUS']) )
            $client->setBankTransactionStatus($response['TXN_STATUS']);
        if ( isset($response['TXN_SIGNATURE']) )
            $client->setBankTransactionSignature($response['TXN_SIGNATURE']);
        if ( isset($response['TXN_SIGNATURE2']) )
            $client->setBankTransactionSignature2($response['TXN_SIGNATURE2']);
        if ( isset($response['AUTH_ID']) )
            $client->setBankAuthID($response['AUTH_ID']);
        if ( isset($response['TRAN_DATE']) )
            $client->setBankTransactionDate($response['TRAN_DATE']);
        if ( isset($response['SALES_DATE']) )
            $client->setBankSalesDate($response['SALES_DATE']);
        if ( isset($response['ECI']) )
            $client->setBankECI($response['ECI']);
        if ( isset($response['RESPONSE_CODE']) )
            $client->setBankResponseCode($response['RESPONSE_CODE']);
        if ( isset($response['RESPONSE_DESC']) )
            $client->setBankResponseDescription($response['RESPONSE_DESC']);
        if ( isset($response['MERCHANT_TRANID']) )
            $client->setBankMerchantTransactionID($response['MERCHANT_TRANID']);
        if ( isset($response['CUSTOMER_ID']) )
            $client->setBankCustomerID($response['CUSTOMER_ID']);
        
        return $client;
    }
}