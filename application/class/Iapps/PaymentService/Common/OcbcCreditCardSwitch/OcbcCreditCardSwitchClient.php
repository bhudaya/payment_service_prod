<?php

namespace Iapps\PaymentService\Common\OcbcCreditCardSwitch;

use Iapps\Common\Core\IappsDateTime;
use Iapps\Common\Helper\HttpService;
use Iapps\Common\Helper\StringMasker;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClientInterface;
use Iapps\PaymentService\Common\Logger;


class OcbcCreditCardSwitchClient implements PaymentRequestClientInterface{
    const QUERY_REQUEST_TYPE = '1';
    const SALES_REQUEST_TYPE = '2';
    const AUTHORIZE_REQUEST_TYPE = '3';
    const CAPTURE_REQUEST_TYPE = '4';
    const VOID_REQUEST_TYPE = '6';

    const SHA2_FORMAT = 'SHA2';
    const MD5_FORMAT = 'MD5';

    const SIGNATURE_METHOD = 'SHA2';
    const HTTP_RESPONSE_TYPE = 'HTTP';
    const XML_RESPONSE_TYPE = 'XML';
    const PLAIN_RESPONSE_TYPE = 'PLAIN';

    protected $config = array();
    protected $_http_serv;
    protected $_query_http_serv;
    protected $_option;
    protected $header;

    protected $user_profile_id;
    protected $transactionID;
    protected $transaction_description = NULL;
    protected $transaction_currency;
    protected $transaction_amount;
    protected $return_url;

    protected $bpg_transactionID;
    protected $bpg_trnx_status;
    protected $bpg_trnx_signature;
    protected $bpg_trnx_signature2;
    protected $bpg_auth_id;
    protected $bpg_trnx_date;
    protected $bpg_sales_date;
    protected $bpg_void_date;
    protected $bpg_eci;
    protected $bpg_response_code;
    protected $bpg_response_desc;
    protected $bpg_merchange_transactionID;
    protected $bpg_user_profile_id;
    protected $bpg_fraud_level;
    protected $bpg_fraud_scoring;

    function __construct(array $config)
    {
        $this->config = $config;
                 
        if( !$this->_getMerchantNo() OR
            !$this->_getTransactionPassword() OR
            !$this->_getUrl() OR
            !$this->_getDirectUrl() OR
            !$this->_getReturnUrl())

            throw new \Exception('invalid OCBC BPG configuration');

        $this->_http_serv = new HttpService();  
        $this->_http_serv->setUrl($this->_getUrl());

        $this->_query_http_serv = new HttpService();
        $this->_query_http_serv->setUrl($this->_getDirectUrl());
        
        $this->header = array
        (
            'Content-Type'=>'application/x-www-form-urlencoded'
        );

    }

    protected function getRequestTransactionHash($hash_method = 'SHA2')
    {
        // OCBC BANK PAYMENT GATEWAY Request Signature
        // 1. Merchant Transaction Password + 
        // 2. Merchant Account No. + 
        // 3. Merchant Transaction ID + 
        // 4. Transaction Amount
        $origin_string = "" . (string)$this->_getTransactionPassword() . (string)$this->_getMerchantNo() . (string)$this->getTransactionID() . (string)$this->getFormattedTransactionAmount();

        if ($hash_method == self::SHA2_FORMAT)
        {
            return strtoupper(hash('sha512', $origin_string));
        }
        else if ($hash_method == self::MD5_FORMAT)
        {
            return hash('md5', $origin_string);
        }
    }

    public function checkResponseTransactionHash($response_transaction_hash, $hash_method = 'MD5')
    {
        // OCBC BANK PAYMENT GATEWAY Response Signature
        // 1. Merchant Transaction Password + 
        // 2. Merchant Account No. + 
        // 3. Merchant Transaction ID + 
        // 4. Transaction Amount + 
        // 5. Transaction ID (Bank Assigned) + 
        // 6. Transaction Status + 
        // 7. Response Code
        
        if ($hash_method == self::SHA2_FORMAT)
        {
            $origin_string = "" . (string)$this->_getTransactionPassword() . (string)$this->_getMerchantNo() . (string)$this->getBankMerchantTransactionID() . (string)$this->getFormattedTransactionAmount() . (string)$this->getBankTransactionID() . (string)$this->getBankTransactionStatus() . (string)$this->getBankResponseCode();
            
            $ori_transaction_hash = strtoupper(hash('sha512', $origin_string));
        }
        else if ($hash_method == self::MD5_FORMAT)
        {
            $origin_string = "" . (string)$this->_getTransactionPassword() . (string)$this->_getMerchantNo() . (string)$this->getBankMerchantTransactionID() . (string)$this->getFormattedTransactionAmount() . (string)$this->getBankTransactionID();
            
            $ori_transaction_hash = hash('md5', $origin_string);
        }

        return ($ori_transaction_hash == $response_transaction_hash);
    }

    public function paymentSales()
    {
        if ( !$this->getTransactionID() OR
             !$this->getTransactionAmount())
            return false;

        $params = array(
            'MERCHANT_ACC_NO'=>$this->_getMerchantNo(),
            'TRANSACTION_TYPE'=>self::SALES_REQUEST_TYPE,
            'MERCHANT_TRANID'=>$this->getTransactionID(),
            'AMOUNT'=>$this->getFormattedTransactionAmount(),
            'TXN_SIGNATURE'=>$this->getRequestTransactionHash(self::SIGNATURE_METHOD),
            'SIGNATURE_METHOD'=>self::SIGNATURE_METHOD,
            'RESPONSE_TYPE'=>self::HTTP_RESPONSE_TYPE,
            'RETURN_URL'=>$this->_getReturnUrl(),
            'TXN_DESC'=>$this->getTransactinDescription(),
            'CUSTOMER_ID'=>$this->getUserProfileID()
        );

        $params_string = '';
        foreach($params as $key => $value)
        {
            $params_string .= (empty($params_string)) ? '' : '&';
            $params_string .= $key . '=' . $value;
        }

        $return_data = array('ocbc_submit_url' => $this->_getUrl(), 'param' => $params, 'param_query_string' => $params_string);
        return $return_data;
    }

    public function paymentStatusQuery()
    {
        if ( !$this->getTransactionID() OR
             !$this->getTransactionAmount())
            return false;

        $params = array(
            'MERCHANT_ACC_NO'=>$this->_getMerchantNo(),
            'MERCHANT_TRANID'=>$this->getTransactionID(),
            'AMOUNT'=>$this->getFormattedTransactionAmount(),
            'TRANSACTION_TYPE'=>self::QUERY_REQUEST_TYPE,
            'TXN_SIGNATURE'=>$this->getRequestTransactionHash(self::SIGNATURE_METHOD),
            'SIGNATURE_METHOD'=>self::SIGNATURE_METHOD,
            'RESPONSE_TYPE'=>self::PLAIN_RESPONSE_TYPE
        );

        $this->_option = $params;
        $response = $this->_query_http_serv->post($this->header, $params);
        return new OcbcCreditCardSwitchResponse($response->getMessage()['message'],"api");
    }

    public function paymentVoid()
    {
        if ( !$this->getTransactionID() OR
             !$this->getTransactionAmount())
            return false;

        $params = array(
            'MERCHANT_ACC_NO'=>$this->_getMerchantNo(),
            'TRANSACTION_ID'=>$this->getBankTransactionID(),
            'MERCHANT_TRANID'=>$this->getTransactionID(),
            'AMOUNT'=>$this->getFormattedTransactionAmount(),
            'TRANSACTION_TYPE'=>self::VOID_REQUEST_TYPE,
            'TXN_SIGNATURE'=>$this->getRequestTransactionHash(self::SIGNATURE_METHOD),
            'SIGNATURE_METHOD'=>self::SIGNATURE_METHOD,
            'RESPONSE_TYPE'=>self::PLAIN_RESPONSE_TYPE
        );

        $this->_option = $params;
        $response = $this->_query_http_serv->post($this->header, $params);
        return new OcbcCreditCardSwitchResponse($response->getMessage()['message'],"api");
    }

    //set post option to Client Object , call from OcbcCreditCardSwitchClientFactory
    public static function fromOption(array $config, array $option)
    {
        $c = new OcbcCreditCardSwitchClient($config);
        
        if( isset($option['transactionID']) )
            $c->setTransactionID($option['transactionID']);
        if( isset($option['transaction_description']) )
            $c->setTransactionDescription($option['transaction_description']);
        if( isset($option['transaction_currency']) )
            $c->setTransactionCurrency($option['transaction_currency']);
        if( isset($option['transaction_amount']) )
            $c->setTransactionAmount($option['transaction_amount']);
        if( isset($option['user_profile_id']) )
            $c->setUserProfileID($option['user_profile_id']);
        
        return $c;
    }


    protected function _getMerchantNo()
    {
        if( array_key_exists('merchant_no', $this->config) )
            return $this->config['merchant_no'];

        return false;
    }

    protected function _getTransactionPassword()
    {
        if ( array_key_exists('tranx_password', $this->config) )
            return $this->config['tranx_password'];

        return false;
    }

    /*
     * This will first try from config['url']
     * Then environment
     * Otherwise return false
     */
    protected function _getUrl()
    {
        if( array_key_exists('url', $this->config) )
            return $this->config['url'];
        else if( getenv('OCBC_BPG_URL') )
            return getenv('OCBC_BPG_URL');

        return false;
    }

    protected function _getDirectUrl()
    {
        if ( array_key_exists('direct_url', $this->config) )
            return $this->config['direct_url'];
        else if ( getenv('OCBC_BPG_DIRECT_URL') )
            return getenv('OCBC_BPG_DIRECT_URL');

        return false;
    }

    public function _getReturnUrl()
    {
        if( array_key_exists('return_url', $this->config) )
            return $this->config['return_url'];
        else if( getenv('OCBC_BPG_RETURN_URL') )
            return getenv('OCBC_BPG_RETURN_URL');

        return false;
    }

    public function setUserProfileID($user_profile_id)
    {
        $this->user_profile_id = $user_profile_id;
        return $this;
    }

    public function getUserProfileID()
    {
        return $this->user_profile_id;
    }

    public function setTransactionID($transactionID)
    {
        $this->transactionID = $transactionID;
        return $this;
    }

    public function getTransactionID()
    {
        return $this->transactionID;
    }

    public function setTransactionDescription($transaction_description)
    {
        $this->transaction_description = $transaction_description;
        return $this;
    }

    public function getTransactinDescription()
    {
        return (empty($this->transaction_description) ? 'null' : $this->transaction_description);
    }

    public function setTransactionCurrency($transaction_currency)
    {
        $this->transaction_currency = $transaction_currency;
        return $this;
    }

    public function getTransactionCurrency()
    {
        return $this->transaction_currency;
    }

    public function setTransactionAmount($transaction_amount)
    {
        $this->transaction_amount = $transaction_amount;
        return $this;
    }

    public function getTransactionAmount()
    {
        return $this->transaction_amount;
    }

    public function getFormattedTransactionAmount()
    {
        return number_format($this->transaction_amount, 2, '.', '');
    }

    public static function fromResponse(array $config, array $response)
    {
        $c = new OcbcCreditCardSwitchClient($config);

        if ( isset($response['TRANSACTION_ID']) )
            $c->setBankTransactionID($response['TRANSACTION_ID']);
        if ( isset($response['TXN_STATUS']) )
            $c->setBankTransactionStatus($response['TXN_STATUS']);
        if ( isset($response['TXN_SIGNATURE']) )
            $c->setBankTransactionSignature($response['TXN_SIGNATURE']);
        if ( isset($response['TXN_SIGNATURE2']) )
            $c->setBankTransactionSignature2($response['TXN_SIGNATURE2']);
        if ( isset($response['AUTH_ID']) )
            $c->setBankAuthID($response['AUTH_ID']);
        if ( isset($response['TRAN_DATE']) )
            $c->setBankTransactionDate($response['TRAN_DATE']);
        if ( isset($response['SALES_DATE']) )
            $c->setBankSalesDate($response['SALES_DATE']);
        if ( isset($response['VOID_REV_DATE']) )
            $c->setBankVoidDate($response['VOID_REV_DATE']);
        if ( isset($response['ECI']) )
            $c->setBankECI($response['ECI']);
        if ( isset($response['RESPONSE_CODE']) )
            $c->setBankResponseCode($response['RESPONSE_CODE']);
        if ( isset($response['RESPONSE_DESC']) )
            $c->setBankResponseDescription($response['RESPONSE_DESC']);
        if ( isset($response['MERCHANT_TRANID']) )
            $c->setBankMerchantTransactionID($response['MERCHANT_TRANID']);
        if ( isset($response['CUSTOMER_ID']) )
            $c->setBankCustomerID($response['CUSTOMER_ID']);
        if ( isset($response['FR_LEVEL']) )
            $c->setBankFraudLevel($response['FR_LEVEL']);
        if ( isset($response['FR_SCORE']) )
            $c->setBankFraudScoring($response['FR_SCORE']);

        return $c;
    }

    public function setBankTransactionID($trnx_id)
    {
        $this->bpg_transactionID = $trnx_id;
        return $this;
    }

    public function getBankTransactionID()
    {
        return $this->bpg_transactionID;
    }

    public function setBankTransactionStatus($trnx_status)
    {
        $this->bpg_trnx_status = $trnx_status;
        return $this;
    }

    public function getBankTransactionStatus()
    {
        return $this->bpg_trnx_status;
    }

    public function setBankTransactionSignature($txn_signature)
    {
        $this->bpg_trnx_signature = $txn_signature;
        return $this;
    }

    public function getBankTransactionSignature()
    {
        return $this->bpg_trnx_signature;
    }

    public function setBankTransactionSignature2($txn_signature2)
    {
        $this->bpg_trnx_signature2 = $txn_signature2;
        return $this;
    }

    public function getBankTransactionSignature2()
    {
        return $this->bpg_trnx_signature2;
    }

    public function setBankAuthID($auth_id)
    {
        $this->bpg_auth_id = $auth_id;
        return $this;
    }

    public function getBankAuthID()
    {
        return $this->bpg_auth_id;
    }

    public function setBankTransactionDate($trnx_date)
    {
        $this->bpg_trnx_date = $trnx_date;
        return $this;
    }

    public function getBankTransactionDate()
    {
        return $this->bpg_trnx_date;
    }

    public function setBankSalesDate($sales_date)
    {
        $this->bpg_sales_date = $sales_date;
        return $this;
    }

    public function getBankSalesDate()
    {
        return $this->bpg_sales_date;
    }

    public function setBankVoidDate($void_date)
    {
        $this->bpg_void_date = $void_date;
        return $this;
    }

    public function getBankVoidDate()
    {
        return $this->bpg_void_date;
    }

    public function setBankECI($eci)
    {
        $this->eci = $eci;
        return $this;
    }

    public function getBankECI()
    {
        return $this->eci;
    }

    public function setBankResponseCode($response_code)
    {
        $this->bpg_response_code = $response_code;
        return $this;
    }

    public function getBankResponseCode()
    {
        return $this->bpg_response_code;
    }

    public function setBankResponseDescription($response_desc)
    {
        $this->bpg_response_desc = $response_desc;
        return $this;
    }

    public function getBankResponseDescription()
    {
        return $this->bpg_response_desc;
    }

    public function setBankMerchantTransactionID($merchant_trnx_id)
    {
        $this->bpg_merchange_transactionID = $merchant_trnx_id;
        $this->transactionID = $merchant_trnx_id;
        return $this;
    }

    public function getBankMerchantTransactionID()
    {
        return $this->bpg_merchange_transactionID;
    }

    public function setBankCustomerID($cust_id)
    {
        $this->bpg_user_profile_id = $cust_id;
        return $this;
    }

    public function getBankCustomerID()
    {
        return $this->bpg_user_profile_id;
    }

    public function setBankFraudLevel($fraud_level)
    {
        $this->bpg_fraud_level = $fraud_level;
        return $this;
    }

    public function getBankFraudLevel()
    {
        return $this->bpg_fraud_level;
    }

    public function setBankFraudScoring($fraud_scoring)
    {
        $this->bpg_fraud_scoring = $fraud_scoring;
        return $this;
    }

    public function getBankFraudScoring()
    {
        return $this->bpg_fraud_scoring;
    }

    public function getOption()
    {
        $option = array('merchant_no' => $this->_getMerchantNo(),
            'user_profile_id' => $this->getUserProfileID(),
            'transactionID' => $this->getTransactionID(),
            'transaction_amount' => $this->getTransactionAmount(),
            'transcation_currency' => $this->getTransactionCurrency(),
            'transaction_description' => $this->getTransactinDescription()
        );
        return json_encode($option);
    }
}