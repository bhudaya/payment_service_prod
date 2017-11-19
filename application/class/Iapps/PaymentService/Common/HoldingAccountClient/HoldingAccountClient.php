<?php

namespace Iapps\PaymentService\Common\HoldingAccountClient;

use Iapps\Common\Helper\MicroserviceHelper\MicroserviceHelper;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClientInterface;

class HoldingAccountClient implements PaymentRequestClientInterface{

    protected $config = array();
    protected $_microServ;

    protected $module_code;
    protected $transactionID;
    protected $country_currency_code;
    protected $amount;
    protected $holding_account_type;
    protected $reference_id;
    protected $payment_code;
    protected $request_token;

    protected $_requestUri = '';
    protected $_cancelUri = '';
    protected $_completeUri = '';

    protected $_lastResponse;

    function __construct(array $config)
    {
        $this->config = $config;

        if( !$this->_getBaseUrl() OR
            !$this->_getHeaders() )
            throw new \Exception('invalid holding account client configuration');

        $this->_microServ = new MicroserviceHelper(array('base_url' => $this->_getBaseUrl()));
        $this->headers = $this->_getHeaders();
    }

    public function setLastResponse($response)
    {
        $this->_lastResponse = $response;
        return $this;
    }

    public function getLastResponse()
    {
        return $this->_lastResponse;
    }

    public static function fromOption(array $option)
    {
        $config = array();
        $config['header'] = null;
        $config['base_url'] = null;

        if( isset($option['headers']) )
            $config['header'] = $option['headers'];

        if( $url = getenv('HOLDING_ACCOUNT_SERVICE_URL') )
            $config['base_url'] = $url;

        $c = new static($config);

        if( isset($option['module_code']) )
            $c->setModuleCode($option['module_code']);

        if( isset($option['transactionID']) )
            $c->setTransactionID($option['transactionID']);

        if( isset($option['country_currency_code']) )
            $c->setCountryCurrencyCode($option['country_currency_code']);

        if( isset($option['amount']) )
            $c->setAmount($option['amount']);

        if( isset($option['holding_account_type']) )
            $c->setHoldingAccountType($option['holding_account_type']);

        if( isset($option['payment_code']) )
            $c->setPaymentCode($option['payment_code']);

        if( isset($option['reference_id']) )
            $c->setReferenceId($option['reference_id']);

        return $c;
    }

    protected function _getBaseUrl()
    {
        if( array_key_exists('base_url', $this->config) )
            return $this->config['base_url'];

        return false;
    }

    protected function _getHeaders()
    {
        if( array_key_exists('header', $this->config) )
        {
            if( is_array($this->config['header']) )
                return $this->config['header'];
        }

        return false;
    }

    public function setModuleCode($module_code)
    {
        $this->module_code = $module_code;
        return $this;
    }

    public function getModuleCode()
    {
        return $this->module_code;
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

    public function setCountryCurrencyCode($country_currency_code)
    {
        $this->country_currency_code = $country_currency_code;
        return $this;
    }

    public function getCountryCurrencyCode()
    {
        return $this->country_currency_code;
    }

    public function setAmount($amount)
    {
        $this->amount = $amount;
        return $this;
    }

    public function getAmount()
    {
        return $this->amount;
    }

    public function setHoldingAccountType($holding_account_type)
    {
        $this->holding_account_type = $holding_account_type;
        return $this;
    }

    public function getHoldingAccountType()
    {
        return $this->holding_account_type;
    }

    public function setReferenceId($reference_id)
    {
        $this->reference_id = $reference_id;
        return $this;
    }

    public function getReferenceId()
    {
        return $this->reference_id;
    }

    public function setPaymentCode($payment_code)
    {
        $this->payment_code = $payment_code;
        return $this;
    }

    public function getPaymentCode()
    {
        return $this->payment_code;
    }

    public function setToken($token)
    {
        $this->request_token = $token;
        return $this;
    }

    public function getToken()
    {
        return $this->request_token;
    }

    public function getOption()
    {
        $option = array('headers' => $this->_getHeaders(),
            'module_code' => $this->getModuleCode(),
            'transactionID' => $this->getTransactionID(),
            'country_currency_code' => $this->getCountryCurrencyCode(),
            'amount' => $this->getAmount(),
            'holding_account_type' => $this->getHoldingAccountType(),
            'reference_id' => $this->getReferenceId()
            );

        return json_encode($option);
    }

    public function request()
    {
        $option = array(
            'method' => 'post',
            'uri' => $this->_requestUri,
            'param' => array('module_code' => $this->getModuleCode(),
                            'transactionID' => $this->getTransactionID(),
                            'country_currency_code' => $this->getCountryCurrencyCode(),
                            'amount' => $this->getAmount(),
                            'payment_code' => $this->getPaymentCode(),
                            'holding_account_type' => $this->getHoldingAccountType(),
                            'reference_id' => $this->getReferenceId(),
                            ),
            'header' => $this->_getHeaders()
        );

        if( $resp = $this->_microServ->call($option) )
            $response['success'] = true;
        else
            $response['success'] = false;

        $response['response'] = $this->_microServ->getLastReponse();

        $this->setLastResponse($this->_microServ->getLastReponse());
        return new HoldingAccountUtilizationClientResponse($response);
    }

    public function cancel()
    {
        $option = array(
            'method' => 'post',
            'uri' => $this->_cancelUri,
            'param' => array('request_token' => $this->getToken()),
            'header' => $this->_getHeaders()
        );

        if( $resp = $this->_microServ->call($option) )
        {//cancelled
            $this->setLastResponse($this->_microServ->getLastReponse());
            return true;
        }

        $this->setLastResponse($this->_microServ->getLastReponse());
        return false;
    }

    public function complete()
    {
        $option = array(
            'method' => 'post',
            'uri' => $this->_completeUri,
            'param' => array('request_token' => $this->getToken()),
            'header' => $this->_getHeaders()
        );

        if( $resp = $this->_microServ->call($option) )
        {//completed
            $this->setLastResponse($this->_microServ->getLastReponse());
            return true;
        }

        $this->setLastResponse($this->_microServ->getLastReponse());
        return false;
    }
}