<?php

namespace Iapps\PaymentService\Common\IndoOcbcSwitch;

use Iapps\Common\Core\IappsDateTime;
use Iapps\Common\Helper\HttpService;
use Iapps\Common\Helper\StringMasker;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClientInterface;

class IndoOcbcSwitchClient implements PaymentRequestClientInterface{

    protected $config = array();
    protected $_http_serv;

    protected $_bankTransferUri = 'transfer_bank';

    protected $product_code = 800;
    protected $merchant_code = 6012;
    protected $terminal_code;
    protected $dest_refnumber;
    protected $dest_bankcode;
    protected $dest_bankaccount;
    protected $dest_amount;

    function __construct(array $config)
    {
        $this->config = $config;

        if( !$this->_getUserName() OR
            !$this->_getPassword() OR
            !$this->_getUrl() )
            throw new \Exception('invalid switch configuration');

        $this->_http_serv = new HttpService();
        $this->_http_serv->setUrl($this->_getUrl());
    }

    protected function _getUserName()
    {
        if( array_key_exists('username', $this->config) )
            return $this->config['username'];

        return false;
    }

    protected function _getPassword()
    {
        if( array_key_exists('password', $this->config) )
            return $this->config['password'];

        return false;
    }

    public static function fromOption(array $config, array $option)
    {
        $c = new IndoOcbcSwitchClient($config);

        if( isset($option['product_code']) )
            $c->setProductCode($option['product_code']);

        if( isset($option['merchant_code']) )
            $c->setMerchantCode($option['merchant_code']);

        if( isset($option['terminal_code']) )
            $c->setTerminalCode($option['terminal_code']);

        if( isset($option['dest_refnumber']) )
            $c->setDestRefNumber($option['dest_refnumber']);

        if( isset($option['dest_bankcode']) )
            $c->setDestBankCode($option['dest_bankcode']);

        if( isset($option['dest_bankacc']) )
            $c->setDestBankAccount($option['dest_bankacc']);

        if( isset($option['dest_amount']) )
            $c->setDestAmount($option['dest_amount']);

        return $c;
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
        else if( getenv('INDO_SWITCH_URL') )
            return getenv('INDO_SWITCH_URL');


        return false;
    }

    //getter/setter
    public function setProductCode($code)
    {
        $this->product_code = $code;
        return $this;
    }

    public function getProductCode()
    {
        return $this->product_code;
    }

    public function setMerchantCode($code)
    {
        $this->merchant_code = $code;
        return $this;
    }

    public function getMerchantCode()
    {
        return $this->merchant_code;
    }

    public function setTerminalCode($code)
    {
        $this->terminal_code = $code;
        return $this;
    }

    public function getTerminalCode()
    {
        return $this->terminal_code;
    }

    public function setDestRefNumber($ref)
    {
        $this->dest_refnumber = $ref;
        return $this;
    }

    public function getDestRefNumber()
    {
        return $this->dest_refnumber;
    }

    public function setDestBankCode($code)
    {
        $this->dest_bankcode = $code;
        return $this;
    }

    public function getDestBankCode()
    {
        return $this->dest_bankcode;
    }

    public function setDestBankAccount($account)
    {
        $this->dest_bankaccount = $account;
        return $this;
    }

    public function getDestBankAccount()
    {
        return $this->dest_bankaccount;
    }

    public function setDestAmount($amount)
    {
        $this->dest_amount = $amount;
        return $this;
    }

    public function getDestAmount()
    {
        return $this->dest_amount;
    }

    public function bankTransfer()
    {
        //generate signature
        $signature = IndoOcbcSwitchSignature::generate($this->_getUserName(), $this->_getPassword(),
                                                       $this->getProductCode(),
                                                       $this->getMerchantCode(),
                                                       $this->getTerminalCode(),
                                                       $this->getDestRefNumber(),
                                                       $this->getDestBankCode(),
                                                       $this->getDestBankAccount(),
                                                       $this->getDestAmount());

        $header = array
        (
            'X-Auth' => $this->_getUserName(),
            'X-Signature' => $signature
        );

        $option = array('username' => $this->_getUserName(),
                        'product_code' => $this->getProductCode(),
                        'merchant_code' => $this->getMerchantCode(),
                        'terminal_code' => $this->getTerminalCode(),
                        'dest_refnumber' => $this->getDestRefNumber(),
                        'dest_bankcode' => $this->getDestBankCode(),
                        'dest_bankacc' => $this->getDestBankAccount(),
                        'dest_amount' => $this->getDestAmount()
        );

        //curl
        $this->_http_serv->post($header, $option, $this->_bankTransferUri);
        return new IndoOcbcSwitchResponse($this->_http_serv->getLastResponse());
    }

    public function getOption()
    {
        $option = array('username' => $this->_getUserName(),
                        'product_code' => $this->getProductCode(),
                        'merchant_code' => $this->getMerchantCode(),
                        'terminal_code' => $this->getTerminalCode(),
                        'dest_refnumber' => $this->getDestRefNumber(),
                        'dest_bankcode' => $this->getDestBankCode(),
                        'dest_bankacc' => $this->getDestBankAccount(),
                        'dest_amount' => $this->getDestAmount() );

        //if( array_key_exists('dest_bankacc', $option) )
        //    $option['dest_bankacc'] = StringMasker::mask($option['dest_bankacc'], 3);

        return json_encode($option);
    }
}