<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

use Iapps\Common\Helper\HttpService;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClientInterface;

class GPLSwitchClient implements PaymentRequestClientInterface{

    protected $customer_ref_no;
    protected $_company;
    protected $sender;
    protected $receiver;
    protected $trx;
    protected $checksum;

    protected $_transferUri = 'api/transfer';
    protected $_inquiryUri = 'api/Inquiry';
    private $config;

    function __construct(array $config)
    {
        $this->config = $config;

        $this->_http_serv = new HttpService();
        $this->_http_serv->setUrl($this->_getUrl());

        $this->_company = new GPLCompany();
        $this->sender = new GPLMemberSender();
        $this->receiver = new GPLMemberReceiver();
        $this->trx = new GPLTransaction();
    }

    protected function _getUrl()
    {
        if( array_key_exists('url', $this->config) )
            return $this->config['url'];

        return false;
    }

    public function setCustomerRefNo($customer_ref_no)
    {
        $this->customer_ref_no = $customer_ref_no;
        return $this;
    }

    public function getCustomerRefNo()
    {
        return $this->customer_ref_no;
    }

    public function setCompany(GPLCompany $_company)
    {
        $this->_company = $_company;
        return $this;
    }

    public function getCompany()
    {
        return $this->_company;
    }

    public function setSender(GPLMemberSender $sender)
    {
        $this->sender = $sender;
        return $this;
    }

    public function getSender()
    {
        return $this->sender;
    }

    public function setReceiver(GPLMemberReceiver $receiver)
    {
        $this->receiver = $receiver;
        return $this;
    }

    public function getReceiver()
    {
        return $this->receiver;
    }

    public function setTrx(GPLTransaction $trx)
    {
        $this->trx = $trx;
        return $this;
    }

    public function getTrx()
    {
        return $this->trx;
    }

    public function setChecksum($checksum)
    {
        $this->checksum = $checksum;
        return $this;
    }

    public function getChecksum()
    {
        return $this->checksum;
    }

    public function bankTransfer()
    {
        $option = json_decode($this->getOption(),true);

        $header = array(
            'Accept'        => 'application/json',
            'Content-Type'  => 'application/json'
        );

        //curl
        $this->_http_serv->post($header, $option, $this->_transferUri, 'json');
        return new GPLSwitchResponse($this->_http_serv->getLastResponse());
    }

    public function inquiry()
    {
        $option = array(
            "customer_ref_no" => $this->getCustomerRefNo(),
            "_company" => $this->getCompany()->jsonSerialize()
        );

        $header = array(
            'Accept'        => 'application/json',
            'Content-Type'  => 'application/json'
        );

        //curl
        $this->_http_serv->post($header, $option, $this->_inquiryUri, 'json');
        return new GPLSwitchResponse($this->_http_serv->getLastResponse());
    }

    public function getOption()
    {
        $option = array('customer_ref_no' => $this->getCustomerRefNo(),
                        '_company' => $this->getCompany()->jsonSerialize(),
                        'sender' => $this->getSender()->jsonSerialize(),
                        'receiver' => $this->getReceiver()->jsonSerialize(),
                        'trx' => $this->getTrx()->jsonSerialize(),
                        'checkSum' => $this->getChecksum()
        );


        return json_encode($option, JSON_UNESCAPED_SLASHES);
    }

    public function setFromOption(array $option)
    {
        if( array_key_exists('customer_ref_no', $option) )
            $this->setCustomerRefNo($option['customer_ref_no']);

        if( array_key_exists('_company', $option) )
            $this->setCompany(GPLCompany::fromOption($option['_company']));

        if( array_key_exists('sender', $option) )
            $this->setSender(GPLMemberSender::fromOption($option['sender']));

        if( array_key_exists('receiver', $option) )
            $this->setReceiver(GPLMemberReceiver::fromOption($option['receiver']));

        if( array_key_exists('trx', $option) )
            $this->setTrx(GPLTransaction::fromOption($option['trx']));

        if( array_key_exists('checkSum', $option) )
            $this->setChecksum($option['checkSum']);

        return $this;
    }
}
