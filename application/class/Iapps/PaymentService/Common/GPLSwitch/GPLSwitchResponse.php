<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

use Iapps\Common\Helper\ResponseMessage;
use Iapps\PaymentService\PaymentRequest\PaymentRequestResponseInterface;
use Iapps\Common\Helper\StringMasker;

class GPLSwitchResponse implements PaymentRequestResponseInterface{

    protected $raw;

    protected $response_code;
    protected $response_message;
    protected $bill_no;
    protected $third_party_pin;
    protected $customer_ref_no;
    protected $member_number;

    function __construct(array $response)
    {
        $this->setRaw($response);
    }

    protected function _extractResponse(array $fields)
    {
        foreach($fields AS $field => $value )
        {
            if( $field == 'response_code' )
                $this->setResponseCode($value);
            if( $field == 'response_message')
                $this->setResponseMessage($value);
            if( $field == 'bill_no')
                $this->setBillNo($value);
            if( $field == 'third_party_pin')
                $this->setThirdPartyPin($value);
            if( $field == 'customer_ref_no')
                $this->setCustomerRefNo($value);
            if( $field == 'member_number')
                $this->setMemberNumber($value);
        }
    }

    public function setRaw($raw)
    {
        $this->raw = $raw;
        $this->_extractResponse($raw);
        return $this;
    }

    public function getRaw()
    {
        return $this->raw;
    }

    public function setResponseCode($response_code)
    {
        $this->response_code = $response_code;
        return $this;
    }

    public function getResponseCode()
    {
        return $this->response_code;
    }

    public function setResponseMessage($response_message)
    {
        $this->response_message = $response_message;
        return $this;
    }

    public function getResponseMessage()
    {
        return $this->response_message;
    }

    public function setBillNo($bill_no)
    {
        $this->bill_no = $bill_no;
        return $this;
    }

    public function getBillNo()
    {
        return $this->bill_no;
    }

    public function setThirdPartyPin($third_party_pin)
    {
        $this->third_party_pin = $third_party_pin;
        return $this;
    }

    public function getThirdPartyPin()
    {
        return $this->third_party_pin;
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

    public function setMemberNumber($member_number)
    {
        $this->member_number = $member_number;
        return $this;
    }

    public function getMemberNumber()
    {
        return $this->member_number;
    }

    public function isSuccess()
    {
        return ( $this->getResponseCode() == "0");
    }

    public function isPending()
    {
        return ( $this->getResponseCode() == "50");
    }

    public function getResponse()
    {
        $response = $this->getRaw();
        return json_encode($response);
    }
}
