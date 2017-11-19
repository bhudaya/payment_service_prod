<?php

namespace Iapps\PaymentService\Common\TMoneySwitch;

use Iapps\Common\Validator\IappsValidator;
use Iapps\PaymentService\Common\Logger;

class TMoneySwitchClientValidator extends IappsValidator{

    protected $_client;
    protected $_function;

    public static function make(TMoneySwitchClient $client, $function = TMoneySwitchFunction::CODE_REMIT)
    {
        $v = new TMoneySwitchClientValidator();
        $v->_client = $client;
        $v->_function = $function;
        $v->validate();

        return $v;
    }

    public function validate()
    {
        $this->isFailed = true;

        if($this->_function == TMoneySwitchFunction::CODE_REMIT)
        {
            if( $this->_validateReferenceNo() AND
                //$this->_validateSignedData() AND
                $this->_validateSenderFullname() AND
                $this->_validateSenderAddress() AND
                $this->_validateReceiverFullname() AND
                $this->_validateReceiverAddress() AND
                $this->_validateReceiverMobilePhone() AND
                $this->_validateAccountNo() AND
                $this->_validateLandedAmount() )
            {
                $this->isFailed = false;
            }
        }else if($this->_function == TMoneySwitchFunction::CODE_INQUIRY)
        {
           // if( $this->_validateReferenceNo() AND
           //     $this->_validateSignedData())
           // {
            if( $this->_validateReferenceNo() ){
                $this->isFailed = false;
            }
        }

        $this->isFailed = false;
    }

    protected function _validateReferenceNo()
    {
        return ($this->_client->getReferenceNo() != NULL);
    }

    protected function _validateSignedData()
    {

        return ($this->_client->getSignedData() != NULL);
    }

    protected function _validateLandedAmount()
    {
        return ($this->_client->getLandedAmount() != NULL);
    }

    protected function _validateAccountNo()
    {
        return ($this->_client->getAccountNo() != NULL || strlen($this->_client->getAccountNo())>20);
    }

    protected function _validateSenderFullname()
    {
        return ($this->_client->getSenderFullname() != NULL);
    }

    protected function _validateReceiverFullname()
    {
        return ($this->_client->getReceiverFullname() != NULL);
    }

    protected function _validateSenderAddress()
    {
        return ($this->_client->getSenderAddress() != NULL);
    }

    protected function _validateReceiverAddress()
    {
        return ($this->_client->getReceiverAddress() != NULL);
    }


    protected function _validateReceiverMobilePhone()
    {
        return ($this->_client->getReceiverMobilePhone() != NULL);
    }

}