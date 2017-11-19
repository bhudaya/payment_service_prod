<?php

namespace Iapps\PaymentService\Common\OcbcCreditCardSwitch;

use Iapps\Common\Validator\IappsValidator;
use Iapps\PaymentService\Common\Logger;

class OcbcCreditCardSwitchClientValidator extends IappsValidator{

    protected $_client;
    protected $_function;

    public static function make(OcbcCreditCardSwitchClient $client, $function = OcbcCreditCardSwitchFunction::CODE_SALES)
    {
        $v = new OcbcCreditCardSwitchClientValidator();
        $v->_client = $client;
        $v->_function = $function;
        $v->validate();

        return $v;
    }

    public function validate()
    {
        $this->isFailed = true;

        if($this->_function == OcbcCreditCardSwitchFunction::CODE_SALES)
        {
            if( $this->_validateTransactionID() AND
                $this->_validateTransactionAmount() AND
                $this->_validateReturnUrl() )
            {
                $this->isFailed = false;
            }
        }else if($this->_function == OcbcCreditCardSwitchFunction::CODE_AUTHORIZATION)
        {
            if( $this->_validateTransactionID() AND
                $this->_validateTransactionAmount() AND
                $this->_validateReturnUrl() )
            {
                $this->isFailed = false;
            }
        }else if($this->_function == OcbcCreditCardSwitchFunction::CODE_QUERY_STATUS)
        {
            if( $this->_validateTransactionID() AND
                $this->_validateTransactionAmount() ){
                $this->isFailed = false;
            }
        }

        $this->isFailed = false;
    }

    protected function _validateTransactionID()
    {
        return ($this->_client->getTransactionID() != NULL);
    }

    protected function _validateTransactionAmount()
    {
        return ($this->_client->getTransactionAmount() != NULL);
    }

    protected function _validateReturnUrl()
    {
        return ($this->_client->_getReturnUrl() != NULL);
    }
}