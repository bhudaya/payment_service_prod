<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

use Iapps\PaymentService\Common\OcbcCreditCardSwitch\OcbcCreditCardSwitchClient;
use Iapps\PaymentService\Common\OcbcCreditCardSwitch\OcbcCreditCardSwitchClientFactory;
use Iapps\PaymentService\Common\OcbcCreditCardSwitch\OcbcCreditCardSwitchClientValidator;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\PaymentAccess\PaymentAccessCheckerFactory;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;

class OcbcCreditCardPaymentRequestValidator extends PaymentRequestValidator
{
    public function validate()
    {
        parent::validate();

        if( !$this->fails() )
        {
            if( !$this->_validateSwitchParameter() )
               $this->isFailed = true;
        }

        $this->isFailed = false;
    }

    protected function _validateCountryCurrency()
    {
        if( parent::_validateCountryCurrency() )
        {
            return $this->request->getCountryCurrencyCode() == 'SG-SGD';
        }

        return false;
    }

    protected function _validateSwitchParameter()
    {
        $client = OcbcCreditCardSwitchClientFactory::buildFromOption($this->request->getOption()->toArray());
        $v = OcbcCreditCardSwitchClientValidator::make($client);

        return !$v->fails();
    }
}