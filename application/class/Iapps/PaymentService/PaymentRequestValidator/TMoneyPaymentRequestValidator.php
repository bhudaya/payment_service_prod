<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

use Iapps\PaymentService\Common\TMoneySwitch\TMoneySwitchClient;
use Iapps\PaymentService\Common\TMoneySwitch\TMoneySwitchClientFactory;
use Iapps\PaymentService\Common\TMoneySwitch\TMoneySwitchClientValidator;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\PaymentAccess\PaymentAccessCheckerFactory;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;

class TMoneyPaymentRequestValidator extends PaymentRequestValidator
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
            return $this->request->getCountryCurrencyCode() == 'ID-IDR';
        }

        return false;
    }

    protected function _validateSwitchParameter()
    {
        $client = TMoneySwitchClientFactory::buildFromOption($this->request->getOption()->toArray());
        $v = TMoneySwitchClientValidator::make($client);

        return !$v->fails();
    }
}