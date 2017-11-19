<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

use Iapps\PaymentService\Common\IndoOcbcSwitch\IndoOcbcSwitchClient;
use Iapps\PaymentService\Common\IndoOcbcSwitch\IndoOcbcSwitchClientFactory;
use Iapps\PaymentService\Common\IndoOcbcSwitch\IndoOcbcSwitchClientValidator;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\PaymentAccess\PaymentAccessCheckerFactory;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;

class BTIndoOCBCPaymentRequestValidator extends PaymentRequestValidator
{
    public function validate()
    {
        parent::validate();

        if( !$this->fails() )
        {
            if( !$this->_validateSwitchParameter() )
                $this->isFailed = true;
        }
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
        $client = IndoOcbcSwitchClientFactory::buildFromOption($this->request->getOption()->toArray());
        $v = IndoOcbcSwitchClientValidator::make($client);

        return !$v->fails();
    }
}