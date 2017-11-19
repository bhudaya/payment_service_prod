<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

use Iapps\PaymentService\Common\GPLSwitch\GPLSwitchClientFactory;
use Iapps\PaymentService\Common\GPLSwitch\GPLSwitchClientValidator;

class GPLPaymentRequestValidator extends PaymentRequestValidator
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

    protected function _validateSwitchParameter()
    {
        $client = GPLSwitchClientFactory::buildFromOption($this->request->getOption()->toArray());
        $v = GPLSwitchClientValidator::make($client);

        return !$v->fails();
    }
}