<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

class KioskPaymentRequestValidator extends PaymentRequestValidator{

    public function validate()
    {
        parent::validate();

        if( !$this->fails() )
        {
            if( !$this->_validateAmount() )
            {
                $this->isFailed = true;
            }
        }
    }

    protected function _validateAmount()
    {
        return ($this->request->getAmount() > 0.0);
    }
}