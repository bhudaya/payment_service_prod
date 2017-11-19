<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\PaymentService\PaymentMode\PaymentMode;

class PaymentModeValidator {

    protected $payment_mode;
    protected $isFailed = true;

    public static function make(PaymentMode $payment_mode)
    {
        $v = new PaymentModeValidator();
        $v->payment_mode = $payment_mode;
        $v->validate();

        return $v;
    }

    public function fails()
    {
        return $this->isFailed;
    }

    public function setPaymentMode(PaymentMode $payment_mode)
    {
        $this->payment_mode = $payment_mode;
        return true;
    }

    public function getPaymentMode()
    {
        return $this->payment_mode;
    }

    public function validate()
    {
        $this->isFailed = true;

        if( $this->_validateCode($this->getPaymentMode()->getCode()) AND
            $this->_validateName($this->getPaymentMode()->getName()) )
        {
            $this->isFailed = false;
            return true;
        }

        return false;
    }

    protected function _validateCode($code)
    {//make sure it three character code
        return (strlen($code) == 3 AND ctype_upper($code));
    }

    protected function _validateName($name)
    {//not sure what to validate for now
        return ($name !== NULL);
    }
}