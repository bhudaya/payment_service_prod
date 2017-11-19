<?php

namespace Iapps\PaymentService\Currency;

use Iapps\PaymentService\Currency\Currency;

class CurrencyValidator {

    protected $currency;
    protected $isFailed = true;

    public static function make(Currency $currency)
    {
        $v = new CurrencyValidator();
        $v->currency = $currency;
        $v->validate();

        return $v;
    }

    public function fails()
    {
        return $this->isFailed;
    }

    public function setCurrency(Currency $currency)
    {
        $this->currency = $currency;
        return true;
    }

    public function getCurrency()
    {
        return $this->currency;
    }

    public function validate()
    {
        $this->isFailed = true;

        if( $this->_validateCode($this->getCurrency()->getCode()) AND
            $this->_validateName($this->getCurrency()->getName()) AND
            $this->_validateDenomination($this->getCurrency()->getDenomination()));
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

    protected function _validateDenomination($denomination)
    {//make sure its digit
        return (is_numeric($denomination));
    }
}