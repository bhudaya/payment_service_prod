<?php

namespace Iapps\PaymentService\CountryCurrency;

use Iapps\PaymentService\CountryCurrency\CountryCurrency;

class CountryCurrencyValidator {

    protected $country_currency;
    protected $isFailed = true;

    public static function make(CountryCurrency $country_currency)
    {
        $v = new CountryCurrencyValidator();
        $v->country_currency = $country_currency;
        $v->validate();

        return $v;
    }

    public function fails()
    {
        return $this->isFailed;
    }

    public function setCountryCurrency(CountryCurrency $country_currency)
    {
        $this->country_currency = $country_currency;
        return true;
    }

    public function getCountryCurrency()
    {
        return $this->country_currency;
    }

    public function validate()
    {
        $this->isFailed = true;

        if( $this->_validateCountryCode($this->getCountryCurrency()->getCountryCode()) AND
            $this->_validateCurrencyCode($this->getCountryCurrency()->getCurrencyCode()))
        {
            $this->isFailed = false;
            return true;
        }

        return false;
    }

    protected function _validateCountryCode($country_code)
    {//make sure it two character code
        return (strlen($country_code) == 2 AND ctype_upper($country_code));
    }

    protected function _validateCurrencyCode($currency_code)
    {//make sure it three character code
        return (strlen($currency_code) == 3 AND ctype_upper($currency_code));
    }
}