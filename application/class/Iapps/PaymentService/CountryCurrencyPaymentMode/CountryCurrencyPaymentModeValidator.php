<?php

namespace Iapps\PaymentService\CountryCurrencyPaymentMode;

use Iapps\PaymentService\CountryCurrencyPaymentMode\CountryCurrencyPaymentMode;

class CountryCurrencyPaymentModeValidator {

    protected $country_currency_payment_mode;
    protected $isFailed = true;

    public static function make(CountryCurrencyPaymentMode $country_currency_payment_mode)
    {
        $v = new CountryCurrencyPaymentModeValidator();
        $v->country_currency_payment_mode = $country_currency_payment_mode;
        $v->validate();

        return $v;
    }

    public function fails()
    {
        return $this->isFailed;
    }

    public function setCountryCurrencyPaymentMode(CountryCurrencyPaymentMode $country_currency_payment_mode)
    {
        $this->country_currency_payment_mode = $country_currency_payment_mode;
        return true;
    }

    public function getCountryCurrencyPaymentMode()
    {
        return $this->country_currency_payment_mode;
    }

    public function validate()
    {
        $this->isFailed = true;

        if( $this->_validateCountryCurrencyCode($this->getCountryCurrencyPaymentMode()->getCountryCurrencyCode()) AND
            $this->_validatePaymentModeCode($this->getCountryCurrencyPaymentMode()->getPaymentModeCode()))
        {
            $this->isFailed = false;
            return true;
        }

        return false;
    }

    protected function _validateCountryCurrencyCode($country_currency_code)
    {//make sure it six character code
        return (strlen($country_currency_code) == 6);
    }

    protected function _validatePaymentModeCode($payment_mode_code)
    {//make sure it three character code
        return (strlen($payment_mode_code) == 3);
    }
}