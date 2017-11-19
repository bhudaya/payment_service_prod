<?php

namespace Iapps\PaymentService\CountryCurrencyPaymentMode;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Core\IappsDateTime;

class CountryCurrencyPaymentMode extends IappsBaseEntity{

    private $country_code;
    private $country_currency_code;
    private $payment_mode_code;
    private $effective_at;
    private $currency_code;

    public function setCountryCode($country_code)
    {
        $this->country_code = strtoupper($country_code);
        return true;
    }

    public function setCountryCurrencyCode($country_currency_code)
    {
        $this->country_currency_code = $country_currency_code;
        return true;
    }

    public function setPaymentModeCode($payment_mode_code)
    {
        $this->payment_mode_code = $payment_mode_code;
        return true;
    }

    public function setEffectiveAt($effective_at)
    {
        $this->effective_at = $effective_at;
        return true;
    }

    public function setCurrencyCode($currency_code)
    {
        $this->currency_code = strtoupper($currency_code);
        return true;
    }

    public function getCountryCode()
    {
        return $this->country_code;
    }

    public function getCountryCurrencyCode()
    {
        return $this->country_currency_code;
    }

    public function getPaymentModeCode()
    {
        return $this->payment_mode_code;
    }

    public function getEffectiveAt()
    {
        return $this->effective_at;
    }

    public function getCurrencyCode()
    {
        return $this->currency_code;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['country_code'] = $this->getCountryCode();
        $json['country_currency_code'] = $this->getCountryCurrencyCode();
        $json['payment_mode_code'] = $this->getPaymentModeCode();
        $json['effective_at'] = $this->getEffectiveAt() ? $this->getEffectiveAt()->getString() : "";
        $json['currency_code'] = $this->getCurrencyCode();

        return $json;
    }
}