<?php

namespace Iapps\PaymentService\CountryCurrency;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Core\IappsDateTime;

class CountryCurrency extends IappsBaseEntity{

    private $code;
    private $country_code;
    private $currency_code;

    public function setCode($code)
    {
        $this->code = strtoupper($code);
        return true;
    }

    public function setCountryCode($country_code)
    {
        $this->country_code = $country_code;
        return true;
    }

    public function setCurrencyCode($currency_code)
    {
        $this->currency_code = $currency_code;
        return true;
    }

    public function getCode()
    {
        return $this->code;
    }

    public function getCountryCode()
    {
        return $this->country_code;
    }

    public function getCurrencyCode()
    {
        return $this->currency_code;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['code'] = $this->getCode();
        $json['country_code'] = $this->getCountryCode();
        $json['currency_code'] = $this->getCurrencyCode();

        return $json;
    }
}