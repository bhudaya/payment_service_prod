<?php

namespace Iapps\PaymentService\PromoCode;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Currency\Currency;
use Iapps\Common\Microservice\CountryService\Country;

class PromoReward extends IappsBaseEntity{

    protected $mian_type;
    protected $sub_type;
    protected $promo_code;
    protected $currency;
    protected $amount;
    protected $transaction_type;
    protected $country;
    protected $start_date;
    protected $end_date;
    protected $expiry_period;
    protected $country_currency_code;

    function __construct()
    {
        parent::__construct();
        $this->start_date = new IappsDateTime();
        $this->end_date = new IappsDateTime();
        $this->currency = new Currency();
        $this->country = new Country();
    }

    public function setMainType($mian_type)
    {
        $this->mian_type = $mian_type;
        return $this;
    }

    public function getMainType()
    {
        return $this->mian_type;
    }

    public function setSubType($sub_type)
    {
        $this->sub_type = $sub_type;
        return $this;
    }

    public function getSubType()
    {
        return $this->sub_type;
    }

    public function setPromoCode($promo_code)
    {
        $this->promo_code = $promo_code;
        return $this;
    }

    public function getPromoCode()
    {
        return $this->promo_code;
    }

    public function setCurrency(Currency $currency)
    {
        $this->currency = $currency;
        return $this;
    }

    public function getCurrency()
    {
        return $this->currency;
    }

    public function setAmount($amount)
    {
        $this->amount = $amount;
        return $this;
    }

    public function getAmount()
    {
        return $this->amount;
    }

    public function setTransactionType($transaction_type)
    {
        $this->transaction_type = $transaction_type;
        return $this;
    }

    public function getTransactionType()
    {
        return $this->transaction_type;
    }

    public function setCountry(Country $country)
    {
        $this->country = $country;
        return $this;
    }

    public function getCountry()
    {
        return $this->country;
    }

    public function setStartDate(IappsDateTime $start_date)
    {
        $this->start_date = $start_date;
        return $this;
    }

    public function getStartDate()
    {
        return $this->start_date;
    }

    public function setEndDate(IappsDateTime $end_date)
    {
        $this->end_date = $end_date;
        return $this;
    }

    public function getEndDate()
    {
        return $this->end_date;
    }

    public function setExpiryPeriod($expiry_period)
    {
        $this->expiry_period = $expiry_period;
        return $this;
    }

    public function getExpiryPeriod()
    {
        return $this->expiry_period;
    }

    public function setCountryCurrencyCode($country_currency_code)
    {
        $this->country_currency_code = $country_currency_code;
        return $this;
    }

    public function getCountryCurrencyCode()
    {
        return $this->country_currency_code;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['mian_type'] = $this->getMainType();
        $json['sub_type'] = $this->getSubType();
        $json['promo_code'] = $this->getPromoCode();
        $json['currency'] = $this->getCurrency();
        $json['amount'] = $this->getAmount();
        $json['transaction_type'] = $this->getTransactionType();
        $json['country'] = $this->getCountry();
        $json['start_date'] = $this->getStartDate()->getString();
        $json['end_date'] = $this->getEndDate()->getString();
        $json['expiry_period'] = $this->getExpiryPeriod();
        $json['country_currency_code'] = $this->getCountryCurrencyCode();

        return $json;
    }
}