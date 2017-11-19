<?php

namespace Iapps\PaymentService\CountryCurrency;

use Iapps\Common\Core\IappsBaseDataMapper;

interface ICountryCurrencyDataMapper extends IappsBaseDataMapper{

    public function findByCode($code);
    public function findByCountryCode($country_code);
    public function findAll($limit, $page);
    public function add(CountryCurrency $country_currency);
}