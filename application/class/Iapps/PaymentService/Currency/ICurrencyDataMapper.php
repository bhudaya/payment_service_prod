<?php

namespace Iapps\PaymentService\Currency;

use Iapps\Common\Core\IappsBaseDataMapper;

interface ICurrencyDataMapper extends IappsBaseDataMapper{

    public function findByCode($code);
    public function findByCodes(array $codes);
    public function findAll($limit, $page);
    public function update(Currency $currency);
    public function add(Currency $currency);

    public function findByCodeOrName($search_value,$limit, $page);
}