<?php

namespace Iapps\PaymentService\CountryCurrencyPaymentMode;

use Iapps\Common\Core\IappsBaseDataMapper;

interface ICountryCurrencyPaymentModeDataMapper extends IappsBaseDataMapper{

    public function findByCountryCode($country_code);
    public function findAll($limit, $page);
    public function findExistingPaymentMode($country_currency_code, $payment_mode_array);
    public function add(CountryCurrencyPaymentMode $country_currency_payment_mode);
    public function addBatch(CountryCurrencyPaymentModeCollection $country_currency_payment_mode_coll);
	public function removeBatch($country_currency_code, $payment_mode_array_to_be_deleted, $updated_by);
}