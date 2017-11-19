<?php

namespace Iapps\PaymentService\CountryCurrencyPaymentMode;

use Iapps\Common\Core\IappsBaseRepository;

class CountryCurrencyPaymentModeRepository extends IappsBaseRepository{

    public function findByCountryCode($country_code)
    {
        return $this->getDataMapper()->findByCountryCode($country_code);
    }

    public function findAll($limit, $page)
    {
        return $this->getDataMapper()->findAll($limit, $page);
    }

    public function findExistingPaymentMode($country_currency_code, $payment_mode_array)
    {
        return $this->getDataMapper()->findExistingPaymentMode($country_currency_code, $payment_mode_array);
    }

    public function add(CountryCurrencyPaymentMode $country_currency_payment_mode)
    {
        return $this->getDataMapper()->add($country_currency_payment_mode);
    }

    public function addBatch(CountryCurrencyPaymentModeCollection $country_currency_payment_mode_coll)
    {
        return $this->getDataMapper()->addBatch($country_currency_payment_mode_coll);
    }

    public function removeBatch($country_currency_code, $payment_mode_array_to_be_deleted, $updated_by)
    {
        return $this->getDataMapper()->removeBatch($country_currency_code, $payment_mode_array_to_be_deleted, $updated_by);
    }
}