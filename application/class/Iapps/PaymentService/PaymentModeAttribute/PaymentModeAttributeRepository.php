<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseRepository;

class PaymentModeAttributeRepository extends IappsBaseRepository{

    public function findByPaymentCode($payment_code)
    {//todo use cached
        $filter = new PaymentModeAttribute();
        $filter->setPaymentCode($payment_code);
        return $this->findByFilter($filter);
    }

    public function findByFilter(PaymentModeAttribute $value)
    {
        $filters = new PaymentModeAttributeCollection();
        $filters->addData($value);
        return $this->findByFilters($filters);
    }

    public function findByFilters(PaymentModeAttributeCollection $collection)
    {
        return $this->getDataMapper()->findByFilters($collection);
    }
}