<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseRepository;

class PaymentModeAttributeValueRepository extends IappsBaseRepository{

    public function findByPaymentModeAttributeId($payment_mode_attribute_id)
    {//todo cache
        $filters = new PaymentModeAttributeValueCollection();
        $filters->addData((new PaymentModeAttributeValue())->setId($payment_mode_attribute_id));
        return $this->findByFilters($filters);
    }

    public function findByFilters(PaymentModeAttributeValueCollection $collection)
    {
        return $this->getDataMapper()->findByFilters($collection);
    }
}