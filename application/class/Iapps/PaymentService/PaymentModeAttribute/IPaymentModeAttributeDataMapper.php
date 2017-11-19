<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseDataMapper;

interface IPaymentModeAttributeDataMapper extends IappsBaseDataMapper{
    public function findByFilters(PaymentModeAttributeCollection $collection);
}