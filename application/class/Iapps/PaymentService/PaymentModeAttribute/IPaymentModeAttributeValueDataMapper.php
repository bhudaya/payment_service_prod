<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseDataMapper;

interface IPaymentModeAttributeValueDataMapper extends IappsBaseDataMapper{
    public function findByFilters(PaymentModeAttributeValueCollection $paymentModeAttributeValueCollection);
}