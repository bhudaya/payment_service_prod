<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\Core\IappsBaseDataMapper;

interface IPaymentModeLocationDataMapper extends IappsBaseDataMapper
{
    public function findAll($limit, $page);
    public function findByParam(PaymentModeLocation $paymentModeLocation, $limit, $page);
}