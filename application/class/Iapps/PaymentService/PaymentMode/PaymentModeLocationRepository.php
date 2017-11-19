<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\Core\IappsBaseRepository;
use Iapps\PaymentService\Common\CacheKey;

class PaymentModeLocationRepository extends IappsBaseRepository
{
    public function findAll($limit, $page)
    {
        return $this->getDataMapper()->findAll($limit, $page);
    }

    public function findByParam(PaymentModeLocation $paymentModeLocation, $limit, $page)
    {
        return $this->getDataMapper()->findByParam($paymentModeLocation, $limit, $page);
    }

}