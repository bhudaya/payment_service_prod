<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\Core\IappsBaseDataMapper;

interface IPaymentModeDataMapper extends IappsBaseDataMapper
{

    public function findByCode($code);

    public function findAll($limit, $page);

    public function findByParam(PaymentMode $paymentMode, $limit, $page);
    public function findByFilters(PaymentModeCollection $filters);
}