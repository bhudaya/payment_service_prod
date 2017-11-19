<?php

namespace Iapps\PaymentService\CodeMapper;

use Iapps\Common\Core\IappsBaseDataMapper;

interface ICodeMapperDataMapper extends IappsBaseDataMapper{

    public function findByFilters(CodeMapperCollection $collection);
}