<?php

namespace Iapps\PaymentService\CodeMapper;

use Iapps\Common\Core\IappsBaseRepository;

class CodeMapperRepository extends IappsBaseRepository{

    public function findByFilters(CodeMapperCollection $filter)
    {
        return $this->getDataMapper()->findByFilters($filter);
    }

}