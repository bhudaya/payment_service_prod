<?php

//todo move this to common package?
namespace Iapps\PaymentService\CodeMapper;

use Iapps\Common\Core\IappsBaseService;

class CodeMapperService extends IappsBaseService{

    public function getByReferenceValues(CodeMapperCollection $ref)
    {
        //get filter object
        $filters = new CodeMapperCollection();
        foreach($ref AS $reference)
        {
            if( $reference instanceof CodeMapper )
            {
                $filter = new CodeMapper();
                $filter->setType($reference->getType());
                $filter->setReferenceValue($reference->getReferenceValue());
                $filters->addData($filter);
            }
        }

        return $this->getRepository()->findByFilters($filters);
    }
}

