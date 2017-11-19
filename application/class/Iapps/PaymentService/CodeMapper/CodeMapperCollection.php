<?php

namespace Iapps\PaymentService\CodeMapper;

use Iapps\Common\Core\IappsBaseEntityCollection;

class CodeMapperCollection extends IappsBaseEntityCollection{

    public function getByReferenceValue($ref, $type)
    {
        foreach($this AS $codeMapper)
        {
            if( $codeMapper instanceof CodeMapper )
            {
                if($codeMapper->getReferenceValue() == $ref AND
                    $codeMapper->getType()->getCode() == $type )
                    return $codeMapper;
            }
        }

        return false;
    }
}