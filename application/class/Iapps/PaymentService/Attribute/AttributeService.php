<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IappsBaseService;

class AttributeService extends IappsBaseService{

    public function getByIds(array $ids)
    {
        if($info = $this->getRepository()->findByIds($ids) )
        {
            return $info->result;
        }

        return false;
    }

    public function getAllAttribute()
    {
        if( $attribute = $this->getRepository()->findAll() )
        {
            $this->setResponseCode(MessageCode::CODE_ATTRIBUTE_FOUND);
            return $attribute->result;
        }

        $this->setResponseCode(MessageCode::CODE_ATTRIBUTE_NOT_FOUND);
        return false;
    }

    public function getByCode($code)
    {
        if( $attribute = $this->getRepository()->findByCode($code) )
        {
            $this->setResponseCode(MessageCode::CODE_ATTRIBUTE_FOUND);
            return $attribute;
        }

        $this->setResponseCode(MessageCode::CODE_ATTRIBUTE_NOT_FOUND);
        return false;
    }

    public function getByCodes(AttributeCollection $attributeCollection)
    {
        if( $info = $this->getRepository()->findByFilters($attributeCollection) )
        {
            return $info->result;
        }

        return false;
    }
}