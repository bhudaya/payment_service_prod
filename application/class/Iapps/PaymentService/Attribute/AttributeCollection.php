<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\Common\Core\IappsBaseEntityCollection;

class AttributeCollection extends IappsBaseEntityCollection{

    public function joinAttributeValue(AttributeValueCollection $attributeValueCollection)
    {
        foreach($this AS $attribute)
        {
            if( $attribute instanceof Attribute )
            {
                foreach($attributeValueCollection AS $attributeValue)
                {
                    if($attributeValue->getAttribute()->getCode() == $attribute->getCode())
                    {
                        $attribute->getAttributeValues()->addData($attributeValue);
                    }
                }
            }
        }

        return $this;
    }

    public function getByCode($code)
    {
        foreach($this AS $attribute)
        {
            if( $attribute instanceof Attribute )
            {
                if($attribute->getCode() == $code)
                {
                    return $attribute;
                }
            }
        }

        return false;
    }
}