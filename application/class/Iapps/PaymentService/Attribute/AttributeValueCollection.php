<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\Common\Core\IappsBaseEntityCollection;

class AttributeValueCollection extends IappsBaseEntityCollection{

    public function groupByAttributeCode()
    {
        $by_attribute = array();
        foreach($this as $value)
        {
            if( $attribute_code = $value->getAttribute()->getCode() )
            {
                if( !array_key_exists($attribute_code, $by_attribute) )
                {
                    $by_attribute[$attribute_code] = array();
                    $by_attribute[$attribute_code]['attribute'] = $value->getAttribute();
                    $by_attribute[$attribute_code]['collection'] = new AttributeValueCollection();
                }

                $by_attribute[$attribute_code]['collection']->addData($value);
            }
        }

        return $by_attribute;
    }

    public function groupByCountryCode()
    {
        $by_country = array();
        foreach($this as $value)
        {
            if( !$country = $value->getCountryCode() )
                $country = 'none';

            if( !array_key_exists($country, $by_country) )
                $by_country[$country] = array();

            $value_arr = array();
            $value_arr['id'] = $value->getId();
            $value_arr['value'] = $value->getValue();

            $by_country[$country][] = $value_arr;
        }

        return $by_country;
    }

    public function hasAttribute(Attribute $attribute)
    {
        foreach($this as $attributeValue)
        {
            if( $attributeValue instanceof AttributeValue )
            {
                if($attributeValue->getAttribute()->equals($attribute))
                    return $attributeValue;
            }
        }

        return false;
    }

    public function hasValue($value)
    {
        foreach($this as $ref_value)
        {
            if( $ref_value->getValue() == $value )
                return true;
        }

        return false;
    }

    public function getByCode($code, $country_code = NULL)
    {
        foreach($this AS $attributeVal)
        {
            if( $attributeVal instanceof AttributeValue )
            {
                if($attributeVal->getCode() == $code)
                {
                    if( $country_code != NULL )
                    {
                        if($attributeVal->getCountryCode() == NULL OR $attributeVal->getCountryCode() == $country_code)
                            return $attributeVal;
                    }
                    else
                        return $attributeVal;
                }
            }
        }

        return false;
    }
}