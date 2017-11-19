<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseEntityCollection;
use Iapps\PaymentService\Attribute\AttributeValueCollection;

class PaymentModeAttributeValueCollection extends IappsBaseEntityCollection{

    public function getAttributeValueIds()
    {
        $ids = array();
        foreach( $this AS $paymentModeAttributeValue)
        {
            if( $paymentModeAttributeValue instanceof PaymentModeAttributeValue )
            {
                $ids[] = $paymentModeAttributeValue->getAttributeValue()->getId();
            }
        }

        return $ids;
    }

    public function getPaymentModeAttributeIds()
    {
        $ids = array();
        foreach( $this AS $paymentModeAttributeValue)
        {
            if( $paymentModeAttributeValue instanceof PaymentModeAttributeValue )
            {
                $ids[] = $paymentModeAttributeValue->getPaymentModeAttribute()->getId();
            }
        }

        return $ids;
    }

    public function joinAttributeValue(AttributeValueCollection $attributeValueCollection)
    {
        foreach( $this AS $paymentModeAttributeValue)
        {
            if( $paymentModeAttributeValue instanceof PaymentModeAttributeValue )
            {
                if( $attribute = $attributeValueCollection->getById($paymentModeAttributeValue->getAttributeValue()->getId()) )
                    $paymentModeAttributeValue->setAttributeValue($attribute);
            }
        }

        return $this;
    }

    public function getByCode($code)
    {
        foreach($this AS $value)
        {
            if( $value->getCode() == $code)
                return $value;
        }

        return false;
    }


    public function groupByAttribute()
    {
        $by_attribute = array();
        foreach($this as $value)
        {
            if( $attribute_code = $value->getPaymentModeAttribute()->getAttribute() )
            {
                if( !array_key_exists($attribute_code, $by_attribute) )
                {
                    $by_attribute[$attribute_code] = array();
                    $by_attribute[$attribute_code]['attribute'] = $value->getPaymentModeAttribute();
                    $by_attribute[$attribute_code]['collection'] = new PaymentModeAttributeValueCollection();
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
            $value_arr['code'] = $value->getCode();
            $value_arr['value'] = $value->getValue();

            $by_country[$country][] = $value_arr;
        }

        return $by_country;
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


}