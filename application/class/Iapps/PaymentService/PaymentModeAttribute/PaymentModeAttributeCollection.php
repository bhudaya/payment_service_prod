<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseEntityCollection;
use Iapps\PaymentService\Attribute\AttributeCollection;
use Iapps\PaymentService\PaymentMode\PaymentMode;
use Iapps\PaymentService\PaymentMode\PaymentModeCollection;

class PaymentModeAttributeCollection extends IappsBaseEntityCollection{

    public function getAttributeIds()
    {
        $ids = array();
        foreach( $this AS $paymentModeAttribute)
        {
            if( $paymentModeAttribute instanceof PaymentModeAttribute )
            {
                $ids[] = $paymentModeAttribute->getAttribute()->getId();
            }
        }

        return $ids;
    }

    public function joinAttribute(AttributeCollection $attributeCollection)
    {
        foreach( $this AS $paymentModeAttribute)
        {
            if( $paymentModeAttribute instanceof PaymentModeAttribute )
            {
                if( $attribute = $attributeCollection->getById($paymentModeAttribute->getAttribute()->getId()) )
                    $paymentModeAttribute->setAttribute($attribute);
            }
        }

        return $this;
    }

    public function joinPaymentMode(PaymentModeCollection $paymentModeCollection)
    {
        foreach( $this AS $paymentModeAttribute)
        {
            if( $paymentModeAttribute instanceof PaymentModeAttribute )
            {
                if( $pm = $paymentModeCollection->getByCode($paymentModeAttribute->getPaymentMode()->getCode()) )
                    $paymentModeAttribute->setPaymentMode($pm);
            }
        }

        return $this;
    }

    public function joinPaymentModeAttributeValue(PaymentModeAttributeValueCollection $paymentModeAttributeValueCollection)
    {
        foreach( $paymentModeAttributeValueCollection AS $paymentModeAttributeValue)
        {
            if( $paymentModeAttributeValue instanceof PaymentModeAttributeValue )
            {
                if( $attribute = $this->getById($paymentModeAttributeValue->getPaymentModeAttribute()->getId()) )
                {
                    $attribute->getValue()->addData($paymentModeAttributeValue);
                }
            }
        }

        return $this;

    }

    public function sortByDisplayOrder()
    {
        $data = $this->toArray();

        if( $sortedArray = usort($data, array($this, "_sortByDisplayOrder") ))
        {
            $sortedCollection = new PaymentModeAttributeCollection();
            foreach($data AS $attribute)
            {
                $sortedCollection->addData($attribute);
            }

            return $sortedCollection;
        }

        return $this;
    }

    // Define the custom sort function
    private function _sortByDisplayOrder($a,$b) {
        if( $a instanceof PaymentModeAttribute AND
            $b instanceof PaymentModeAttribute )
        {
            if( $b->getAttribute()->getDisplayOrder() != NULL )
                $b_order = $b->getAttribute()->getDisplayOrder();
            else
                $b_order = -1;

            if( $a->getAttribute()->getDisplayOrder() != NULL )
                $a_order = $a->getAttribute()->getDisplayOrder();
            else
                $a_order = -1;

            return $a_order > $b_order;
        }

        //remain same order if
        return false;
    }

    /**
     * 
     * @param string $code
     * @return PaymentModeAttribute
     */
    public function getByAttributeCode($code)
    {
        foreach( $this AS $paymentModeAttribute)
        {
            if( $paymentModeAttribute->getAttribute()->getCode() == $code )
            {
                return $paymentModeAttribute;
            }
        }
        
        return false;
    }
    
    public function getByPaymentModeGroup($code)
    {
        $result = array();
        foreach( $this AS $paymentModeAttribute)
        {
            if( $paymentModeAttribute instanceof PaymentModeAttribute )
            {
                if( $code == $paymentModeAttribute->getPaymentMode()->getPaymentModeGroup()->getCode() )
                {
                    if( $paymentModeAttribute->getAttribute()->getCode() AND !array_key_exists($paymentModeAttribute->getAttribute()->getCode(), $result) )
                    {
                        $temp = $paymentModeAttribute->getAttribute()->getSelectedField(array('code', 'name'));
                        $temp['value'] = $paymentModeAttribute->getAttribute()->getAttributeValues()->getSelectedField(array('country_code', 'code', 'value', 'image_url'));

                        $result[$paymentModeAttribute->getAttribute()->getCode()] = $temp;
                    }
                }
            }
        }


        return $result;
    }
}