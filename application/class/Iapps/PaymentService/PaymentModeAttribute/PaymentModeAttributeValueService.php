<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseService;
use Iapps\PaymentService\Attribute\AttributeValueServiceFactory;

class PaymentModeAttributeValueService extends IappsBaseService{

    public function getValuesByPaymentModeAttributes(PaymentModeAttributeCollection $paymentModeAttributeCollection, $countryCode = NULL)
    {
        $pm_attribute_ids = $paymentModeAttributeCollection->getIds();

        $filter = new PaymentModeAttributeValueCollection();
        foreach( $pm_attribute_ids AS $pm_attribute_id )
        {
            $pm_attributeVal = new PaymentModeAttributeValue();
            $pm_attributeVal->getPaymentModeAttribute()->setId($pm_attribute_id);
            $filter->addData($pm_attributeVal);
        }

        if( $info = $this->getRepository()->findByFilters($filter) )
        {
            $paymentModeAttributeValueCollection = $info->result;

            //join attribute value
            $attrValServ = AttributeValueServiceFactory::build();
            if( $attrValCollection = $attrValServ->getByIds($paymentModeAttributeValueCollection->getAttributeValueIds()))
            {
                $paymentModeAttributeValueCollection->joinAttributeValue($attrValCollection);
            }

            //filter country code if given
            if( $countryCode )
            {
                $filteredCollection = new PaymentModeAttributeValueCollection();
                foreach($paymentModeAttributeValueCollection AS $paymentModeAttributeValue)
                {
                    if($paymentModeAttributeValue->getAttributeValue()->getCountryCode() == $countryCode )
                        $filteredCollection->addData($paymentModeAttributeValue);
                }
                $paymentModeAttributeValueCollection = $filteredCollection;
            }

            $paymentModeAttributeCollection->joinPaymentModeAttributeValue($paymentModeAttributeValueCollection);
        }


        return $paymentModeAttributeCollection;
    }

    public function getByAttributeValueIds(array $attributeValueIds)
    {
        $filters = new PaymentModeAttributeValueCollection();
        foreach($attributeValueIds AS $attributeValueId)
        {
            $filter = new PaymentModeAttributeValue();
            $filter->getAttributeValue()->setId($attributeValueId);
            $filters->addData($filter);
        }

        if( $info = $this->getRepository()->findByFilters($filters) )
        {
            return $info->result;
        }

        return false;
    }
}