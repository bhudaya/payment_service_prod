<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Helper\GuidGenerator;

class AttributeValueService extends IappsBaseService{

    public function getByIds(array $ids)
    {
        if( $info = $this->getRepository()->findByIds($ids) )
        {
            return $info->result; //return collection
        }

        return false;
    }

    public function getByAttributeIds(array $attributeIds)
    {
        if( $info = $this->getRepository()->findByAttributeIds($attributeIds) )
        {
            return $info->result;
        }

        return false;
    }

    public function getByAttributeCode($code, $is_array = true)
    {
        $attr_serv = AttributeServiceFactory::build();
        if( $attr = $attr_serv->getByCode($code) )
        {
            if( $info =$this->getRepository()->findByAttributeId($attr->getId()) )
            {
                $collection = $info->result;
                $attr->setAttributeValues($collection);
                $this->setResponseCode(MessageCode::CODE_ATTRIBUTE_FOUND);

                if($is_array)
                {
                    $result['attribute'] = $attr->getSelectedField(
                        array('code','selection_only','name','description')
                    );
                    $result['list'] = $collection->groupByCountryCode();
                    return $result;
                }
                else
                    return $attr;
            }

            $this->setResponseCode(MessageCode::CODE_ATTRIBUTE_NOT_FOUND);
            return false;
        }
        else
        {
            $this->setResponseCode($attr_serv->getResponseCode());
            return false;
        }
    }

    public function getByAttributeValueCodes(AttributeCollection $attributeCollection)
    {
        //get by attribute codes
        $attrServ = AttributeServiceFactory::build();
        if( $attrCollection = $attrServ->getByCodes($attributeCollection) )
        {
            $filters = new AttributeValueCollection();
            foreach($attrCollection AS $attribute)
            {
                if( $attribute instanceof Attribute )
                {
                    if( $refAttribute = $attributeCollection->getByCode($attribute->getCode()) )
                    {
                        foreach($refAttribute->getAttributeValues() AS $attributeValue)
                        {
                            $attributeValue->getAttribute()->setId($attribute->getId());
                            $filters->addData($attributeValue);
                        }
                    }
                }
            }

            if( count($filters) > 0 )
            {
                if( $info = $this->getRepository()->findByFilters($filters) )
                    return $info->result;
            }
        }

        return false;
    }

    public function getAll()
    {
        if( $info =$this->getRepository()->findAll() )
        {
            $collection = $info->result;

            $results = array();
            if( $groups = $collection->groupByAttributeCode() )
            {
                foreach($groups AS $group)
                {
                    $result = array();
                    $result['attribute'] = $group['attribute']->getSelectedField(
                            array('code','selection_only','name','description')
                        );
                    $result['list'] = $group['collection']->groupByCountryCode();
                    $results[] = $result;
                }
            }

            $this->setResponseCode(MessageCode::CODE_ATTRIBUTE_FOUND);
            return $results;
        }

        $this->setResponseCode(MessageCode::CODE_ATTRIBUTE_NOT_FOUND);
        return false;
    }

    public function addValues($attribute_code, array $values)
    {
        $attr_serv = AttributeServiceFactory::build();
        if( $attr = $attr_serv->getByCode($attribute_code) )
        {
            $this->getRepository()->startDBTransaction();
            foreach($values as $value)
            {
                $val = NULL;
                $country_code = NULL;

                if( isset($value['value']) )
                    $val = $value['value'];

                if( isset($value['country_code']) )
                    $country_code = $value['country_code'];

                $attribute_value = AttributeValue::createNew($attr, $val, $country_code);

                //validate
                $v = AttributeValueValidator::make($attribute_value);
                if( !$v->fails() )
                {
                    if( $this->getRepository()->insert($attribute_value) )
                    {
                        $this->fireLogEvent('iafb_payment.attribute_value', AuditLogAction::CREATE, $attribute_value->getId());
                    }
                    else
                    {
                        $this->getRepository()->rollbackDBTransaction();
                        $this->setResponseCode(MessageCode::CODE_ADD_ATTRIBUTE_VALUES_FAILED);
                        return false;
                    }
                }
                else
                {
                    $this->getRepository()->rollbackDBTransaction();
                    $this->setResponseCode(MessageCode::CODE_INVALID_ATTRIBUTE_VALUE);
                    return false;
                }
            }
            $this->getRepository()->completeDBTransaction();
            $this->setResponseCode(MessageCode::CODE_ATTRIBUTE_VALUES_ADDED);
            return true;
        }
        else
        {
            $this->setResponseCode($attr_serv->getResponseCode());
            return false;
        }
    }

    public function checkValue(Attribute $attribute, $value)
    {
        if( $info =$this->getRepository()->findByAttributeId($attribute->getId()) )
        {
            $collection = $info->result;

            return $collection->hasValue($value);
        }

        return false;
    }

    public function getValueById(AttributeValue $attributeValue)
    {
        if( $attributeValue->getId() )
        {
            if( $info =$this->getRepository()->findById($attributeValue->getId()) )
            {
                $attributeValue->setValue($info->getValue());
                return $attributeValue;
            }
        }

        return false;
    }
}