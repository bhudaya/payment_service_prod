<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseService;
use Iapps\PaymentService\Attribute\Attribute;
use Iapps\PaymentService\Attribute\AttributeCode;
use Iapps\PaymentService\Attribute\AttributeCollection;
use Iapps\PaymentService\Attribute\AttributeServiceFactory;
use Iapps\PaymentService\Attribute\AttributeValue;
use Iapps\PaymentService\Attribute\AttributeValueServiceFactory;
use Iapps\PaymentService\Common\CacheKey;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Common\Logger;
use Iapps\PaymentService\Common\SystemCodeServiceFactory;
use Iapps\PaymentService\PaymentMode\DeliveryTime;
use Iapps\PaymentService\PaymentMode\PaymentMode;
use Iapps\PaymentService\PaymentMode\PaymentModeServiceFactory;

class PaymentModeAttributeService extends IappsBaseService{

    /**
     * @return PaymentModeAttributeCollection
     */
    public function getAttributesByPaymentCode($payment_code, $country_code = NULL, $is_array = true)
    {
        $cache_key = CacheKey::PAYMENT_MODE_ATTRIBUTE_LIST . $payment_code . $country_code;
        if( !$collection = $this->getElasticCache($cache_key) )
        {
            if( $info = $this->getRepository()->findByPaymentCode($payment_code) ) {
                $collection = $info->result;

                $attrServ = AttributeServiceFactory::build();
                if ($attributeCollection = $attrServ->getByIds($collection->getAttributeIds())) {
                    //join attribute
                    $collection->joinAttribute($attributeCollection);
                }

                $pmAttrValServ = PaymentModeAttributeValueServiceFactory::build();
                $pmAttrValServ->getValuesByPaymentModeAttributes($collection, $country_code);

                $this->setElasticCache($cache_key, $collection);
            }
        }

        if( $collection instanceof PaymentModeAttributeCollection )
        {
            $collection = $collection->sortByDisplayOrder();

            $this->setResponseCode(MessageCode::CODE_GET_ATTRIBUTE_SUCCESS);
            if( $is_array )
                return $collection->getSelectedField(
                    array('attribute','name', 'selection_only', 'value' => array('country_code', 'code', 'value', 'option', 'image_url')));
            else
                return $collection;
        }

        $this->setResponseCode(MessageCode::CODE_GET_ATTRIBUTE_FAILED);
        return false;
    }

    public function getAllByPaymentCode($payment_code)
    {
        if( $pmAttributes = $this->getAttributesByPaymentCode($payment_code, NULL, false) )
        {
            $results = array();
            foreach($pmAttributes AS $pmAttribute)
            {
                $result = array();
                $result['attribute'] = $pmAttribute->getAttribute()->getSelectedField(
                    array('attribute','name', 'code', 'selection_only')
                );
                $result['list'] = $pmAttribute->getValue()->groupByCountryCode();
                $results[] = $result;
            }

            $this->setResponseCode(MessageCode::CODE_GET_ATTRIBUTE_SUCCESS);
            return $results;
        }

        $this->setResponseCode(MessageCode::CODE_GET_ATTRIBUTE_FAILED);
        return false;
    }

    public function getValueByCode($payment_code, $attribute, $code)
    {
        if( $pmAttributes = $this->getAttributesByPaymentCode($payment_code, NULL, false) )
        {
            foreach($pmAttributes AS $pmAttribute)
            {
                if( $pmAttribute->getAttribute()->getCode() == $attribute )
                {
                    if( $value = $pmAttribute->getValue()->getByCode($code) )
                        return $value;
                }
            }
        }

        return false;
    }
    
    public function getAllBankNames(){
        $attrValServ = AttributeValueServiceFactory::build();
        if( $attr = $attrValServ->getByAttributeCode(AttributeCode::BANK_CODE, false) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_ATTRIBUTE_SUCCESS);
            return $attr->getAttributeValues();
        }

        $this->setResponseCode(MessageCode::CODE_GET_ATTRIBUTE_FAILED);
        return false;
    }

    public function validateCollectionInfo($payment_code, array $collection_info, $country_code = NULL){

        if( $payment_code )
            return $this->_validateByPaymentCode($payment_code, $collection_info);
        elseif( $country_code )
            return $this->_validateByCountryCode($country_code, $collection_info);

        return false;
    }

    /*
     * this can only validate the given collection info is valid value
     */
    protected function _validateByCountryCode($country_code, array $collection_info)
    {
        $attrValServ = AttributeValueServiceFactory::build();
        $attrCol = new AttributeCollection();
        foreach( $collection_info AS $key => $value ) {
            if ($attr = $attrValServ->getByAttributeCode($key, false)) {
                if ($attr instanceof Attribute) {
                    if ($attr->isSelectionOnly()) {
                        if ($attrVal = $attr->getAttributeValues()->getByCode($value, $country_code)) {
                            if ($attrVal->getCountryCode() == NULL OR $attrVal->getCountryCode() == $country_code) {
                                if (!$attrVal->checkOption($collection_info))
                                    return false;
                            }
                            else
                                return false;
                        } else
                            return false;
                    }
                }
            }
        }

        return true;
    }

    protected function _validateByPaymentCode($payment_code, array $collection_info)
    {
        //get required attributes
        if( $paymentAttributeCol = $this->getAttributesByPaymentCode($payment_code, NULL, false) )
        {
            foreach($paymentAttributeCol AS $paymentAttribute)
            {
                $attrCode = $paymentAttribute->getAttribute()->getCode();

                //workaround
                if( $attrCode == AttributeCode::SLIDE_BANK_CODE )
                    $attrCode = 'to_bank_code';

                //check if all required attribute exists
                if( !array_key_exists($attrCode, $collection_info) )
                {
                    Logger::debug('payment_mode.validate: missing attribute code'. $attrCode);
                    return false;
                }


                if( count($paymentAttribute->getValue()) > 0 )
                {
                    $checkValue = $collection_info[$attrCode];
                    //check if value is one of the option
                    if( !$attrVal = $paymentAttribute->getValue()->getByCode($checkValue) )
                    {
                        Logger::debug('payment_mode.validate: missing attribute value'. $checkValue);
                        return false;
                    }

                    if( !$attrVal->getAttributeValue()->checkOption($collection_info) )
                        return false;
                }
            }
        }

        return true;
    }

    public function getCollectionOption()
    {
        $cacheKey = CacheKey::COLLECTION_OPTION_LIST;
        if( $result = $this->getElasticCache($cacheKey) )
        {
            if( count($result) > 0 )
            {
                $this->setResponseCode(MessageCode::CODE_GET_ATTRIBUTE_SUCCESS);
                return $result;
            }
        }

        //get all collection modes
        $pmServ = PaymentModeServiceFactory::build();
        $pmfilter = new PaymentMode();
        $pmfilter->setIsCollectionMode(1);

        $result = array();
        $result['payment_mode_group'] = array();
        if( $info = $pmServ->getPaymentModeByParam($pmfilter) )
        {
            $pmCol = $info->result;

            $pmAttrFilter = new PaymentModeAttributeCollection();
            foreach($pmCol AS $collectionMode)
            {
                $pmAttr = new PaymentModeAttribute();
                $pmAttr->setPaymentCode($collectionMode->getCode());
                $pmAttrFilter->addData($pmAttr);
            }

            if( $info = $this->getRepository()->findByFilters($pmAttrFilter) )
            {
                $pmAttrCol = $info->result;
                $pmAttrCol->joinPaymentMode($pmCol);

                if( $pmAttrCol instanceof PaymentModeAttributeCollection )
                {
                    $attrServ = AttributeServiceFactory::build();
                    if ($attributeCollection = $attrServ->getByIds($pmAttrCol->getAttributeIds())) {
                        //join attribute
                        $attrValServ = AttributeValueServiceFactory::build();
                        $filteredAttributeCollection = new AttributeCollection();
                        if( $attrValCol = $attrValServ->getByAttributeIds($pmAttrCol->getAttributeIds()) )
                            $attributeCollection->joinAttributeValue($attrValCol);

                        foreach($attributeCollection AS $attribute)
                        {
                            if( count($attribute->getAttributeValues()) > 0 )
                                $filteredAttributeCollection->addData($attribute);
                        }

                        $pmAttrCol->joinAttribute($filteredAttributeCollection);
                    }
                }
            }

            foreach( $pmCol AS $pm )
            {//group payment mode group
                $gCode = $pm->getPaymentModeGroup()->getCode();
                if( !array_key_exists($gCode, $result['payment_mode_group']) )
                {
                    $result['payment_mode_group'][$gCode]['code'] = $pm->getPaymentModeGroup()->getCode();
                    $result['payment_mode_group'][$gCode]['name'] = $pm->getPaymentModeGroup()->getDisplayName();
                    if( isset($pmAttrCol) AND $attributeArr = $pmAttrCol->getByPaymentModeGroup($gCode) )
                    {
                        $result['payment_mode_group'][$gCode]['attribute'] = $attributeArr;
                    }
                }
            }

            //reset array key
            $tempArray = $result['payment_mode_group'];
            $result['payment_mode_group'] = array();
            foreach( $tempArray AS $temp )
            {
                $result['payment_mode_group'][] = $temp;
            }

            //get delivery option
            $syscodeServ = SystemCodeServiceFactory::build();
            if( $info = $syscodeServ->getBySystemCodeGroup(DeliveryTime::getSystemGroupCode()) )
            {
                $list = $info->result;
                $result['delivery_time'] = $list->getSelectedField(array('code', 'display_name'));
            }

            if( count($result) > 0 )
            {
                $this->setElasticCache($cacheKey, $result);
                $this->setResponseCode(MessageCode::CODE_GET_ATTRIBUTE_SUCCESS);
                return $result;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_ATTRIBUTE_FAILED);
        return false;
    }

    public function getByAttributeValue(AttributeCollection $attributeCollection)
    {
        $attrValServ = AttributeValueServiceFactory::build();
        if( $attrVal = $attrValServ->getByAttributeValueCodes($attributeCollection) )
        {
            $pm_attrValServ = PaymentModeAttributeValueServiceFactory::build();
            if( $pm_attrVals = $pm_attrValServ->getByAttributeValueIds($attrVal->getIds()) )
            {
                $filters = new PaymentModeAttributeCollection();
                foreach($pm_attrVals->getPaymentModeAttributeIds() AS $paymentModeAttributeId)
                {
                    $filter = new PaymentModeAttribute();
                    $filter->setId($paymentModeAttributeId);
                    $filters->addData($filter);
                }
                if( $info = $this->getRepository()->findByFilters($filters) )
                {
                    return $info->result;
                }
            }
        }

        return false;
    }
}