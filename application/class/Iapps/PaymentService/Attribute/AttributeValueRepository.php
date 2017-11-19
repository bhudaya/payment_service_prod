<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\Common\Core\IappsBaseRepository;
use Iapps\PaymentService\Common\CacheKey;
use Iapps\PaymentService\Attribute\AttributeValueCollection;

class AttributeValueRepository extends IappsBaseRepository{

    public function findByIds(array $ids)
    {
        return $this->getDataMapper()->findByIds($ids);
    }

    public function findByAttributeIds(array $attribute_ids)
    {
        list($result, $remaining_ids) = $this->_getListFromCache($attribute_ids, CacheKey::ATTRIBUTE_VALUE_ATTRIBUTE_ID, new AttributeValueCollection());
        if( count($remaining_ids) > 0 )
        {
            $additional_result = $this->getDataMapper()->findByAttributeIds($remaining_ids);                       
            if( $additional_result )
            {               
                $this->_setListToCacheAsPaginatedResult("attribute_id", $remaining_ids, $additional_result, CacheKey::ATTRIBUTE_VALUE_ATTRIBUTE_ID);
                $result->combineCollection($additional_result->getResult());                
            }
        }
        
        if( count($result->getResult())>0 )
            return $result;
        
        return false;
    }

    public function findByAttributeId($attribute_id)
    {
        $cacheKey = CacheKey::ATTRIBUTE_VALUE_ATTRIBUTE_ID . $attribute_id;
        
        if( !$result = $this->getElasticCache($cacheKey) )
        {
            $result = $this->getDataMapper()->findByAttributeId($attribute_id);
            if( $result )
                $this->setElasticCache($cacheKey, $result);
        }
        
        return $result;        
    }

    public function findByFilters(AttributeValueCollection $filters)
    {
        return $this->getDataMapper()->findByFilters($filters);
    }

    public function findAll()
    {
        return $this->getDataMapper()->findAll();
    }

    public function insert(AttributeValue $attribute)
    {
        $this->_removeCache($attribute);
        return $this->getDataMapper()->insert($attribute);
    }

    public function update(AttributeValue $attribute)
    {
        $this->_removeCache($attribute);
        return $this->getDataMapper()->update($attribute);
    }
    
    protected function _removeCache(AttributeValue $attribute)
    {
        $cacheKeys = array(CacheKey::ATTRIBUTE_VALUE_ATTRIBUTE_ID . $attribute->getAttribute()->getId(),
                           CacheKey::COLLECTION_OPTION_LIST);
        foreach($cacheKeys AS $key)
            $this->deleteElastiCache($key);
    }
}