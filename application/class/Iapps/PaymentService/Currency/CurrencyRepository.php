<?php

namespace Iapps\PaymentService\Currency;

use Iapps\Common\Core\IappsBaseRepository;
use Iapps\PaymentService\Common\CacheKey;
use Iapps\PaymentService\Currency\CurrencyCollection;

class CurrencyRepository extends IappsBaseRepository{

    public function findByCode($code)
    {
        $cacheKey = CacheKey::CURRENCY_CODE;
        
        if( !$result = $this->getElasticCache($cacheKey) )
        {
            $result = $this->getDataMapper()->findByCode($code);
            
            if( $result )
                $this->setElasticCache($cacheKey, $result);
        }
        
        return $result;
    }

    public function findByCodes(array $codes)
    {
        list($result, $remaining_ids) = $this->_getListFromCache($codes, CacheKey::CURRENCY_CODE, new CurrencyCollection());
        if( count($remaining_ids) > 0 )
        {
            $additional_result = $this->getDataMapper()->findByCodes($remaining_ids);
            if( $additional_result )
            {               
                $this->_setListToCache("code", $remaining_ids, $additional_result, CacheKey::CURRENCY_CODE);
                $result->combineCollection($additional_result->getResult());                
            }
        }
        
        if( count($result->getResult())>0 )
            return $result;
        
        return false;        
    }

    public function findAll($limit, $page)
    {
        return $this->getDataMapper()->findAll($limit, $page);
    }

    public function update(Currency $currency)
    {
        $this->_removeCache($currency);
        return $this->getDataMapper()->update($currency);
    }

    public function add(Currency $currency)
    {
        $this->_removeCache($currency);
        return $this->getDataMapper()->add($currency);
    }

    public function findByCodeOrName($search_value,$limit, $page)
    {
        return $this->getDataMapper()->findByCodeOrName($search_value, $limit, $page);
    }
    
    protected function _removeCache(Currency $currency)
    {
        $cacheKeys = array(CacheKey::CURRENCY_CODE . $currency->getCode());
        foreach($cacheKeys AS $key)
            $this->deleteElastiCache($key);
    }
}