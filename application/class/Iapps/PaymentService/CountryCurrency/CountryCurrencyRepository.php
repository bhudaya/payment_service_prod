<?php

namespace Iapps\PaymentService\CountryCurrency;

use Iapps\Common\Core\IappsBaseRepository;
use Iapps\PaymentService\Common\CacheKey;

class CountryCurrencyRepository extends IappsBaseRepository{

    public function findByCode($code)
    {
        return $this->getDataMapper()->findByCode($code);
    }

    public function findByCountryCode($country_code)
    {
        return $this->getDataMapper()->findByCountryCode($country_code);
    }

    public function findAll($limit, $page)
    {
        if( $limit == NULL AND $page == NULL )
        {
            $cacheKey = CacheKey::COUNTRY_CURRENCY_ALL;

            if( !$result = $this->getElasticCache($cacheKey) )
            {
                $result = $this->getDataMapper()->findAll($limit, $page);
                if( $result )
                    $this->setElasticCache($cacheKey, $result);
            }

            return $result;
        }
        
        return $this->getDataMapper()->findAll($limit, $page);        
    }

    public function add(CountryCurrency $country_currency)
    {
        $this->_removeCache($country_currency);
        return $this->getDataMapper()->add($country_currency);
    }
    
    protected function _removeCache(CountryCurrency $country_currency)
    {
        $cacheKeys = array(CacheKey::COUNTRY_CURRENCY_ALL);
        
        foreach($cacheKeys AS $key)
            $this->deleteElastiCache($key);
    }
}