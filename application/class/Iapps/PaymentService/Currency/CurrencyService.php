<?php

namespace Iapps\PaymentService\Currency;

use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\Common\MessageCode;

class CurrencyService extends IappsBaseService{

    public function getCurrencyList($limit, $page)
    {
        if( $object = $this->getRepository()->findAll($limit, $page) )
        {
            if( $object->result instanceof CurrencyCollection )
            {
                $this->setResponseCode(MessageCode::CODE_GET_CURRENCY_SUCCESS);
                $object->result = $object->result->getSelectedField(array('code','name','symbol','denomination','effective_at'));
                return $object;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_CURRENCY_FAILED);
        return false;
    }

    public function getCurrencyInfo($code)
    {
        if( $currencyInfo = $this->getRepository()->findByCode($code) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_CURRENCY_SUCCESS);
            return $currencyInfo->getSelectedField(array('id','code','name','symbol','denomination','effective_at'));
        }

        $this->setResponseCode(MessageCode::CODE_GET_CURRENCY_FAILED);
        return false;
    }

    public function getBulkCurrencyInfo(array $codes)
    {
        if( $object = $this->getRepository()->findByCodes($codes) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_CURRENCY_SUCCESS);
            $object->result = $object->result->getSelectedField(array('code','name','symbol','denomination','effective_at'));
            return $object;
        }

        $this->setResponseCode(MessageCode::CODE_GET_CURRENCY_FAILED);
        return false;
    }

    public function addCurrency(Currency $currency)
    {
        //validate currency
        $v = CurrencyValidator::make($currency);

        if( !$v->fails() )
        {
            //check if exists
            if( !$currencyInfo = $this->getRepository()->findByCode($currency->getCode()) )
            { 
                //assign an id
                $currency->setId(GuidGenerator::generate());
                $currency->setCreatedBy($this->getUpdatedBy());

                if( $this->getRepository()->add($currency) )
                {
                    $this->setResponseCode(MessageCode::CODE_ADD_CURRENCY_SUCCESS);

                    //dispatch event to auditLog
                    $this->fireLogEvent('iafb_payment.currency', AuditLogAction::CREATE, $currency->getId());

                    return $currency->getSelectedField(array('code','name','symbol','denomination','effective_at'));
                }
            }
            else
            {
                //set already exists msg code
                $this->setResponseCode(MessageCode::CODE_ADD_CURRENCY_FAILED);
                return false;
            }
        }

        $this->setResponseCode(MessageCode::CODE_ADD_CURRENCY_FAILED);
        return false;
    }

    public function editCurrency($currency)
    {
        //validate currency
        $v = CurrencyValidator::make($currency);

        if( !$v->fails() )
        {
            //check if exists
            if( $currencyInfo = $this->getRepository()->findByCode($currency->getCode()) )
            {  
                $currency->setId($currencyInfo->getId());
                $currency->setUpdatedBy($this->getUpdatedBy());

                if( $this->getRepository()->update($currency) )
                {
                    $this->setResponseCode(MessageCode::CODE_EDIT_CURRENCY_SUCCESS);
                    //dispatch event to auditLog
                    $this->fireLogEvent('iafb_payment.currency', AuditLogAction::UPDATE, $currency->getId(), $currencyInfo);

                    return $currency->getSelectedField(array('code','name','symbol','denomination','effective_at'));
                }
            }
        }

        $this->setResponseCode(MessageCode::CODE_EDIT_CURRENCY_FAILED);
        return false;
    }

    public function getCurrencyInfoByCodeOrName($search_value, $limit, $page)
    {
        if( $object = $this->getRepository()->findByCodeOrName($search_value, $limit, $page) )
        {
            if( $object->result instanceof CurrencyCollection )
            {
                $this->setResponseCode(MessageCode::CODE_GET_CURRENCY_SUCCESS);
                $object->result = $object->result->getSelectedField(array('code','name','symbol','denomination','effective_at'));
                return $object;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_CURRENCY_FAILED);
        return false;
    }
}