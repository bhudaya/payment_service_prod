<?php

namespace Iapps\PaymentService\CountryCurrency;

use Iapps\PaymentService\Currency\CurrencyInfoExtractor;
use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\Common\MessageCode;

class CountryCurrencyService extends IappsBaseService{

    protected $_country_currency_payment_mode_service;
    protected $_currency_service;
    public function addCountryCurrencyPaymentModeService($country_currency_payment_mode_service)
    {
        $this->_country_currency_payment_mode_service = $country_currency_payment_mode_service;
    }

    public function addCurrencyService($currency_service)
    {
        $this->_currency_service = $currency_service;
    }

    public function getCountryCurrencyList($limit, $page)
    {
        if( $object = $this->getRepository()->findAll($limit, $page) )
        {
            if( $object->result instanceof CountryCurrencyCollection )
            {
                $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_SUCCESS);
                $object->result = $object->result->getSelectedField(array('code','country_code','currency_code'));
                $object->result = CurrencyInfoExtractor::extract($object->result);
                return $object;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_FAILED);
        return false;
    }

    public function getCountryCurrencyInfo($code)
    {
        if( $countryCurrencyInfo = $this->getRepository()->findByCode($code) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_SUCCESS);
            $result = $countryCurrencyInfo->getSelectedField(array('id','code','country_code','currency_code'));
            $result_array = CurrencyInfoExtractor::extract(array($result));
            return $result_array[0];
        }

        $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_FAILED);
        return false;
    }

    public function addCountryCurrency(CountryCurrency $country_currency)
    {
        //validate country currency
        $v = CountryCurrencyValidator::make($country_currency);

        if( !$v->fails() )
        {
            //check if exists
            if( !$countryCurrencyInfo = $this->getRepository()->findByCode($country_currency->getCode()) )
            { 
                //assign an id
                $country_currency->setId(GuidGenerator::generate());
                $country_currency->setCode($country_currency->getCountryCode()."-".$country_currency->getCurrencyCode());
                $country_currency->setCreatedBy($this->getUpdatedBy());

                if( $this->getRepository()->add($country_currency) )
                {
                    $this->setResponseCode(MessageCode::CODE_ADD_COUNTRY_CURRENCY_SUCCESS);

                    //dispatch event to auditLog
                    $this->fireLogEvent('iafb_payment.country_currency', AuditLogAction::CREATE, $country_currency->getId());

                    return $country_currency->getSelectedField(array('code','country_code','currency_code'));
                }
            }
            else
            {
                //set already exists msg code
                $this->setResponseCode(MessageCode::CODE_ADD_COUNTRY_CURRENCY_FAILED);
                return false;
            }
        }

        $this->setResponseCode(MessageCode::CODE_ADD_COUNTRY_CURRENCY_FAILED);
        return false;
    }

    public function addCountryCurrencyWithPaymentMode($country_code, $currency_list, $created_by)
    {
        $response_code = MessageCode::CODE_ADD_COUNTRY_CURRENCY_FAILED;
        $currency_list_count = isset($currency_list) && !empty($currency_list) ? 
                                    is_array($currency_list) ? 
                                        count($currency_list) > 0 : 
                                    0 :
                                0;

        if($currency_list_count > 0)
        {
            $commit_trans = false;
            //start db trans
            $this->getRepository()->startDBTransaction();
            
            for ($row = 0; $row < $currency_list_count; $row++)
            {
                $currency_code = $currency_list[$row]['currency_code'];

                $country_currency = new \Iapps\PaymentService\CountryCurrency\CountryCurrency();
                $country_currency->setCountryCode($country_code);
                $country_currency->setCurrencyCode($currency_code);
                $country_currency->setCreatedBy($created_by);
                
                //validate country currency
                $v = CountryCurrencyValidator::make($country_currency);

                if( !$v->fails() )
                {
                    //check if country code valid
                    //
                    
                    //check if currency code valid
                    if($currencyInfo = $this->_currency_service->getCurrencyInfo($currency_code))
                    {
                        //!check if mapping exists
                        $code = $country_currency->getCountryCode()."-".$country_currency->getCurrencyCode();
                        if( !$countryCurrencyInfo = $this->getRepository()->findByCode($code) )
                        {
                            //assign an id
                            $country_currency->setId(GuidGenerator::generate());
                            $country_currency->setCode($code);
                            $country_currency->setCreatedBy($created_by);

                            if( $this->getRepository()->add($country_currency) )
                            {
                                //dispatch event to auditLog
                                $this->fireLogEvent('iafb_payment.country_currency', AuditLogAction::CREATE, $country_currency->getId());

                                //check valid payment mode
                                $is_list_valid = isset($currency_list[$row]['payment_mode_list']) && !empty($currency_list[$row]['payment_mode_list']) ? 
                                                    is_array($currency_list[$row]['payment_mode_list']) ? 
                                                        count($currency_list[$row]['payment_mode_list']) > 0 : 
                                                    false :
                                                false;

                                if($is_list_valid)
                                {
                                    //add payment mode
                                    $commit_trans = $this->_country_currency_payment_mode_service->addCountryCurrencyPaymentModeBatch($country_currency->getCode(), $currency_list[$row]['payment_mode_list'], $created_by);
                                }
                                else
                                {
                                    //invalid payment mode list
                                    $response_code = MessageCode::CODE_COUNTRY_CURRENCY_INVALID_PAYMENT_MODE;
                                    $commit_trans = false;
                                    break;
                                }
                            }
                        }
                        else
                        {
                            //country currency info already exists
                            $response_code = MessageCode::CODE_COUNTRY_CURRENCY_ALREADY_EXISTS;
                            $commit_trans = false;
                            break;
                        }
                    }
                    else
                    {
                        //invalid currency code
                        $response_code = MessageCode::CODE_COUNTRY_CURRENCY_INVALID_CURRENCY_CODE;
                        $commit_trans = false;
                        break;
                    }
                }
                else
                {
                    //vfail
                    $response_code = MessageCode::CODE_COUNTRY_CURRENCY_FAILED_VALIDATION;
                    $commit_trans = false;
                    break;
                }
            }

            if($commit_trans)
            {
                $this->setResponseCode(MessageCode::CODE_ADD_COUNTRY_CURRENCY_SUCCESS);
                //commit db trans
                $this->getRepository()->completeDBTransaction();
                return true;
            }

            //roll back db trans
            $this->getRepository()->rollbackDBTransaction();
        }

        
        $this->setResponseCode($response_code);
        return false;
    }

    public function getCurrencyInfoByCountryCode($country_code)
    {
        if( $object = $this->getRepository()->findByCountryCode($country_code) )
        {
            if( $object->result instanceof CountryCurrencyCollection )
            {
                $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_SUCCESS);
                $object->result = $object->result->getSelectedField(array('code','country_code','currency_code'));
                $object->result = CurrencyInfoExtractor::extract($object->result);
                return $object;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_FAILED);
        return false;
    }

    public function getCurrencyInfoWithPaymentModeByCountryCode($code)
    {
        $result_array = array();
        $object = new \StdClass;

        if( $countryCurrencyObject = $this->getRepository()->findByCountryCode($code) )
        {
            $currency_array = array();
            if( $countryCurrencyObject->result instanceof CountryCurrencyCollection )
            {
                $currency_array = $countryCurrencyObject->result->getSelectedField(array('currency_code'));
                $currency_array_value = array();
                foreach ($currency_array as $currency_array_each) 
                {
                    $currency_array_value[] = $currency_array_each["currency_code"];
                }
                $currency_count = count($currency_array_value);
                
                $mapped_payment_mode_value = array();
                if($mapped_payment_mode = $this->_country_currency_payment_mode_service->getCountryCurrencyPaymentModeInfoByCountryCode($code))
                {
                    $ccpm_count = count($mapped_payment_mode->result);
                    $payment_mode_object = new \StdClass;
                    for ($row = 0; $row < $currency_count; $row++)
                    {
                        $mapped_payment_mode_value = array();
                        for ($rowpm = 0; $rowpm < $ccpm_count; $rowpm++)
                        {
                            if($currency_array_value[$row] == $mapped_payment_mode->result[$rowpm]["currency_code"])
                            {
                                $payment_mode_object = new \StdClass;
                                $payment_mode_object->payment_mode_code = $mapped_payment_mode->result[$rowpm]["payment_mode_code"];
                                $payment_mode_object->effective_at = $mapped_payment_mode->result[$rowpm]["effective_at"];
                                $mapped_payment_mode_value[] = $payment_mode_object;
                            }
                        }

                        $object = new \StdClass;
                        $object->currency_code = $currency_array_value[$row];
                        $object->payment_mode_list = $mapped_payment_mode_value;
                        $result_array[] = $object;
                    }
                }
                else
                {
                    //if no payment mode was mapped
                    for ($row = 0; $row < $currency_count; $row++)
                    {
                        $object = new \StdClass;
                        $object->currency_code = $currency_array_value[$row];
                        $object->payment_mode_list = null;
                        $result_array[] = $object;
                    }
                }
            }

            $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_SUCCESS);
            return $result_array;
        }

        $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_FAILED);
        return false;
    }
}