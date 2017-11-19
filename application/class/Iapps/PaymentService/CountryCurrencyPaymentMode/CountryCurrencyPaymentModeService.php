<?php

namespace Iapps\PaymentService\CountryCurrencyPaymentMode;

use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IappsDateTime;

class CountryCurrencyPaymentModeService extends IappsBaseService{

    public function getCountryCurrencyPaymentModeList($limit, $page)
    {
        if( $object = $this->getRepository()->findAll($limit, $page) )
        {
            if( $object->result instanceof CountryCurrencyPaymentModeCollection )
            {
                $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_PAYMENT_MODE_SUCCESS);
                $object->result = $object->result->getSelectedField(array('country_code','country_currency_code','payment_mode_code','effective_at'));
                return $object;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_PAYMENT_MODE_FAILED);
        return false;
    }

    public function getCountryCurrencyPaymentModeInfoByCountryCode($country_code)
    {
        if( $object = $this->getRepository()->findByCountryCode($country_code) )
        {
            if( $object->result instanceof CountryCurrencyPaymentModeCollection )
            {
                $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_PAYMENT_MODE_SUCCESS);
                $object->result = $object->result->getSelectedField(array('id','country_code','country_currency_code','currency_code','payment_mode_code','effective_at'));
                return $object;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_COUNTRY_CURRENCY_PAYMENT_MODE_FAILED);
        return false;
    }

    public function addCountryCurrencyPaymentMode(CountryCurrencyPaymentMode $country_currency_payment_mode)
    {
        //validate country currency payment mode
        $v = CountryCurrencyPaymentModeValidator::make($country_currency_payment_mode);

        if( !$v->fails() )
        {
            //check country currency code and payment mode code is valid, set country code to obj

            //assign an id
            $country_currency_payment_mode->setId(GuidGenerator::generate());
            $country_currency_payment_mode->setCountryCode("ID"); //set with country code
            $country_currency_payment_mode->setCreatedBy($this->getUpdatedBy());

            if( $this->getRepository()->add($country_currency_payment_mode) )
            {
                $this->setResponseCode(MessageCode::CODE_ADD_COUNTRY_CURRENCY_PAYMENT_MODE_SUCCESS);

                //dispatch event to auditLog
                $this->fireLogEvent('country_currency_payment_mode', AuditLogAction::CREATE, $country_currency_payment_mode->getId());

                return $country_currency_payment_mode->getSelectedField(array('code','country_code','country_currency_code','payment_mode_code','effective_at'));
            }
        }

        $this->setResponseCode(MessageCode::CODE_ADD_COUNTRY_CURRENCY_PAYMENT_MODE_FAILED);
        return false;
    }

    public function addCountryCurrencyPaymentModeBatch($country_currency_code, $payment_mode_list, $created_by)
    {
        $collection = new CountryCurrencyPaymentModeCollection();
        $country_currency_payment_mode = new CountryCurrencyPaymentMode();
        $guids = array();
        $new_guid = "";
        $payment_mode_array = array();
        $existing_data = array();
        $existing_data_value = array();

        //check country currency code and payment mode code is valid, set country code to obj
        $count = count($payment_mode_list);
        if($count > 0)
        {
            //check if payment mode code is valid
            //

            //convert list payment mode to payment mode array only
            for ($row = 0; $row < $count; $row++)
            {
                $payment_mode_array[] = $payment_mode_list[$row]['payment_mode_code'];
            }

            //check existing mappings if any
            if( $existing_data = $this->getRepository()->findExistingPaymentMode($country_currency_code, $payment_mode_array) )
            {
                foreach ($existing_data as $existing_data_each) {
                    $existing_data_value[] = $existing_data_each["payment_mode_code"];
                }
            }

            for ($row = 0; $row < $count; $row++)
            {
                if (!in_array($payment_mode_list[$row]['payment_mode_code'], $existing_data_value )) //remove existing to prevent double
                {
                    $country_currency_payment_mode = new CountryCurrencyPaymentMode();

                    $new_guid = GuidGenerator::generate();
                    $guids[] = $new_guid;
                    $country_currency_payment_mode->setId($new_guid);

                    //temp solution, need to change to code from retrieved object. set with country code
                    $country_currency_payment_mode->setCountryCode(substr($country_currency_code, 0, 2));
                    $country_currency_payment_mode->setCountryCurrencyCode($country_currency_code);

                    $country_currency_payment_mode->setPaymentModeCode($payment_mode_list[$row]['payment_mode_code']);
                    $country_currency_payment_mode->setEffectiveAt(IappsDateTime::fromString($payment_mode_list[$row]['effective_at']));

                    $country_currency_payment_mode->setCreatedBy($created_by);
                    $collection->addData($country_currency_payment_mode);
                }
            }

            if($collection->count() > 0)
            {
                if( $this->getRepository()->addBatch($collection) )
                {
                    foreach ($guids as $guid) 
                    {
                        $this->fireLogEvent('iafb_payment.country_currency_payment_mode', AuditLogAction::CREATE, $guid);
                    }

                    $this->setResponseCode(MessageCode::CODE_ADD_COUNTRY_CURRENCY_PAYMENT_MODE_SUCCESS);
                    return true;
                }
            }
            else
            {
                $this->setResponseCode(MessageCode::CODE_ADD_COUNTRY_CURRENCY_PAYMENT_MODE_SUCCESS);
                return true;
            }
        }
        $this->setResponseCode(MessageCode::CODE_ADD_COUNTRY_CURRENCY_PAYMENT_MODE_FAILED);
        return false;
    }
}