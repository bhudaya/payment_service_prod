<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Common\CacheKey;

class PaymentModeLocationService extends IappsBaseService
{

    public function getSupportedLocationByPaymentCode($payment_code)
    {
        $cache_key = CacheKey::PAYMENT_MODE_LOCATION_LIST . $payment_code;
        if( !$collection = $this->getElasticCache($cache_key) )
        {
            $payment_mode_location = new PaymentModeLocation();
            $payment_mode_location->setPaymentCode($payment_code);

            if( $object = $this->getRepository()->findByParam($payment_mode_location, 1000, 1) )
            {
                $collection = $object->result;
                
                $this->setElasticCache($cache_key, $collection);
            }
        }

        if( $collection instanceof PaymentModeLocationCollection )
        {
            $result = $collection->getSelectedField(array('id','payment_code','address','latitude','longitude','operating_hours','created_at','created_by','updated_at','updated_by','deleted_at','deleted_by'));
            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_LOCATION_SUCCESS);
            return $result;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_LOCATION_FAILED);
        return false;
    }

}