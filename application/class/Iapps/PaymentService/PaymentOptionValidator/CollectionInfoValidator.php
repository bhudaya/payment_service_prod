<?php

namespace Iapps\PaymentService\PaymentOptionValidator;

use Iapps\Common\Core\IappsBasicBaseService;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;

class CollectionInfoValidator extends IappsBasicBaseService{

    public function validate($payment_code, $country_code, array $option = array())
    {
        $attr_serv = PaymentModeAttributeServiceFactory::build();
        if($result = $attr_serv->validateCollectionInfo($payment_code, $option, $country_code)){
            $this->setResponseCode(MessageCode::CODE_PAYMENT_ATTRIBUTE_VALUE_VALIDATE_SUCCESS);
            return true;
        }

        $this->setResponseCode(MessageCode::CODE_PAYMENT_ATTRIBUTE_VALUE_VALIDATE_FAIL);
        return false;
    }
}