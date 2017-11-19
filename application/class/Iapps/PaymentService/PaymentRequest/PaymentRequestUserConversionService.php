<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Core\IappsBaseService;
use Iapps\PaymentService\Common\MessageCode;

class PaymentRequestUserConversionService extends IappsBaseService{

    /*
     * Tag the request to user
     */
    public function convert($payment_request_id, $user_id)
    {
        if( $request = $this->getRepository()->findById($payment_request_id) )
        {
            if( $request instanceof PaymentRequest)
            {
                $request->setUserProfileId($user_id);
                $request->setUpdatedBy($this->getUpdatedBy());
                if( $this->getRepository()->update($request) )
                {
                    return $request;
                }
            }
        }

        $this->setResponseCode(MessageCode::CODE_REQUEST_NOT_FOUND);
        return false;
    }
}