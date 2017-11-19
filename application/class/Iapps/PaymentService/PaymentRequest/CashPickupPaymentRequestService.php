<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\RequestHeader;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class CashPickupPaymentRequestService extends PaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::CASH_PICKUP;
    }

    public function request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, array $option)
    {
        //add admin access token as option
        $headers = RequestHeader::get();
        $option['token'] = NULL;
        if( array_key_exists(ResponseHeader::FIELD_X_AUTHORIZATION, $headers) )
            $option['token'] = $headers[ResponseHeader::FIELD_X_AUTHORIZATION];

        return parent::request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, $option);
    }
}