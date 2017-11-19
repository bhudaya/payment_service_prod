<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\PaymentService\PaymentMode\PaymentModeType;

class AdminBTPaymentRequestService extends AdminCashPaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::ADMIN_BANK_TRANSFER;
    }

    protected function _requestAction(PaymentRequest $request)
    {
        $option_array = $request->getOption()->toArray();
        if(array_key_exists('reference_no', $option_array)) {
            $request->setReferenceID($option_array['reference_no']);
        }
        return true;
    }

}