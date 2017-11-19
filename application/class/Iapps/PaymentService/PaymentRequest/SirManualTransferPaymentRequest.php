<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\PaymentService\PaymentMode\PaymentModeType;

class SirManualTransferPaymentRequest extends BTIndoOCBCPaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::SIR_BANK_TRANSFER_MANUAL;
    }

    public function _completeAction(PaymentRequest $request)
    {//don't call the switch
        return PaymentRequestService::_completeAction($request);
    }
}