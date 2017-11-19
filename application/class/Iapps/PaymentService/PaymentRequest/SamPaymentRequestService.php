<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class SamPaymentRequestService extends KioskPaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy,PaymentModeType::SINGAPORE_POST);
    }

    protected function _generateDetail1(PaymentRequest $request)
    {
        $desc = new PaymentDescription();
        $desc->add('', 'You were served by SingPost Post Office');

        $request->setDetail1($desc);
        return true;
    }
}