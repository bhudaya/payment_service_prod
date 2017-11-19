<?php

namespace Iapps\PaymentService\PaymentRequest;

require_once './application/modules/paymentrequest/models/Payment_request_model.php';

use Iapps\PaymentService\PaymentMode\PaymentModeType;

class ListPaymentRequestServiceFactory{
    protected static $_instance = array();

    public static function build()
    {
        $dm = new \Payment_request_model();
        $repo = new PaymentRequestRepository($dm);
        self::$_instance = new ListPaymentRequestService($repo);

        return self::$_instance;
    }
}