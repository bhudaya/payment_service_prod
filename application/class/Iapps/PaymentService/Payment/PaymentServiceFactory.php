<?php

namespace Iapps\PaymentService\Payment;

require_once './application/modules/payment/models/Payment_model.php';

class PaymentServiceFactory{

    protected static $_instance = array();

    public static function build()
    {
        if (self::$_instance == NULL) {
            $dm = new \Payment_model();
            $repo = new PaymentRepository($dm);
            self::$_instance = new PaymentService($repo);
        }

        return self::$_instance;
    }
}