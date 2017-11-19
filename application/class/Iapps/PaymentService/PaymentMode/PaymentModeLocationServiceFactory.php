<?php

namespace Iapps\PaymentService\PaymentMode;

class PaymentModeLocationServiceFactory{

    protected static $_instance = array();

    public static function build()
    {
        if (self::$_instance == NULL) {
            $_ci = get_instance();
            $_ci->load->model('paymentmode/Payment_mode_location_model');
            $repo = new PaymentModeLocationRepository($_ci->Payment_mode_location_model);
            self::$_instance = new PaymentModeLocationService($repo);
        }

        return self::$_instance;
    }
}