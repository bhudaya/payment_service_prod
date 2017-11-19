<?php

namespace Iapps\PaymentService\PaymentMode;

class PaymentModeServiceFactory{

    protected static $_instance = array();

    public static function build()
    {
        if (self::$_instance == NULL) {
            $_ci = get_instance();
            $_ci->load->model('paymentmode/Payment_mode_model');
            $repo = new PaymentModeRepository($_ci->Payment_mode_model);
            self::$_instance = new PaymentModeService($repo);
        }

        return self::$_instance;
    }
}