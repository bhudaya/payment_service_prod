<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

class PaymentModeAttributeServiceFactory{

    protected static $_instance = array();

    /**
     * 
     * @return PaymentModeAttributeService
     */
    public static function build()
    {
        if (self::$_instance == NULL) {
            $_ci = get_instance();
            $_ci->load->model('paymentmodeattribute/Payment_mode_attribute_model');
            $repo = new PaymentModeAttributeRepository($_ci->Payment_mode_attribute_model);
            self::$_instance = new PaymentModeAttributeService($repo);
        }

        return self::$_instance;
    }
}