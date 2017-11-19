<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

class PaymentModeAttributeValueServiceFactory{

    protected static $_instance = array();

    public static function build()
    {
        if (self::$_instance == NULL) {
            $_ci = get_instance();
            $_ci->load->model('paymentmodeattribute/Payment_mode_attribute_value_model');
            $repo = new PaymentModeAttributeValueRepository($_ci->Payment_mode_attribute_value_model);
            self::$_instance = new PaymentModeAttributeValueService($repo);
        }

        return self::$_instance;
    }
}