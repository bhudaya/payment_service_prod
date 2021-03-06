<?php

namespace Iapps\PaymentService\PaymentRequest;

class PaymentRequestUserConversionServiceFactory {

    protected static $_instance;

    public static function build()
    {
        if( self::$_instance == NULL )
        {
            $_ci = get_instance();
            $_ci->load->model('paymentrequest/Payment_request_model');
            $repo = new PaymentRequestRepository($_ci->Payment_request_model);
            self::$_instance = new PaymentRequestUserConversionService($repo);
        }

        return self::$_instance;
    }
}