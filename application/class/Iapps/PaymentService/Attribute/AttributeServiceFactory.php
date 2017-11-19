<?php

namespace Iapps\PaymentService\Attribute;

class AttributeServiceFactory{

    protected static $_instance;

    public static function build()
    {
        if( self::$_instance == NULL )
        {
            $_ci = get_instance();
            $_ci->load->model('attribute/Attribute_model');
            $repo = new AttributeRepository($_ci->Attribute_model);
            self::$_instance = new AttributeService($repo);
        }

        return self::$_instance;
    }
}