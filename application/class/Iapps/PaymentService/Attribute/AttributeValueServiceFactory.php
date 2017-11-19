<?php

namespace Iapps\PaymentService\Attribute;

class AttributeValueServiceFactory{

    protected static $_instance;

    public static function build()
    {
        if( self::$_instance == NULL )
        {
            $_ci = get_instance();
            $_ci->load->model('attribute/Attribute_value_model');
            $repo = new AttributeValueRepository($_ci->Attribute_value_model);
            self::$_instance = new AttributeValueService($repo);
        }

        return self::$_instance;
    }
}