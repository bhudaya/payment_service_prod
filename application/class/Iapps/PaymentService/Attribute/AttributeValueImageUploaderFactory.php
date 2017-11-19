<?php

namespace Iapps\PaymentService\Attribute;

class AttributeValueImageUploaderFactory{

    protected static $_instance;

    public static function build($key)
    {
        if( self::$_instance == NULL )
        {
            self::$_instance = new AttributeValueImageUploader($key);
        }

        self::$_instance->setFileName($key);
        return self::$_instance;
    }
}