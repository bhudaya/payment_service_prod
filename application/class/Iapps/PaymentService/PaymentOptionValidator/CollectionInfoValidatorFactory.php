<?php

namespace Iapps\PaymentService\PaymentOptionValidator;

use Iapps\PaymentService\PaymentMode\PaymentModeType;

class CollectionInfoValidatorFactory{

    protected static $_instance = array();

    public static function build($country_code)
    {
        if( !isset(self::$_instance[$country_code]) )
        {
            switch($country_code)
            {
            case 'ID':
                //all manual bank transfer to indo bank will use tektaya!, temporary disable
                self::$_instance[$country_code] = new IndoBankCollectionInfoValidator();
                break;
            default:
                self::$_instance[$country_code] = new CollectionInfoValidator();
                break;
            }
        }

        return self::$_instance[$country_code];
    }
}