<?php

namespace Iapps\PaymentService\Common;

use Iapps\Common\SystemCode\SystemCodeRepositoryV2;
use Iapps\Common\SystemCode\SystemCodeServiceV2;

class SystemCodeServiceFactory{

    protected static $_instance = NULL;

    public static function build()
    {
        if( self::$_instance == NULL )
        {
            $_ci = get_instance();
            $_ci->load->model('common/Systemcode_model');
            $repo = new SystemCodeRepositoryV2($_ci->Systemcode_model);
            self::$_instance = new SystemCodeServiceV2($repo);
        }

        return self::$_instance;
    }
}