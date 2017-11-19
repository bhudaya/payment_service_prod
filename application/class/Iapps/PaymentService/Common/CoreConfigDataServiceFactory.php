<?php

namespace Iapps\PaymentService\Common;

use Iapps\Common\CoreConfigData\CoreConfigDataRepository;
use Iapps\Common\CoreConfigData\CoreConfigDataService;

require_once  './application/modules/common/models/Core_config_data_model.php';

class CoreConfigDataServiceFactory{

    protected static $_instance = NULL;

    public static function build()
    {
        if( self::$_instance == NULL )
        {
            $dm = new \Core_config_data_model();
            $repo = new CoreConfigDataRepository($dm);
            self::$_instance = new CoreConfigDataService($repo);
        }

        return self::$_instance;
    }
}