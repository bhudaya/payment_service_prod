<?php

namespace Iapps\PaymentService\CodeMapper;

class CodeMapperServiceFactory{
    protected static $_instance;

    public static function build()
    {
        if( self::$_instance == NULL )
        {
            $_ci = get_instance();
            $_ci->load->model('common/Code_mapper_model');
            $repo = new CodeMapperRepository($_ci->Code_mapper_model);
            self::$_instance = new CodeMapperService($repo);
        }

        return self::$_instance;
    }
}