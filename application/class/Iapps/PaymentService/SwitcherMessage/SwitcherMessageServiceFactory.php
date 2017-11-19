<?php

namespace Iapps\PaymentService\SwitcherMessage;


class SwitcherMessageServiceFactory{

    protected static $_instance = NULL;

    public static function build()
    {
        if( self::$_instance == NULL )
        {
            $_ci = get_instance();
            $_ci->load->model('common/Switcher_message_model');
            $repo = new SwitcherMessageRepository($_ci->Switcher_message_model);
            self::$_instance = new SwitcherMessageService($repo);
        }

        return self::$_instance;
    }
}