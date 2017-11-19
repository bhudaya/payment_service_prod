<?php

namespace Iapps\PaymentService\Common;

class Rijndael256EncryptorFactory {

    protected static $_instance;

    public static function build()
    {
        if( self::$_instance == NULL )
        {
            if( !$key = getenv('ENCRYPTION_KEY') )
                throw new \Exception('ENCRYPTION KEY IS Not Defined');

            self::$_instance = new Rijndael256Encryptor($key);
        }

        return self::$_instance;
    }
}