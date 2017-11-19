<?php

namespace Iapps\PaymentService\Common;

use Iapps\Common\Helper\FieldEncryptionInterface;
require_once './system/libraries/Encrypt.php';

class Rijndael256Encryptor implements FieldEncryptionInterface{

    protected $encryptor;
    function __construct($key)
    {
        $this->encryptor = new \CI_Encrypt();
        $this->encryptor->set_key($key);
        $this->encryptor->set_cipher(MCRYPT_RIJNDAEL_256);
    }

    public function encrypt($rawField)
    {
        return $this->encryptor->encode($rawField);
    }

    public function decrypt($encryptedField)
    {
        return $this->encryptor->decode($encryptedField);
    }
}