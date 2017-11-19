<?php

namespace Iapps\PaymentService\Common\GPLSwitch;




use Iapps\PaymentService\Common\Logger;

class GPLPGPEncryptor{

    public static function encrypt($string)
    {
        $key_file = './files/gpl_public_key.gpg';
        if (!file_exists($key_file)) {
            throw new \Exception("GPL PGP key doesnt exists! Aborting...", 1);
        }

        try
        {
            $gpg = new \Crypt_GPG();
            $keyInfo = $gpg->importKey(file_get_contents($key_file));
            $gpg->addEncryptKey($keyInfo['fingerprint']);

            $data = $gpg->encrypt($string, false);
        }
        catch (\Exception $e)
        {
            Logger::error('Failed PGP Encryption: ' . $e->getMessage());
            return false;
        }

        return base64_encode($data);
    }
}