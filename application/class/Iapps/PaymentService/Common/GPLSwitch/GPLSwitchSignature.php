<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

class GPLSwitchSignature {

    public static function generate(GPLSwitchClient $gplClient)
    {
        $string = $gplClient->getCustomerRefNo() .
                  $gplClient->getSender()->getFullName() .
                  $gplClient->getReceiver()->getReceiverName() .
                  $gplClient->getTrx()->getTransactionAmount() .
                  $gplClient->getTrx()->getTransactionDate()->getFormat('m/d/Y');

        //encrypt with PGP encryption
        try{
            $signature = GPLPGPEncryptor::encrypt($string);
            $gplClient->setChecksum($signature);
            return $gplClient;
        }
        catch( \Exception $e )
        {
            return false;
        }
    }
}