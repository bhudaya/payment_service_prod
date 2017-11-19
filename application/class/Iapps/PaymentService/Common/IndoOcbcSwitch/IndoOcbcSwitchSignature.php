<?php

namespace Iapps\PaymentService\Common\IndoOcbcSwitch;

class IndoOcbcSwitchSignature{

    public static function generate($username,
                                    $password,
                                    $product_code,
                                    $merchant_code,
                                    $terminal_code,
                                    $dest_refnumber,
                                    $dest_bankcode,
                                    $dest_bankacc,
                                    $dest_amount
                                    )
    {
        $dataSign = $username ."&".$password ."&". $product_code."&".
                    $merchant_code ."&".$terminal_code ."&".$dest_refnumber ."&".
                    $dest_bankcode ."&".$dest_bankacc ."&".$dest_amount;


        $signature = hash_hmac('sha256', $dataSign, $password, true);
        return base64_encode($signature);
    }
}