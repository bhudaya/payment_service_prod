<?php

namespace Iapps\PaymentService\Currency;

class CurrencyInfoExtractor{

    public static function extract(array $list, $key = 'currency_code')
    {
        $codes = array();
        foreach($list AS $info)
        {
            $codes[] = $info[$key];
        }

        $currencies = array();
        $cur_serv = CurrencyServiceFactory::build();
        if($currency_info = $cur_serv->getBulkCurrencyInfo($codes))
        {
            //map code as key
            foreach($currency_info->result AS $currency)
            {
                $currencies[$currency['code']] = $currency;
            }
        }

        $newlist = array();
        foreach($list AS $info)
        {
            if( array_key_exists($info[$key], $currencies))
            {
                $info['currency_info'] = $currencies[$info[$key]];
            }
            else
                $info['currency_info'] = NULL;

            $newlist[] = $info;
        }

        return $newlist;
    }
}