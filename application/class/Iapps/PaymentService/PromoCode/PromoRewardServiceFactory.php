<?php

namespace Iapps\PaymentService\PromoCode;

require_once './application/modules/promocode/models/Promo_reward_model.php';

class PromoRewardServiceFactory{

    protected static $_instance = array();

    public static function build()
    {
        if (self::$_instance == NULL) {
            $dm = new \Promo_reward_model();
            $repo = new PromoRewardRepository($dm);
            self::$_instance = new PromoRewardService($repo);
        }

        return self::$_instance;
    }
}