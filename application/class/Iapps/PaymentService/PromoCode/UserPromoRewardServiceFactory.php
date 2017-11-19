<?php

namespace Iapps\PaymentService\PromoCode;

require_once './application/modules/promocode/models/User_promo_reward_model.php';

class UserPromoRewardServiceFactory{

    protected static $_instance = array();

    public static function build()
    {
        if (self::$_instance == NULL) {
            $dm = new \User_promo_reward_model();
            $repo = new UserPromoRewardRepository($dm);
            self::$_instance = new UserPromoRewardService($repo);
        }

        return self::$_instance;
    }
}