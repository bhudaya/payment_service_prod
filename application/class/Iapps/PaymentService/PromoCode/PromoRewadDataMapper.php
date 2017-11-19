<?php

namespace Iapps\PaymentService\PromoCode;

use Iapps\Common\Core\IappsBaseDataMapper;

interface PromoRewadDataMapper extends IappsBaseDataMapper{

    public function insert(PromoReward $promoReward);
    public function findAllPromoReward($limit,$page);
    public function validatePromoCode($code);
    public function findByPromoCode($code);
    public function findPromoRewardByParmar(PromoReward $promoReward, $limit = NULL, $page = NULL);
    
}