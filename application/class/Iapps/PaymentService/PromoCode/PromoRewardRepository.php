<?php

namespace Iapps\PaymentService\PromoCode;

use Iapps\Common\Core\IappsBaseRepository;

class PromoRewardRepository extends IappsBaseRepository{

    public function insert(PromoReward $promoReward)
    {
        return $this->getDataMapper()->insert($promoReward);
    }

    public function findAllPromoReward($limit,$page)
    {
        return $this->getDataMapper()->findAllPromoReward($limit,$page);
    }

    public function validatePromoCode($code)
    {
        return $this->getDataMapper()->validatePromoCode($code);
    }

    public function findByPromoCode($code)
    {
        return $this->getDataMapper()->findByPromoCode($code);
    }

    public function findPromoRewardByParmar(PromoReward $promoReward, $limit = NULL, $page = NULL)
    {
        return $this->getDataMapper()->findPromoRewardByParmar($promoReward, $limit, $page);
    }
}