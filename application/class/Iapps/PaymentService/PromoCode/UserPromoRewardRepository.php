<?php

namespace Iapps\PaymentService\PromoCode;

use Iapps\Common\Core\IappsBaseRepository;

class UserPromoRewardRepository extends IappsBaseRepository{

    public function insert(UserPromoReward $userPromoReward)
    {
        return $this->getDataMapper()->insert($userPromoReward);
    }

    public function update(UserPromoReward $userPromoReward)
    {
        return $this->getDataMapper()->update($userPromoReward);
    }
    
    public function findUserPromoRewardByParmar(UserPromoReward $userPromoReward, $limit = NULL, $page = NULL)
    {
        return $this->getDataMapper()->findUserPromoRewardByParmar($userPromoReward, $limit, $page);
    }

    public function findUserPromoRewardByUserProfileId($user_id)
    {
        return $this->getDataMapper()->findUserPromoRewardByUserProfileId($user_id);
    }

}