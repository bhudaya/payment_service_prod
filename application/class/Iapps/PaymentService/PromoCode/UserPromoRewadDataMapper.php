<?php

namespace Iapps\PaymentService\PromoCode;

use Iapps\Common\Core\IappsBaseDataMapper;

interface UserPromoRewadDataMapper extends IappsBaseDataMapper{

    public function insert(UserPromoReward $userPromoReward);
    public function update(UserPromoReward $userPromoReward);
    public function findUserPromoRewardByParmar(UserPromoReward $userPromoReward, $limit = NULL, $page = NULL);
    public function findUserPromoRewardByUserProfileId($user_id);

}