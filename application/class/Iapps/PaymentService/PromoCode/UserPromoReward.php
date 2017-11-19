<?php

namespace Iapps\PaymentService\PromoCode;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\PromoCode\PromoReward;

class UserPromoReward extends IappsBaseEntity{

    protected $user_profile_id;
    protected $tag_user_profile_id;
    protected $promo_reward_id;
    protected $status;
    protected $expiry_at;
    protected $promo_code;
    protected $promo_reward_info;


    function __construct()
    {
        parent::__construct();
        $this->expiry_at = new IappsDateTime();
        $this->promo_reward_info = new PromoReward();
    }

    public function setUserProfileId($user_profile_id)
    {
        $this->user_profile_id = $user_profile_id;
        return $this;
    }

    public function getUserProfileId()
    {
        return $this->user_profile_id;
    }

    public function setTagUserProfileId($tag_user_profile_id)
    {
        $this->tag_user_profile_id = $tag_user_profile_id;
        return $this;
    }

    public function getTagUserProfileId()
    {
        return $this->tag_user_profile_id;
    }

    public function setPromoRewardId($promo_reward_id)
    {
        $this->promo_reward_id = $promo_reward_id;
        return $this;
    }

    public function getPromoRewardId()
    {
        return $this->promo_reward_id;
    }

    public function setStatus($status)
    {
        $this->status = $status;
        return $this;
    }

    public function getStatus()
    {
        return $this->status;
    }

    public function setExpiryAt(IappsDateTime $expiry_at)
    {
        $this->expiry_at = $expiry_at;
        return $this;
    }

    public function getExpiryAt()
    {
        return $this->expiry_at;
    }

    public function setPromoCode($promo_code)
    {
        $this->promo_code = $promo_code;
        return $this;
    }

    public function getPromoCode()
    {
        return $this->promo_code;
    }

    public function setPromoRewardInfo(PromoReward $promo_reward_info)
    {
        $this->promo_reward_info = $promo_reward_info;
        return $this;
    }

    public function getPromoRewardInfo()
    {
        return $this->promo_reward_info;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['user_profile_id'] = $this->getUserProfileId();
        $json['tag_user_profile_id'] = $this->getTagUserProfileId();
        $json['promo_reward_id'] = $this->getPromoRewardId();
        $json['status'] = $this->getStatus();
        $json['expiry_at'] = $this->getExpiryAt()->getString();
        $json['promo_code'] = $this->getPromoCode();
        $json['promo_reward_info'] = $this->getPromoRewardInfo();

        return $json;
    }
}