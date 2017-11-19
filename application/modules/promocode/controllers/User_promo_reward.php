<?php

use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\Common\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IpAddress;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\PromoCode\UserPromoReward;
use Iapps\PaymentService\PromoCode\UserPromoRewardRepository;
use Iapps\PaymentService\PromoCode\UserPromoRewardService;

class User_promo_reward extends Base_Controller{

    protected $_service;

    function __construct()
    {
        parent::__construct();
        $this->load->model('promocode/User_promo_reward_model');
        $repo = new UserPromoRewardRepository($this->User_promo_reward_model);
        $this->_service = new UserPromoRewardService($repo);
        $this->_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
    }

    public function getUserPromoRewardByUserProfileId()
    {
        if (!$user_profile_id = $this->_getUserProfileId()) 
            return false;

        // $user_profile_id = '123';

        if( $object = $this->_service->getUserPromoRewardByUserProfileId($user_profile_id))
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object, 'total' => count($object)));
            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    
    public function updateUserPromoReward()
    {
        if (!$user_profile_id = $this->_getUserProfileId()) 
            return false;

        // $user_profile_id = '123';

        if( !$this->is_required($this->input->post(), array('user_promo_reward_id')))
        {
            return false;
        }

        $userPromoReward = new UserPromoReward();
        $userPromoReward->setId($this->input->post('user_promo_reward_id'));
        $userPromoReward->setUpdatedBy($user_profile_id);
        
        // $userPromoReward->setUserProfileId($this->input->post('user_profile_id'));
        // $userPromoReward->setPromoCode($this->input->post('promo_code'));
        // $userPromoReward->setPromoRewardId($this->input->post('promo_reward_id'));

        if ($this->input->post('tag_user_profile_id')) {
            $userPromoReward->setTagUserProfileId($this->input->post('tag_user_profile_id'));
        }

        if( $object = $this->_service->updateUserPromoReward($userPromoReward))
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object));
            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getUserPromoRewardByUserProfileIdAndPromoCode()
    {
        if (!$user_profile_id = $this->_getUserProfileId()) 
            return false;

        // $user_profile_id = '123';

        if( !$this->is_required($this->input->post(), array('user_profile_id','promo_code')))
        {
            return false;
        }

        $userPromoReward = new UserPromoReward();
        $userPromoReward->setUserProfileId($this->input->post('user_profile_id'));
        $userPromoReward->setPromoCode($this->input->post('promo_code'));

        if( $object = $this->_service->getUserPromoRewardByUserProfileIdAndPromoCode($userPromoReward))
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object, 'total' => count($object)));
            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
        
    }
}