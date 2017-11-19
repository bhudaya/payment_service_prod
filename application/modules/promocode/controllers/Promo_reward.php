<?php

use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\Common\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IpAddress;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\PromoCode\PromoRewardMainType;
use Iapps\PaymentService\PromoCode\PromoRewardSubType;
use Iapps\PaymentService\PromoCode\PromoReward;
use Iapps\PaymentService\PromoCode\PromoRewardRepository;
use Iapps\PaymentService\PromoCode\PromoRewardService;

class Promo_reward extends Base_Controller{

    protected $_service;

    function __construct()
    {
        parent::__construct();
        $this->load->model('promocode/Promo_reward_model');
        $repo = new PromoRewardRepository($this->Promo_reward_model);
        $this->_service = new PromoRewardService($repo);
        $this->_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
    }

    public function getAllPromoReward()
    {
        $limit = $this->_getLimit();
        $page = $this->_getPage();

        if( $object = $this->_service->getAllPromoReward($limit,$page))
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object->result, 'total' => $object->total));
            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;

    }
    
    public function getPromoRewardDetailByPromoCode()
    {
        if (!$user_profile_id = $this->_getUserProfileId()) 
            return false;

        // $user_profile_id = '123';

        if( !$this->is_required($this->input->post(), array('promo_code')))
        {
            return false;
        }

        $promo_code = $this->input->post('promo_code');
        $user_id = $user_profile_id;

        if( $object = $this->_service->getPromoRewardByPromoCode($promo_code,$user_id))
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object, 'total' => count($object)));
            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function addPromoReward()
    {
        if (!$admin_id = $this->_getUserProfileId()) 
            return false;

        // $admin_id = '123';

        if( !$this->is_required($this->input->post(), array('reward_main_type','reward_sub_type','currency_code',
                                                            'reward_amount','transaction_type','country_code','expiry_period')))
        {
            return false;
        }

        if ($this->input->post('reward_main_type') == PromoRewardMainType::AD_HOC) {
            if (!$this->is_required($this->input->post(), array('promo_code'))) {
                return false;
            }
        }

        if ($this->input->post('reward_sub_type') == PromoRewardSubType::NEW_USER_CAMPAIGN_REWARD 
            || $this->input->post('reward_sub_type') == PromoRewardSubType::NEW_USER_REFERRAL_CAMPAIGN_REWARD
            || $this->input->post('reward_sub_type') == PromoRewardSubType::AD_HOC_PROMO_REWARD) 
        {
            if (!$this->is_required($this->input->post(), array('start_date','end_date'))) {
                return false;
            }
        }

        $promoReward = new PromoReward();
        $promoReward->setMainType($this->input->post('reward_main_type'));
        $promoReward->setSubType($this->input->post('reward_sub_type'));
        $promoReward->getCurrency()->setCode($this->input->post('currency_code'));
        $promoReward->setAmount($this->input->post('reward_amount'));
        $promoReward->setTransactionType($this->input->post('transaction_type'));
        $promoReward->getCountry()->setCode($this->input->post('country_code'));
        $promoReward->setExpiryPeriod($this->input->post('expiry_period')); // defualt unit is day....
        $promoReward->setCreatedBy($admin_id);

        if ($this->input->post('promo_code')) 
            $promoReward->setPromoCode($this->input->post('promo_code'));

        if ($this->input->post('start_date')) 
            $promoReward->setStartDate(IappsDateTime::fromString($this->input->post('start_date')));

        if ($this->input->post('end_date')) 
            $promoReward->setEndDate(IappsDateTime::fromString($this->input->post('end_date')));


        if( $object = $this->_service->addNewPromoReward($promoReward))
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object));
            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
}