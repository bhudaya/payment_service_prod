<?php

namespace Iapps\PaymentService\PromoCode;

use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Core\IappsBaseEntity;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IappsDateTime;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\PromoCode\UserPromoReward;
use Iapps\PaymentService\PromoCode\PromoRewardServiceFactory;
use Iapps\PaymentService\PromoCode\PromoReward;
use Iapps\PaymentService\PromoCode\UserPromoRewardStatus;
use Iapps\PaymentService\PromoCode\PromoRewardTransactionType;
use Iapps\PaymentService\Currency\CurrencyServiceFactory;
use Iapps\Common\Microservice\CountryService\CountryServiceFactory;
use Iapps\PaymentService\CountryCurrency\CountryCurrencyServiceFactory;

class UserPromoRewardService extends IappsBaseService{

    public function updateUserPromoReward(UserPromoReward $userPromoReward)
    {
        
        // $this->getRepository()->deleteElastiCache($userPromoReward->getUserProfileId());
        // exit();

        if ( !$userPromoRewardInfo = $this->getRepository()->findById($userPromoReward->getId())) {
            
            $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_FAIL);
            return false;
        }

        if ( !$promoCode = $this->checkPromoCodeExists($userPromoRewardInfo)) {
            
            $this->setResponseCode(MessageCode::CODE_INVALID_PROMO_CODE);
            return false;
        }

        if ($userPromoRewardInfo->getStatus() == UserPromoRewardStatus::APPLIED) {
            $this->setResponseCode(MessageCode::CODE_PROMO_CODE_USED);
            return false;
        }


        if ( $promoCode->getStartDate()->getString() <= IappsDateTime::now()->getString() 
             && IappsDateTime::now()->getString() < $promoCode->getEndDate()->getString()
             && IappsDateTime::now()->addDay($promoCode->getExpiryPeriod())->getString() < $promoCode->getEndDate()->getString() ) 
        {

            // if ($userPromoRewardInfo) {

                $userPromoRewardInfo->setStatus(UserPromoRewardStatus::APPLIED);
                $this->getRepository()->startDBTransaction();

                if ($this->getRepository()->update($userPromoRewardInfo)) {
                    
                    $this->getRepository()->completeDBTransaction();
                    $this->setResponseCode(MessageCode::CODE_ADD_PROMO_REWARD_SUCCESS);
                    return true;
                }

            // }else{

            //     $userPromoReward->setId(GuidGenerator::generate());
            //     $userPromoReward->setPromoRewardId($promoCode->getId());
            //     $userPromoReward->setExpiryAt(IappsDateTime::now()->addDay($promoCode->getExpiryPeriod()));
            //     $userPromoReward->setStatus(UserPromoRewardStatus::APPLIED);
            //     $userPromoReward->setCreatedBy($userPromoReward->getUserProfileId());

            //     $this->getRepository()->startDBTransaction();

            //     if($this->getRepository()->insert($userPromoReward))
            //     {
            //         $this->getRepository()->completeDBTransaction();
            //         $this->setResponseCode(MessageCode::CODE_ADD_PROMO_REWARD_SUCCESS);
            //         return true;
            //     }
            // }

            $this->setResponseCode(MessageCode::CODE_ADD_PROMO_REWARD_FAIL);
            return false;

        }

        $this->setResponseCode(MessageCode::CODE_INVALID_PROMO_CODE);
        return false;
    }

    public function insertNewRecord(UserPromoReward $userPromoReward)
    {

        // this code will control user won't allowed add same promo code many times. 
        if ( $object = $this->getRepository()->findUserPromoRewardByParmar($userPromoReward) ) {

            $data = $object->result->current();
            return $data;
        }

        $userPromoReward->setId(GuidGenerator::generate());
        $userPromoReward->setStatus(UserPromoRewardStatus::AVAILABLE);

        $this->getRepository()->startDBTransaction();

        if($this->getRepository()->insert($userPromoReward))
        {
            $this->getRepository()->completeDBTransaction();
            $this->setResponseCode(MessageCode::CODE_ADD_PROMO_REWARD_SUCCESS);
            return true;
        }

        $this->setResponseCode(MessageCode::CODE_ADD_PROMO_REWARD_FAIL);
        return false;
    }

    public function getUserPromoRewardByUserProfileId($user_profile_id)
    {


        // var_dump(IappsDateTime::now()->addDay(60));
        if( $object = $this->getRepository()->findUserPromoRewardByUserProfileId($user_profile_id))
        {
            $promoRewardSer = PromoRewardServiceFactory::build();
            $currencySer    = CurrencyServiceFactory::build();
            $countrySer     = CountryServiceFactory::build();

            $results = array();
            $result  = array();

            foreach ($object->result as $eachData) {

                if ($eachData->getStatus() == UserPromoRewardStatus::AVAILABLE && $eachData->getExpiryAt()->getString() < IappsDateTime::now()) {
                        
                    if ($promoRewardDetail = $promoRewardSer->getRepository()->findById($eachData->getPromoRewardId())) {

                        if (IappsDateTime::now()->getString() < $promoRewardDetail->getEndDate()->getString() ) {

                            $result = $eachData->getSelectedField(array('id', 'user_profile_id','tag_user_profile_id', 'promo_reward_id','status','expiry_at','promo_code','created_at','created_by'));
                            $result['mian_type'] = $promoRewardDetail->getMainType();
                            $result['sub_type'] = $promoRewardDetail->getSubType();
                            $result['amount'] = $promoRewardDetail->getAmount();
                            $result['transaction_type'] = $promoRewardDetail->getTransactionType();
                            $result['start_date'] = $promoRewardDetail->getStartDate()->getString();
                            $result['end_date'] = $promoRewardDetail->getEndDate()->getString();
                            $result['expiry_period'] = $promoRewardDetail->getExpiryPeriod();
                            $result['currency'] = NULL;
                            $result['country'] = NULL;

                            if ($promoRewardDetail->getCurrency()->getCode()) {
                                if ( $currencyInfo = $currencySer->getRepository()->findByCode($promoRewardDetail->getCurrency()->getCode()) ) {
                                    $result['currency'] = $currencyInfo;
                                }
                            }

                            if ($promoRewardDetail->getCountry()->getCode()) {
                                if ( $countryInfo = $countrySer->getCountryInfo($promoRewardDetail->getCountry()->getCode()) ) {
                                    $result['country'] = $countryInfo;
                                }
                            }

                            $results[] = $result;

                        }
                    }
                }
            }

            if (count($results) > 0) {
                $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_SUCCESS);
                return $results;
            }

            $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_FAIL);
            return false;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_FAIL);
        return false;
    }


    public function getUserPromoRewardByUserProfileIdAndPromoCode(UserPromoReward $userPromoReward)
    {
        if( $object = $this->getRepository()->findUserPromoRewardByParmar($userPromoReward))
        {
            $promoRewardSer = PromoRewardServiceFactory::build();
            $currencySer    = CurrencyServiceFactory::build();
            $countrySer     = CountryServiceFactory::build();
            $countryCurrnecySer  = CountryCurrencyServiceFactory::build();

            foreach ($object->result as $eachData) {

                if ($eachData->getStatus() == UserPromoRewardStatus::AVAILABLE && $eachData->getExpiryAt()->getString() < IappsDateTime::now()) {
                    
                    if ( $promoRewardDetail = $promoRewardSer->getRepository()->findById($eachData->getPromoRewardId()) ) {

                        if ( IappsDateTime::now()->addDay($promoRewardDetail->getExpiryPeriod())->getString() < $promoRewardDetail->getEndDate()->getString()
                            && IappsDateTime::now()->getString() < $promoRewardDetail->getEndDate()->getString() ) {
                            

                            if ($promoRewardDetail->getCurrency()->getCode()) {
                                if ( $currencyInfo = $currencySer->getRepository()->findByCode($promoRewardDetail->getCurrency()->getCode()) ) {
                                    $promoRewardDetail->setCurrency($currencyInfo);
                                }
                            }

                            if ($promoRewardDetail->getCountry()->getCode()) {
                                if ( $countryInfo = $countrySer->getCountryInfo($promoRewardDetail->getCountry()->getCode()) ) {
                                    $promoRewardDetail->setCountry($countryInfo);
                                }

                                if ( $countryCurrencyInfo = $countryCurrnecySer->getRepository()->findByCountryCode($promoRewardDetail->getCountry()->getCode()) ) {
                                    $promoRewardDetail->setCountryCurrencyCode($countryCurrencyInfo->result->current()->getCode());
                                }
                            }

                            $eachData->setPromoRewardInfo($promoRewardDetail);

                            $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_SUCCESS);

                            return $object->result;
                        }
                    }
                }
            }

            $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_FAIL);
            return false;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_FAIL);
        return false;
    }

    public function checkPromoCodeExists(UserPromoReward $userPromoReward)
    {
        $promoRewardSer = PromoRewardServiceFactory::build();

        if ($object = $promoRewardSer->getRepository()->findById($userPromoReward->getPromoRewardId())) {
            // exixts this promo code on promo_reward table...
            return $object;
        }

        return false;
    }

}