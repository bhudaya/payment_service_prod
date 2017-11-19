<?php

namespace Iapps\PaymentService\PromoCode;

use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Core\IappsBaseEntity;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IappsDateTime;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\PromoCode\PromoReward;
use Iapps\PaymentService\PromoCode\PromoRewardMainType;
use Iapps\PaymentService\PromoCode\PromoRewardSubType;
use Iapps\PaymentService\PromoCode\PromoRewardTransactionType;
use Iapps\PaymentService\Currency\CurrencyServiceFactory;
use Iapps\Common\Microservice\CountryService\CountryServiceFactory;
use Iapps\PaymentService\PromoCode\UserPromoRewardServiceFactory;
use Iapps\PaymentService\PromoCode\UserPromoReward;

class PromoRewardService extends IappsBaseService{

    public function addNewPromoReward(PromoReward $promoReward)
    {
        if (!$this->_validate($promoReward)) 
        {
            return false;
        }

        $promoReward->setId(GuidGenerator::generate());

        $this->getRepository()->startDBTransaction();

        if($this->getRepository()->insert($promoReward))
        {
            $this->getRepository()->completeDBTransaction();
            $this->setResponseCode(MessageCode::CODE_ADD_PROMO_REWARD_SUCCESS);
            return $promoReward;
        }

        $this->setResponseCode(MessageCode::CODE_ADD_PROMO_REWARD_FAIL);
        return false;
    }

    public function getAllPromoReward($limit,$page)
    {
        if( $object = $this->getRepository()->findAllPromoReward($limit, $page))
        {

            if( $object->result instanceof PromoRewardCollection )
            {
                $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_SUCCESS);
                return $object;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_FAIL);
        return false;
    }

    public function getPromoRewardByPromoCode($code,$user_id)
    {
        if( $object = $this->getRepository()->findByPromoCode($code))
        {

        // $this->getRepository()->deleteElastiCache($user_id);
        // exit();

            if ($this->getRepository()->getElasticCache($user_id)) {
                if ($this->getRepository()->getElasticCache($user_id) < 10) {
                    $this->getRepository()->deleteElastiCache($user_id);
                }else{
                    $this->setResponseCode(MessageCode::CODE_PLEASE_TRY_AGAIN_IN_1_HOURS);
                    return false;
                }
            }

            if( $object->result instanceof PromoRewardCollection )
            {
                foreach ($object->result as $eachData) {

                    if ( IappsDateTime::now()->getString() >= $eachData->getEndDate()->getString()) {
                        $this->setResponseCode(MessageCode::CODE_PROMO_CODE_HAS_EXPIRED);
                        return false;
                    }

                    $userPromoSer = UserPromoRewardServiceFactory::build();

                    $userPromoRewardEntity = new UserPromoReward();

                    $userPromoRewardEntity->setUserProfileId($user_id);
                    $userPromoRewardEntity->setPromoCode($eachData->getPromoCode());
                    $userPromoRewardEntity->setPromoRewardId($eachData->getId());
                    $userPromoRewardEntity->setExpiryAt(IappsDateTime::now()->addDay($eachData->getExpiryPeriod()));
                    $userPromoRewardEntity->setCreatedBy($user_id);

                    if ($data = $userPromoSer->insertNewRecord($userPromoRewardEntity)) {
                        
                        if (is_object($data)) {

                            if ($data->getStatus() == UserPromoRewardStatus::APPLIED) {
                                $this->setResponseCode(MessageCode::CODE_PROMO_CODE_USED);
                                return false;
                            }else{
                                $this->setResponseCode(MessageCode::CODE_ALREADY_EXISTING_SAME_PROMO_CODE);
                                return false;
                            }
                        }

                    }else{

                        $this->setResponseCode(MessageCode::CODE_ADD_PROMO_REWARD_FAIL);
                        return false;
                    }
                    
                    $results = array();
                    $result  = array();

                    if ($eachData->getCurrency()->getCode()) {

                        $currencySer = CurrencyServiceFactory::build();
                        if ( $currencyInfo = $currencySer->getRepository()->findByCode($eachData->getCurrency()->getCode()) ) {
                            $eachData->setCurrency($currencyInfo);
                        }
                    }

                    if ($eachData->getCountry()->getCode()) {
                        $countrySer = CountryServiceFactory::build();
                        if ( $countryInfo = $countrySer->getCountryInfo($eachData->getCountry()->getCode()) ) {
                            $eachData->setCountry($countryInfo);
                        }
                    }

                    $result = $eachData->getSelectedField(array('id', 'mian_type','sub_type', 'promo_code','currency_code','amount','transaction_type','country_code','start_date','end_date','expiry_period','currency','country','created_at','created_by','updated_at','updated_by'));

                    $result['expiry_at'] = IappsDateTime::now()->addDay($eachData->getExpiryPeriod())->getString();

                    $results[] = $result;

                    $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_SUCCESS);
                    return $results;
                }
            }
        }else{

            if ($this->getRepository()->getElasticCache($user_id)) {
                $input_num = $this->getRepository()->getElasticCache($user_id);
                $input_num += 1;

                $this->getRepository()->setElasticCache($user_id,$input_num);

                if ( $this->getRepository()->getElasticCache($user_id) >= 10) {
                    $this->setResponseCode(MessageCode::CODE_PLEASE_TRY_AGAIN_IN_1_HOURS);
                    return false;
                }

            }else{
                $input_num = 1;
            }

            $this->getRepository()->setElasticCache($user_id,$input_num);

            $this->setResponseCode(MessageCode::CODE_INVALID_PROMO_CODE);
            return false;
        }
    }

    public function getPromoRewardByParmar(PromoReward $promoReward, $limit = NULL, $page = NULL)
    {
        if( $object = $this->getRepository()->findPromoRewardByParmar($promoReward, $limit, $page))
        {
            if( $object->result instanceof PromoRewardCollection )
            {
                $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_SUCCESS);
                return $object;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_PROMO_REWARD_FAIL);
        return false;
    }


    protected function _validate(PromoReward $promoReward)
    {
        if ($promoReward->getMainType() != PromoRewardMainType::NEW_USER_REWARD && $promoReward->getMainType()!= PromoRewardMainType::AD_HOC)
        {
            $this->setResponseCode(MessageCode::CODE_VALIDATE_PROMO_REWARD_FAIL);
            return false;
        }

        if ($promoReward->getSubType() != PromoRewardSubType::NEW_USER_DEFAULT_REWARD 
            && $promoReward->getSubType()!= PromoRewardSubType::NEW_USER_CAMPAIGN_REWARD
            && $promoReward->getSubType()!= PromoRewardSubType::NEW_USER_REFERRAL_CAMPAIGN_REWARD 
            && $promoReward->getSubType()!= PromoRewardSubType::NEW_USER_REFERRAL_DEFAULT_REWARD 
            && $promoReward->getSubType()!= PromoRewardSubType::AD_HOC_PROMO_REWARD)
        {
            $this->setResponseCode(MessageCode::CODE_VALIDATE_PROMO_REWARD_FAIL);
            return false;
        }

        if ($promoReward->getTransactionType() != PromoRewardTransactionType::PROMO_REWARD_TRANSACTION_TYPE_EWALLET 
            && $promoReward->getTransactionType()!= PromoRewardTransactionType::PROMO_REWARD_TRANSACTION_TYPE_REMITTANCE
            && $promoReward->getTransactionType()!= PromoRewardTransactionType::PROMO_REWARD_TRANSACTION_TYPE_BILL)
        {
            $this->setResponseCode(MessageCode::CODE_VALIDATE_PROMO_REWARD_FAIL);
            return false;
        }


        if ($promoReward->getMainType() == PromoRewardMainType::AD_HOC) {
            if ($promoReward->getSubType()!= PromoRewardSubType::AD_HOC_PROMO_REWARD) {

                $this->setResponseCode(MessageCode::CODE_VALIDATE_PROMO_REWARD_FAIL);
                return false;
            }
        }

        if ($this->getRepository()->validatePromoCode($promoReward->getPromoCode())) {
            // already has same promo code, can not add it again.
            $this->setResponseCode(MessageCode::CODE_ALREADY_EXISTING_SAME_PROMO_CODE);
            return false;
        }

        return true;
    }
}