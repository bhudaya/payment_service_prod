<?php

use Iapps\PaymentService\PromoCode\PromoRewadDataMapper;
use Iapps\PaymentService\PromoCode\PromoReward;
use Iapps\PaymentService\PromoCode\PromoRewardCollection;
use Iapps\Common\Core\IappsDateTime;

class Promo_reward_model extends Base_Model
                            implements PromoRewadDataMapper
{

    public function map(stdClass $data)
    {
        $entity = new PromoReward();

        if (isset($data->id))
            $entity->setId($data->id);

        if (isset($data->mian_type))
            $entity->setMainType($data->mian_type);

        if (isset($data->sub_type))
            $entity->setSubType($data->sub_type);

        if (isset($data->promo_code))
            $entity->setPromoCode($data->promo_code);

        if (isset($data->currency_code))
            $entity->getCurrency()->setCode($data->currency_code);

        if (isset($data->amount))
            $entity->setAmount($data->amount);

        if (isset($data->transaction_type))
            $entity->setTransactionType($data->transaction_type);

        if (isset($data->country_code))
            $entity->getCountry()->setCode($data->country_code);

        if (isset($data->start_date))
            $entity->setStartDate(IappsDateTime::fromUnix($data->start_date));

        if (isset($data->end_date))
            $entity->setEndDate(IappsDateTime::fromUnix($data->end_date));

        if (isset($data->expiry_period))
            $entity->setExpiryPeriod($data->expiry_period);

        if (isset($data->created_at))
            $entity->setCreatedAt(IappsDateTime::fromUnix($data->created_at));

        if (isset($data->created_by))
            $entity->setCreatedBy($data->created_by);

        if (isset($data->updated_at))
            $entity->setUpdatedAt(IappsDateTime::fromUnix($data->updated_at));

        if (isset($data->updated_by))
            $entity->setUpdatedBy($data->updated_by);

        if (isset($data->deleted_at))
            $entity->setDeletedAt(IappsDateTime::fromUnix($data->deleted_at));

        if (isset($data->deleted_by))
            $entity->setDeletedBy($data->deleted_by);

        return $entity;
    }

    public function findById($id, $deleted = false)
    {
        $this->db->select("*");
        $this->db->from('iafb_payment.promo_reward pr');
        $this->db->where('pr.id', $id);
        $this->db->where('pr.deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByPromoCode($code)
    {
        $total = 0;
        $this->db->start_cache(); //to cache active record query
        $this->db->select("pr.id,
                           pr.mian_type,
                           pr.sub_type,
                           pr.promo_code,
                           pr.currency_code,
                           pr.amount,
                           pr.transaction_type,
                           pr.country_code,
                           pr.start_date,
                           pr.end_date,
                           pr.expiry_period,
                           pr.created_at,
                           pr.created_by,
                           pr.updated_at,
                           pr.updated_by,
                           pr.deleted_at,
                           pr.deleted_by");
        $this->db->from('iafb_payment.promo_reward pr');
        $this->db->where('pr.promo_code', $code);
        $this->db->where('pr.deleted_at', NULL);

        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        $query = $this->db->get();
        $this->db->flush_cache();
        
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PromoRewardCollection(), $total);
        }

        return false;
    }

    public function findAllPromoReward($limit, $page)
    {
        $total = 0;
        $offset = ($page - 1) * $limit;

        $this->db->start_cache(); //to cache active record query
        $this->db->select("pr.id,
                           pr.mian_type,
                           pr.sub_type,
                           pr.promo_code,
                           pr.currency_code,
                           pr.amount,
                           pr.transaction_type,
                           pr.country_code,
                           pr.start_date,
                           pr.end_date,
                           pr.expiry_period,
                           pr.created_at,
                           pr.created_by,
                           pr.updated_at,
                           pr.updated_by,
                           pr.deleted_at,
                           pr.deleted_by");
        $this->db->from('iafb_payment.promo_reward pr');
        $this->db->where('pr.deleted_at', NULL);
        $this->db->stop_cache();
        
        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        
        $this->db->limit($limit, $offset);
        $query = $this->db->get();
        $this->db->flush_cache();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PromoRewardCollection(), $total);
        }

        return false;
    }

    public function findPromoRewardByParmar(PromoReward $promoReward, $limit = NULL, $page = NULL)
    {
        $total = 0;
        if ($limit != NULL &&  $page != NULL) {
            $offset = ($page - 1) * $limit;
        }

        $this->db->start_cache(); //to cache active record query
        $this->db->select("pr.id,
                           pr.mian_type,
                           pr.sub_type,
                           pr.promo_code,
                           pr.currency_code,
                           pr.amount,
                           pr.transaction_type,
                           pr.country_code,
                           pr.start_date,
                           pr.end_date,
                           pr.expiry_period,
                           pr.created_at,
                           pr.created_by,
                           pr.updated_at,
                           pr.updated_by,
                           pr.deleted_at,
                           pr.deleted_by");
        $this->db->from('iafb_payment.promo_reward pr');

        if($promoReward->getId())
        {
            $this->db->where('id', $promoReward->getId());
        }

        if($promoReward->getPromoCode())
        {
            $this->db->where('promo_code', $promoReward->getPromoCode());
        }

        $this->db->where('deleted_at', NULL);
        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        if ($limit != NULL &&  $page != NULL) {
            $this->db->limit($limit, $offset);
        }
        $query = $this->db->get();
        $this->db->flush_cache();

        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PromoRewardCollection(), $total);
        }

        return false;
    }

    public function validatePromoCode($code)
    {
        $this->db->select("*");
        $this->db->from('iafb_payment.promo_reward pr');
        $this->db->where('pr.promo_code', $code);
        $this->db->where('pr.deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return true;
        }

        return false;
    }

    public function insert(PromoReward $promoReward)
    {
        $this->db->set('id', $promoReward->getId());
        $this->db->set('mian_type', $promoReward->getMainType());
        $this->db->set('sub_type', $promoReward->getSubType());

        if ($promoReward->getPromoCode()) 
            $this->db->set('promo_code', $promoReward->getPromoCode());

        $this->db->set('currency_code', $promoReward->getCurrency()->getCode());
        $this->db->set('amount', $promoReward->getAmount());
        $this->db->set('transaction_type', $promoReward->getTransactionType());
        $this->db->set('country_code', $promoReward->getCountry()->getCode());
                
        if ($promoReward->getStartDate()) 
            $this->db->set('start_date', $promoReward->getStartDate()->getUnix());

        if ($promoReward->getEndDate()) 
            $this->db->set('end_date', $promoReward->getEndDate()->getUnix());

        $this->db->set('expiry_period', $promoReward->getExpiryPeriod());
        $this->db->set('created_at', IappsDateTime::now()->getUnix());
        $this->db->set('created_by', $promoReward->getCreatedBy());

        if ($this->db->insert('iafb_payment.promo_reward')) {
            return true;
        }

        return false;
    }



}