<?php

use Iapps\PaymentService\PromoCode\UserPromoRewadDataMapper;
use Iapps\PaymentService\PromoCode\UserPromoReward;
use Iapps\PaymentService\PromoCode\UserPromoRewardCollection;
use Iapps\Common\Core\IappsDateTime;

class User_promo_reward_model extends Base_Model
                            implements UserPromoRewadDataMapper
{
    public function map(stdClass $data)
    {
        $entity = new UserPromoReward();

        if (isset($data->id))
            $entity->setId($data->id);

        if (isset($data->user_profile_id))
            $entity->setUserProfileId($data->user_profile_id);

        if (isset($data->tag_user_profile_id))
            $entity->setTagUserProfileId($data->tag_user_profile_id);

        if (isset($data->promo_reward_id))
            $entity->setPromoRewardId($data->promo_reward_id);

        if (isset($data->status))
            $entity->setStatus($data->status);

        if (isset($data->expiry_at))
            $entity->setExpiryAt(IappsDateTime::fromUnix($data->expiry_at));

        if (isset($data->promo_code))
            $entity->setPromoCode($data->promo_code);

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
        $this->db->from('iafb_payment.user_promo_reward upr');
        $this->db->where('upr.id', $id);
        $this->db->where('upr.deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findUserPromoRewardByUserProfileId($user_id)
    {
        $total = 0;

        $this->db->start_cache(); //to cache active record query
        $this->db->select("upr.id,
                   upr.user_profile_id,
                   upr.tag_user_profile_id,
                   upr.promo_reward_id,
                   upr.status,
                   upr.expiry_at,
                   upr.promo_code,
                   upr.created_at,
                   upr.created_by,
                   upr.updated_at,
                   upr.updated_by,
                   upr.deleted_at,
                   upr.deleted_by");
        $this->db->from('iafb_payment.user_promo_reward upr');
        $this->db->where('user_profile_id', $user_id);
        $this->db->where('deleted_at', NULL);
        $this->db->order_by('expiry_at', 'asc');

        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit

        $query = $this->db->get();
        $this->db->flush_cache();

        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new UserPromoRewardCollection(), $total);
        }

        return false;
    }

    public function findUserPromoRewardByParmar(UserPromoReward $userPromoReward, $limit = NULL, $page = NULL)
    {
        $total = 0;
        if ($limit != NULL &&  $page != NULL) {
            $offset = ($page - 1) * $limit;
        }

        $this->db->start_cache(); //to cache active record query
        $this->db->select("upr.id,
                   upr.user_profile_id,
                   upr.tag_user_profile_id,
                   upr.promo_reward_id,
                   upr.status,
                   upr.expiry_at,
                   upr.promo_code,
                   upr.created_at,
                   upr.created_by,
                   upr.updated_at,
                   upr.updated_by,
                   upr.deleted_at,
                   upr.deleted_by");
        $this->db->from('iafb_payment.user_promo_reward upr');

        if($userPromoReward->getId())
        {
            $this->db->where('id', $userPromoReward->getId());
        }

        if($userPromoReward->getUserProfileId())
        {
            $this->db->where('user_profile_id', $userPromoReward->getUserProfileId());
        }

        if($userPromoReward->getStatus())
        {
            $this->db->where('status', $userPromoReward->getStatus());
        }

        if($userPromoReward->getPromoCode())
        {
            $this->db->where('promo_code', $userPromoReward->getPromoCode());
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
            return $this->mapCollection($query->result(), new UserPromoRewardCollection(), $total);
        }

        return false;
    }

    public function insert(UserPromoReward $userPromoReward)
    {
        $this->db->set('id', $userPromoReward->getId());
        $this->db->set('user_profile_id', $userPromoReward->getUserProfileId());
        $this->db->set('tag_user_profile_id', $userPromoReward->getTagUserProfileId());
        $this->db->set('promo_reward_id', $userPromoReward->getPromoRewardId());
        $this->db->set('status', $userPromoReward->getStatus());
        $this->db->set('expiry_at', $userPromoReward->getExpiryAt()->getUnix());
        $this->db->set('promo_code', $userPromoReward->getPromoCode());
        $this->db->set('created_at', IappsDateTime::now()->getUnix());
        $this->db->set('created_by', $userPromoReward->getCreatedBy());

        if ($this->db->insert('iafb_payment.user_promo_reward')) {
            return true;
        }

        return false;
    }


    public function update(UserPromoReward $userPromoReward)
    { 
        if ($userPromoReward->getTagUserProfileId()) {
            $this->db->set('tag_user_profile_id', $userPromoReward->getTagUserProfileId());
        }

        if ($userPromoReward->getStatus()) {
            $this->db->set('status', $userPromoReward->getStatus());
        }

        if ($userPromoReward->getExpiryAt()->getUnix()) {
            $this->db->set('expiry_at', $userPromoReward->getExpiryAt()->getUnix());
        }

        $this->db->set('updated_at', IappsDateTime::now()->getUnix());
        $this->db->set('updated_by', $userPromoReward->getUpdatedBy());

        $this->db->where('id', $userPromoReward->getId());

        if ($this->db->update('iafb_payment.user_promo_reward')) {
            return true;
        }

        return false;
    }


}