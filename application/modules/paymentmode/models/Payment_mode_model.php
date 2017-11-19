<?php

use Iapps\PaymentService\PaymentMode\IPaymentModeDataMapper;
use Iapps\PaymentService\PaymentMode\PaymentMode;
use Iapps\PaymentService\PaymentMode\PaymentModeCollection;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\PaymentMode\PaymentModeGroup;

class payment_mode_model extends Base_Model implements IPaymentModeDataMapper{

    public function map(stdClass $data)
    {
        $entity = new PaymentMode();
        if( isset($data->payment_mode_id) )
            $entity->setId($data->payment_mode_id);

        if( isset($data->code) )
            $entity->setCode($data->code);

        if( isset($data->name) )
            $entity->setName($data->name);

        if( isset($data->payment_mode_group_id) )
            $entity->getPaymentModeGroup()->setId($data->payment_mode_group_id);

        if( isset($data->payment_mode_group) )
            $entity->getPaymentModeGroup()->setCode($data->payment_mode_group);

        if( isset($data->payment_mode_group_name))
            $entity->getPaymentModeGroup()->setDisplayName($data->payment_mode_group_name);

        if( isset($data->self_service) )
            $entity->setSelfService($data->self_service);

        if( isset($data->need_approval) )
            $entity->setNeedApproval($data->need_approval);

        if( isset($data->for_refund) )
            $entity->setForRefund($data->for_refund);

        if( isset($data->is_payment_mode) )
            $entity->setIsPaymentMode($data->is_payment_mode);

        if( isset($data->is_collection_mode) )
            $entity->setIsCollectionMode($data->is_collection_mode);

        if( isset($data->delivery_time_id) )
            $entity->getDeliveryTime()->setId($data->delivery_time_id);

        if( isset($data->delivery_time_code) )
            $entity->getDeliveryTime()->setCode($data->delivery_time_code);

        if( isset($data->delivery_time_name) )
            $entity->getDeliveryTime()->setDisplayName($data->delivery_time_name);

        if( isset($data->created_at) )
            $entity->setCreatedAt(IappsDateTime::fromUnix($data->created_at));

        if( isset($data->created_by) )
            $entity->setCreatedBy($data->created_by);

        if( isset($data->updated_at) )
            $entity->setUpdatedAt(IappsDateTime::fromUnix($data->updated_at));

        if( isset($data->updated_by) )
            $entity->setUpdatedBy($data->updated_by);

        if( isset($data->deleted_at) )
            $entity->setDeletedAt(IappsDateTime::fromUnix($data->deleted_at));

        if( isset($data->deleted_by) )
            $entity->setDeletedBy($data->deleted_by);

        return $entity;
    }

    public function findById($id, $deleted = false)
    {
        $this->db->select('pm.id as payment_mode_id,
                           pm.code,
                           pm.name,
                           pm.payment_mode_group_id,
                           usp.code as payment_mode_group,
                           usp.display_name as payment_mode_group_name,
                           pm.self_service,
                           pm.need_approval,
                           pm.for_refund,
                           pm.is_payment_mode,
                           pm.is_collection_mode,
                           dt.id delivery_time_id,
                           dt.code delivery_time_code,
                           dt.display_name delivery_time_name,
                           pm.created_at,
                           pm.created_by,
                           pm.updated_at,
                           pm.updated_by,
                           pm.deleted_at,
                           pm.deleted_by');
        $this->db->from('iafb_payment.payment_mode pm');
        $this->db->join('iafb_payment.system_code usp', 'pm.payment_mode_group_id = usp.id');
        $this->db->join('iafb_payment.system_code_group uspg', 'usp.system_code_group_id = uspg.id');
        $this->db->join('iafb_payment.system_code dt', 'pm.delivery_time_id = dt.id', 'left');
        $this->db->join('iafb_payment.system_code_group dtg', 'dt.system_code_group_id = dtg.id', 'left');
        $this->db->where('pm.id', $id);
        $this->db->where('uspg.code', PaymentModeGroup::getSystemGroupCode());
        if( !$deleted )
            $this->db->where('pm.deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findAll($limit, $page)
    {
        $total = 0;
        $offset = ($page - 1) * $limit;

        $this->db->start_cache(); //to cache active record query
        $this->db->select('pm.id as payment_mode_id,
                           pm.code,
                           pm.name,
                           pm.self_service,
                           pm.need_approval,
                           pm.for_refund,
                           pm.payment_mode_group_id,
                           usp.code as payment_mode_group,
                           usp.display_name as payment_mode_group_name,
                           pm.is_payment_mode,
                           pm.is_collection_mode,
                           dt.id delivery_time_id,
                           dt.code delivery_time_code,
                           dt.display_name delivery_time_name,
                           pm.created_at,
                           pm.created_by,
                           pm.updated_at,
                           pm.updated_by,
                           pm.deleted_at,
                           pm.deleted_by');
        $this->db->from('iafb_payment.payment_mode pm');
        $this->db->join('iafb_payment.system_code usp', 'pm.payment_mode_group_id = usp.id');
        $this->db->join('iafb_payment.system_code_group uspg', 'usp.system_code_group_id = uspg.id');
        $this->db->join('iafb_payment.system_code dt', 'pm.delivery_time_id = dt.id', 'left');
        $this->db->join('iafb_payment.system_code_group dtg', 'dt.system_code_group_id = dtg.id', 'left');
        $this->db->where('uspg.code', PaymentModeGroup::getSystemGroupCode());
        $this->db->where('pm.deleted_at', NULL);
        $this->db->stop_cache();
        
        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        
        $this->db->limit($limit, $offset);
        $query = $this->db->get();
        $this->db->flush_cache();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentModeCollection(), $total);
        }

        return false;
    }

    public function findByParam(PaymentMode $paymentMode, $limit, $page)
    {
        $total = 0;
        $offset = ($page - 1) * $limit;

        $this->db->start_cache(); //to cache active record query
        $this->db->select('pm.id as payment_mode_id,
                           pm.code,
                           pm.name,
                           pm.self_service,
                           pm.need_approval,
                           pm.for_refund,
                           pm.payment_mode_group_id,
                           usp.code as payment_mode_group,
                           usp.display_name as payment_mode_group_name,
                           pm.is_payment_mode,
                           pm.is_collection_mode,
                           dt.id delivery_time_id,
                           dt.code delivery_time_code,
                           dt.display_name delivery_time_name,
                           pm.created_at,
                           pm.created_by,
                           pm.updated_at,
                           pm.updated_by,
                           pm.deleted_at,
                           pm.deleted_by');
        $this->db->from('iafb_payment.payment_mode pm');
        $this->db->join('iafb_payment.system_code usp', 'pm.payment_mode_group_id = usp.id');
        $this->db->join('iafb_payment.system_code_group uspg', 'usp.system_code_group_id = uspg.id');
        $this->db->join('iafb_payment.system_code dt', 'pm.delivery_time_id = dt.id', 'left');
        $this->db->join('iafb_payment.system_code_group dtg', 'dt.system_code_group_id = dtg.id', 'left');
        $this->db->where('uspg.code', PaymentModeGroup::getSystemGroupCode());
        $this->db->where('pm.deleted_at', NULL);

        if((bool)$paymentMode->getForRefund())
        {
            $this->db->where('pm.for_refund', $paymentMode->getForRefund());
        }
        if((bool)$paymentMode->getNeedApproval())
        {
            $this->db->where('pm.need_approval', $paymentMode->getNeedApproval());
        }
        if((bool)$paymentMode->getSelfService())
        {
            $this->db->where('pm.self_service', $paymentMode->getSelfService());
        }
        if( $paymentMode->getIsCollectionMode() != NULL)
            $this->db->where('pm.is_collection_mode', $paymentMode->getIsCollectionMode());
        if( $paymentMode->getIsPaymentMode() != NULL)
            $this->db->where('pm.is_payment_mode', $paymentMode->getIsPaymentMode());

        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit

        $this->db->limit($limit, $offset);
        $query = $this->db->get();
        $this->db->flush_cache();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentModeCollection(), $total);
        }

        return false;
    }

    public function findByFilters(PaymentModeCollection $filters)
    {
        $this->db->select('pm.id as payment_mode_id,
                           pm.code,
                           pm.name,
                           pm.self_service,
                           pm.need_approval,
                           pm.for_refund,
                           pm.payment_mode_group_id,
                           usp.code as payment_mode_group,
                           usp.display_name as payment_mode_group_name,
                           pm.is_payment_mode,
                           pm.is_collection_mode,
                           dt.id delivery_time_id,
                           dt.code delivery_time_code,
                           dt.display_name delivery_time_name,
                           pm.created_at,
                           pm.created_by,
                           pm.updated_at,
                           pm.updated_by,
                           pm.deleted_at,
                           pm.deleted_by');
        $this->db->from('iafb_payment.payment_mode pm');
        $this->db->join('iafb_payment.system_code usp', 'pm.payment_mode_group_id = usp.id');
        $this->db->join('iafb_payment.system_code_group uspg', 'usp.system_code_group_id = uspg.id');
        $this->db->join('iafb_payment.system_code dt', 'pm.delivery_time_id = dt.id', 'left');
        $this->db->join('iafb_payment.system_code_group dtg', 'dt.system_code_group_id = dtg.id', 'left');
        $this->db->where('uspg.code', PaymentModeGroup::getSystemGroupCode());
        $this->db->where('pm.deleted_at', NULL);

        $ids = array();
        $delivery_ids = array();
        $group_ids = array();
        $is_collection_modes = array();
        $is_payment_modes = array();
        $payment_codes = array();

        foreach($filters AS $filter)
        {
            if($filter instanceof PaymentMode)
            {
                if( $filter->getId() )
                    $ids[] = $filter->getId();

                if( $filter->getCode() )
                    $payment_codes[] = $filter->getCode();

                if( !is_null($filter->getIsCollectionMode()) )
                    $is_collection_modes[] = $filter->getIsCollectionMode();

                if( !is_null($filter->getIsPaymentMode()) )
                    $is_payment_modes[] = $filter->getIsPaymentMode();

                if( $filter->getDeliveryTime()->getId() )
                    $delivery_ids[] = $filter->getDeliveryTime()->getId();

                if( $filter->getPaymentModeGroup()->getId() )
                    $group_ids[] = $filter->getPaymentModeGroup()->getId();
            }
        }

        if( count($ids) > 0 )
            $this->db->where_in('pm.id', $ids);
        if( count($delivery_ids) > 0 )
            $this->db->where_in('pm.delivery_time_id', $delivery_ids);
        if( count($group_ids) > 0 )
            $this->db->where_in('pm.payment_mode_group_id', $group_ids);
        if( count($is_collection_modes) > 0 )
            $this->db->where_in('pm.is_collection_mode', $is_collection_modes);
        if( count($is_payment_modes) > 0 )
            $this->db->where_in('pm.is_payment_mode', $is_payment_modes);
        if( count($payment_codes) > 0 )
            $this->db->where_in('pm.code', $payment_codes);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentModeCollection(), $query->num_rows());
        }

        return false;
    }

    public function findByCode($code)
    {
        $this->db->select('pm.id as payment_mode_id,
                           pm.code,
                           pm.name,
                           pm.self_service,
                           pm.need_approval,
                           pm.for_refund,
                           pm.payment_mode_group_id,
                           usp.code as payment_mode_group,
                           usp.display_name as payment_mode_group_name,
                           pm.is_payment_mode,
                           pm.is_collection_mode,
                           dt.id delivery_time_id,
                           dt.code delivery_time_code,
                           dt.display_name delivery_time_name,
                           pm.created_at,
                           pm.created_by,
                           pm.updated_at,
                           pm.updated_by,
                           pm.deleted_at,
                           pm.deleted_by');
        $this->db->from('iafb_payment.payment_mode pm');
        $this->db->join('iafb_payment.system_code usp', 'pm.payment_mode_group_id = usp.id');
        $this->db->join('iafb_payment.system_code_group uspg', 'usp.system_code_group_id = uspg.id');
        $this->db->join('iafb_payment.system_code dt', 'pm.delivery_time_id = dt.id', 'left');
        $this->db->join('iafb_payment.system_code_group dtg', 'dt.system_code_group_id = dtg.id', 'left');
        $this->db->where('uspg.code', PaymentModeGroup::getSystemGroupCode());
        $this->db->where('pm.code', $code);
        $this->db->where('pm.deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->map($query->row());
        }

        return false;
    }
}