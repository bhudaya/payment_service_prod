<?php

use Iapps\PaymentService\PaymentModeAttribute\IPaymentModeAttributeDataMapper;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttribute;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeCollection;

use Iapps\Common\Core\IappsDateTime;

class Payment_mode_attribute_model extends Base_Model
                                   implements IPaymentModeAttributeDataMapper{

    public function map(stdClass $data)
    {
        $entity = new PaymentModeAttribute();

        if( isset($data->payment_mode_attribute_id) )
            $entity->setId($data->payment_mode_attribute_id);

        if( isset($data->payment_code) )
            $entity->setPaymentCode($data->payment_code);

        if( isset($data->attribute_id) )
            $entity->getAttribute()->setId($data->attribute_id);

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
        $this->db->select('id as payment_mode_attribute_id,
                           payment_code,
                           attribute_id,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.payment_mode_attribute');
        if( !$deleted )
            $this->db->where('deleted_at', NULL);

        $this->db->where('id', $id);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByFilters(PaymentModeAttributeCollection $filters)
    {
        $this->db->select('id as payment_mode_attribute_id,
                           payment_code,
                           attribute_id,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.payment_mode_attribute');
        $this->db->where('deleted_at', NULL);

        $this->db->group_start();
        foreach($filters AS $filter)
        {
            if($filter instanceof PaymentModeAttribute)
            {
                $this->db->or_group_start();

                if( $filter->getId() )
                    $this->db->where('id',  $filter->getId());

                if( $filter->getPaymentCode() )
                    $this->db->where('payment_code',  $filter->getPaymentCode());

                if( $filter->getAttribute()->getId() )
                    $this->db->where('attribute_id',  $filter->getAttribute()->getId());

                $this->db->group_end();
            }
        }
        $this->db->group_end();

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentModeAttributeCollection(), $query->num_rows());
        }

        return false;
    }
}
