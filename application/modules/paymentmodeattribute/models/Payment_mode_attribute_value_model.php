<?php

use Iapps\PaymentService\PaymentModeAttribute\IPaymentModeAttributeValueDataMapper;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeValue;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeValueCollection;
use Iapps\Common\Core\IappsDateTime;

class Payment_mode_attribute_value_model extends Base_Model
                                         implements IPaymentModeAttributeValueDataMapper{

    public function map(\stdClass $data)
    {
        $entity = new PaymentModeAttributeValue();

        if( isset($data->payment_mode_attribute_value_id) )
            $entity->setId($data->payment_mode_attribute_value_id);

        if( isset($data->payment_mode_attribute_id) )
            $entity->getPaymentModeAttribute()->setId($data->payment_mode_attribute_id);

        if( isset($data->attribute_value_id) )
            $entity->getAttributeValue()->setId($data->attribute_value_id);

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
        $this->db->select('id as payment_mode_attribute_value_id,
                           payment_mode_attribute_id,
                           attribute_value_id,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.payment_mode_attribute_value');
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

    public function findByFilters(PaymentModeAttributeValueCollection $filters)
    {
        $this->db->select('id as payment_mode_attribute_value_id,
                           payment_mode_attribute_id,
                           attribute_value_id,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.payment_mode_attribute_value');
        $this->db->where('deleted_at', NULL);

        $this->db->group_start();
        foreach($filters AS $filter)
        {
            if($filter instanceof PaymentModeAttributeValue)
            {
                $this->db->or_group_start();

                if( $filter->getId() )
                    $this->db->where('id',  $filter->getId());

                if( $filter->getPaymentModeAttribute()->getId() )
                    $this->db->where('payment_mode_attribute_id',  $filter->getPaymentModeAttribute()->getId());

                if( $filter->getAttributeValue()->getId() )
                    $this->db->where('attribute_value_id',  $filter->getAttributeValue()->getId());

                $this->db->group_end();
            }
        }
        $this->db->group_end();

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentModeAttributeValueCollection(), $query->num_rows());
        }

        return false;
    }
}