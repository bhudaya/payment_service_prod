<?php

use Iapps\PaymentService\PaymentMode\IPaymentModeLocationDataMapper;
use Iapps\PaymentService\PaymentMode\PaymentModeLocation;
use Iapps\PaymentService\PaymentMode\PaymentModeLocationCollection;
use Iapps\Common\Core\IappsDateTime;

class payment_mode_location_model extends Base_Model implements IPaymentModeLocationDataMapper{

    public function map(stdClass $data)
    {
        $entity = new PaymentModeLocation();

        if( isset($data->payment_mode_location_id) )
            $entity->setId($data->payment_mode_location_id);

        if( isset($data->payment_code) )
            $entity->setPaymentCode($data->payment_code);

        if( isset($data->address) )
            $entity->setAddress($data->address);

        if( isset($data->postal_code) )
            $entity->setPostalCode($data->postal_code);

        if( isset($data->latitude) )
            $entity->setLatitude($data->latitude);

        if( isset($data->longitude) )
            $entity->setLongitude($data->longitude);

        if( isset($data->operating_hours) )
            $entity->setOperatingHours($data->operating_hours);

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
        $this->db->select('pml.id as payment_mode_location_id,
                           pml.payment_code,
                           pml.address,
                           pml.postal_code,
                           pml.latitude,
                           pml.longitude,
                           pml.operating_hours,
                           pml.created_at,
                           pml.created_by,
                           pml.updated_at,
                           pml.updated_by,
                           pml.deleted_at,
                           pml.deleted_by');
        $this->db->from('iafb_payment.payment_mode_location pml');
        $this->db->where('pml.id', $id);
        if( !$deleted )
            $this->db->where('pml.deleted_at', NULL);

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
        $this->db->select('pml.id as payment_mode_location_id,
                           pml.payment_code,
                           pml.address,
                           pml.postal_code,
                           pml.latitude,
                           pml.longitude,
                           pml.operating_hours,
                           pml.created_at,
                           pml.created_by,
                           pml.updated_at,
                           pml.updated_by,
                           pml.deleted_at,
                           pml.deleted_by');
        $this->db->from('iafb_payment.payment_mode_location pml');
        $this->db->where('pml.deleted_at', NULL);
        $this->db->stop_cache();
        
        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        
        $this->db->limit($limit, $offset);
        $query = $this->db->get();
        $this->db->flush_cache();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentModeLocationCollection(), $total);
        }

        return false;
    }

    public function findByParam(PaymentModeLocation $paymentModeLocation, $limit, $page)
    {
        $total = 0;
        $offset = ($page - 1) * $limit;

        $this->db->start_cache(); //to cache active record query
        $this->db->select('pml.id as payment_mode_location_id,
                           pml.payment_code,
                           pml.address,
                           pml.postal_code,
                           pml.latitude,
                           pml.longitude,
                           pml.operating_hours,
                           pml.created_at,
                           pml.created_by,
                           pml.updated_at,
                           pml.updated_by,
                           pml.deleted_at,
                           pml.deleted_by');
        $this->db->from('iafb_payment.payment_mode_location pml');
        $this->db->where('pml.deleted_at', NULL);

        if( $paymentModeLocation->getPaymentCode() != NULL)
            $this->db->where('pml.payment_code', $paymentModeLocation->getPaymentCode());
        
        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit

        $this->db->limit($limit, $offset);
        $query = $this->db->get();
        $this->db->flush_cache();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentModeLocationCollection(), $total);
        }

        return false;
    }

}