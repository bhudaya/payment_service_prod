<?php

use Iapps\Common\CoreConfigData\ICoreConfigDataMapper;
use Iapps\Common\CoreConfigData\CoreConfigData;
use Iapps\Common\Core\IappsDateTime;

class Core_config_data_model extends Base_Model
                             implements ICoreConfigDataMapper{

    public function map(\stdClass $data)
    {
        $entity = new CoreConfigData();

        if( isset($data->core_config_data_id))
            $entity->setId($data->core_config_data_id);

        if( isset($data->unique_code))
            $entity->setUniqueCode($data->unique_code);

        if( isset($data->value))
            $entity->setValue($data->value);

        if( isset($data->description))
            $entity->setDescription($data->description);

        if( isset($data->created_at) )
            $entity->setUpdatedAt(IappsDateTime::fromUnix($data->created_at));

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
        $this->db->select('id as core_config_data_id,
                               unique_code,
                               value,
                               description');
        $this->db->from('iafb_payment.core_config_data');
        if( !$deleted )
            $this->db->where('deleted_at', NULL);
        $this->db->where('id', $id);

        $query = $this->db->get();
        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByCode($code)
    {
        $this->db->select('id as core_config_data_id,
                               unique_code,
                               value,
                               description');
        $this->db->from('iafb_payment.core_config_data');
        $this->db->where('deleted_at', NULL);
        $this->db->where('unique_code', $code);

        $query = $this->db->get();
        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }

        return false;
    }
}