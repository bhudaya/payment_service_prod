<?php

use Iapps\PaymentService\CodeMapper\ICodeMapperDataMapper;
use Iapps\PaymentService\CodeMapper\CodeMapper;
use Iapps\PaymentService\CodeMapper\CodeMapperCollection;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\CodeMapper\CodeMapperType;

class Code_mapper_model extends Base_Model
    implements ICodeMapperDataMapper{

    public function map(\stdClass $data)
    {
        $entity = new CodeMapper();

        if( isset($data->code_mapper_id) )
            $entity->setId($data->code_mapper_id);

        if( isset($data->type_id) )
            $entity->getType()->setId($data->type_id);

        if( isset($data->type_code) )
            $entity->getType()->setCode($data->type_code);

        if( isset($data->type_name) )
            $entity->getType()->setDisplayName($data->type_name);

        if( isset($data->reference_value) )
            $entity->setReferenceValue($data->reference_value);

        if( isset($data->mapped_value) )
            $entity->setMappedValue($data->mapped_value);

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
        $this->db->select("c.id as code_mapper_id,
                           type.id as type_id,
                           type.code as type_code,
                           type.display_name as type_name,
                           c.reference_value,
                           c.mapped_value,
                           c.created_at,
                           c.created_by,
                           c.updated_at,
                           c.updated_by,
                           c.deleted_at,
                           c.deleted_by");
        $this->db->from('iafb_payment.code_mapper c');
        $this->db->join('iafb_payment.system_code type', 'c.type_id = type.id');
        $this->db->join('iafb_payment.system_code_group type_group', 'type.system_code_group_id = type_group.id');

        if( !$deleted )
            $this->db->where('c.deleted_at', NULL);
        $this->db->where('id', $id);
        $this->db->where('type_group.code', CodeMapperType::getSystemGroupCode());

        $query = $this->db->get();
        if( $query->num_rows() > 0 )
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByFilters(CodeMapperCollection $filters)
    {
        $this->db->select("c.id as code_mapper_id,
                           type.id as type_id,
                           type.code as type_code,
                           type.display_name as type_name,
                           c.reference_value,
                           c.mapped_value,
                           c.created_at,
                           c.created_by,
                           c.updated_at,
                           c.updated_by,
                           c.deleted_at,
                           c.deleted_by");
        $this->db->from('iafb_payment.code_mapper c');
        $this->db->join('iafb_payment.system_code type', 'c.type_id = type.id');
        $this->db->join('iafb_payment.system_code_group type_group', 'type.system_code_group_id = type_group.id');

        $this->db->where('c.deleted_at', NULL);
        $this->db->where('type_group.code', CodeMapperType::getSystemGroupCode());

        $ids = array();
        $reference_values = array();
        $type_ids = array();
        $type_codes = array();
        $mapped_values = array();

        foreach($filters AS $filter)
        {
            if($filter instanceof CodeMapper)
            {
                if( $filter->getId() )
                    $ids[] = $filter->getId();

                if( $filter->getReferenceValue() )
                    $reference_values[] = $filter->getReferenceValue();

                if( $filter->getType()->getId() )
                    $type_ids[] = $filter->getType()->getId();

                if( $filter->getMappedValue() )
                    $mapped_values[] = $filter->getMappedValue();

                if( $filter->getType()->getCode() )
                    $type_codes[] = $filter->getType()->getCode();
            }
        }

        if( count($ids) > 0 )
            $this->db->where_in('c.id', $ids);
        if( count($reference_values) > 0 )
            $this->db->where_in('c.reference_value', $reference_values);
        if( count($type_ids) > 0 )
            $this->db->where_in('c.type_id', $type_ids);
        if( count($type_codes) > 0 )
            $this->db->where_in('type.code', $type_codes);
        if( count($mapped_values) > 0 )
            $this->db->where_in('c.mapped_value', $mapped_values);

        $query = $this->db->get();
        if( $query->num_rows() > 0 )
        {
            return $this->mapCollection($query->result(), new CodeMapperCollection(), $query->num_rows());
        }

        return false;
    }
}