<?php

use Iapps\PaymentService\Attribute\IAttributeValueDataMapper;
use Iapps\PaymentService\Attribute\AttributeValue;
use Iapps\PaymentService\Attribute\AttributeValueCollection;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Attribute\Attribute;
use Iapps\PaymentService\Attribute\AttributeCollection;

class Attribute_value_model extends Base_Model
                            implements IAttributeValueDataMapper{

    public function map(\stdClass $data)
    {
        $entity = new AttributeValue();

        if( isset($data->attribute_value_id) )
            $entity->setId($data->attribute_value_id);

        if( isset($data->country_code) )
            $entity->setCountryCode($data->country_code);

        if( isset($data->attribute_id) )
            $entity->getAttribute()->setId($data->attribute_id);

        if( isset($data->attribute_selection_only) )
            $entity->getAttribute()->setSelectionOnly($data->attribute_selection_only);

        if( isset($data->attribute_code) )
            $entity->getAttribute()->setCode($data->attribute_code);

        if( isset($data->attribute_name) )
            $entity->getAttribute()->setName($data->attribute_name);

        if( isset($data->attribute_description) )
            $entity->getAttribute()->setDescription($data->attribute_description);

        if( isset($data->code) )
            $entity->setCode($data->code);

        if( isset($data->value) )
            $entity->setValue($data->value);

        if( isset($data->option) )
            $entity->setOption($data->option);

        if( isset($data->image_url) )
            $entity->setImageUrl($data->image_url);

        if( isset($data->created_at) )
            $entity->getCreatedAt()->setDateTimeUnix($data->created_at);

        if( isset($data->created_by) )
            $entity->setCreatedBy($data->created_by);

        if( isset($data->updated_at) )
            $entity->getUpdatedAt()->setDateTimeUnix($data->updated_at);

        if( isset($data->updated_by) )
            $entity->setUpdatedBy($data->updated_by);

        if( isset($data->deleted_at) )
            $entity->getDeletedAt()->setDateTimeUnix($data->deleted_at);

        if( isset($data->deleted_by) )
            $entity->setDeletedBy($data->deleted_by);

        return $entity;
    }

    public function findById($id, $deleted = false)
    {
        $this->db->select('v.id as attribute_value_id,
                           v.country_code,
                           v.attribute_id,
                           a.selection_only attribute_selection_only,
                           a.code attribute_code,
                           a.name attribute_name,
                           a.description attribute_description,
                           v.code,
                           v.value,
                           v.option,
                           v.image_url,
                           v.created_at,
                           v.created_by,
                           v.updated_at,
                           v.updated_by,
                           v.deleted_at,
                           v.deleted_by');
        $this->db->from('iafb_payment.attribute_value v');
        $this->db->join('iafb_payment.attribute a', 'v.attribute_id = a.id');
        if( !$deleted )
            $this->db->where('v.deleted_at', NULL);
        $this->db->where('v.id', $id);

        $query = $this->db->get();
        if( $query->num_rows () > 0 )
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByIds(array $ids)
    {
        $this->db->select('v.id as attribute_value_id,
                           v.country_code,
                           v.attribute_id,
                           a.selection_only attribute_selection_only,
                           a.code attribute_code,
                           a.name attribute_name,
                           a.description attribute_description,
                           v.code,
                           v.value,
                           v.option,
                           v.image_url,
                           v.created_at,
                           v.created_by,
                           v.updated_at,
                           v.updated_by,
                           v.deleted_at,
                           v.deleted_by');
        $this->db->from('iafb_payment.attribute_value v');
        $this->db->join('iafb_payment.attribute a', 'v.attribute_id = a.id');
        $this->db->where('v.deleted_at', NULL);
        $this->db->where_in('v.id', $ids);

        $this->db->order_by('v.value', 'asc');
        $query = $this->db->get();
        if( $query->num_rows () > 0 )
        {
            return $this->mapCollection($query->result(), new AttributeValueCollection(), $query->num_rows());
        }

        return false;
    }

    public function findAll()
    {
        $this->db->select('v.id as attribute_value_id,
                           v.country_code,
                           v.attribute_id,
                           a.selection_only attribute_selection_only,
                           a.code attribute_code,
                           a.name attribute_name,
                           a.description attribute_description,
                           v.code,
                           v.value,
                           v.option,
                           v.image_url,
                           v.created_at,
                           v.created_by,
                           v.updated_at,
                           v.updated_by,
                           v.deleted_at,
                           v.deleted_by');
        $this->db->from('iafb_payment.attribute_value v');
        $this->db->join('iafb_payment.attribute a', 'v.attribute_id = a.id');
        $this->db->where('v.deleted_at', NULL);

        $this->db->order_by('v.value', 'asc');
        $query = $this->db->get();
        if( $query->num_rows () > 0 )
        {
            return $this->mapCollection($query->result(), new AttributeValueCollection(), $query->num_rows());
        }

        return false;
    }

    public function findByAttributeId($attribute_id)
    {
        $this->db->select('v.id as attribute_value_id,
                           v.country_code,
                           v.attribute_id,
                           a.selection_only attribute_selection_only,
                           a.code attribute_code,
                           a.name attribute_name,
                           a.description attribute_description,
                           v.code,
                           v.value,
                           v.option,
                           v.image_url,
                           v.created_at,
                           v.created_by,
                           v.updated_at,
                           v.updated_by,
                           v.deleted_at,
                           v.deleted_by');
        $this->db->from('iafb_payment.attribute_value v');
        $this->db->join('iafb_payment.attribute a', 'v.attribute_id = a.id');
        $this->db->where('v.deleted_at', NULL);
        $this->db->where('v.attribute_id', $attribute_id);

        $this->db->order_by('v.value', 'asc');
        $query = $this->db->get();
        if( $query->num_rows () > 0 )
        {
            return $this->mapCollection($query->result(), new AttributeValueCollection(), $query->num_rows());
        }

        return false;
    }

    public function findByAttributeIds(array $attribute_ids)
    {
        $this->db->select('v.id as attribute_value_id,
                           v.country_code,
                           v.attribute_id,
                           a.selection_only attribute_selection_only,
                           a.code attribute_code,
                           a.name attribute_name,
                           a.description attribute_description,
                           v.code,
                           v.value,
                           v.option,
                           v.image_url,
                           v.created_at,
                           v.created_by,
                           v.updated_at,
                           v.updated_by,
                           v.deleted_at,
                           v.deleted_by');
        $this->db->from('iafb_payment.attribute_value v');
        $this->db->join('iafb_payment.attribute a', 'v.attribute_id = a.id');
        $this->db->where('v.deleted_at', NULL);
        $this->db->where_in('v.attribute_id', $attribute_ids);

        $this->db->order_by('v.value', 'asc');
        $query = $this->db->get();
        if( $query->num_rows () > 0 )
        {
            return $this->mapCollection($query->result(), new AttributeValueCollection(), $query->num_rows());
        }

        return false;
    }

    public function findByFilters(AttributeValueCollection $filters)
    {
        $this->db->select('v.id as attribute_value_id,
                           v.country_code,
                           v.attribute_id,
                           a.selection_only attribute_selection_only,
                           a.code attribute_code,
                           a.name attribute_name,
                           a.description attribute_description,
                           v.code,
                           v.value,
                           v.option,
                           v.image_url,
                           v.created_at,
                           v.created_by,
                           v.updated_at,
                           v.updated_by,
                           v.deleted_at,
                           v.deleted_by');
        $this->db->from('iafb_payment.attribute_value v');
        $this->db->join('iafb_payment.attribute a', 'v.attribute_id = a.id');
        $this->db->where('v.deleted_at', NULL);

        $attributeIds = array();
        $attributeValueCodes = array();
        $attributeValueIds = array();
        $attributeValueValues = array();

        foreach($filters AS $filter)
        {
            if($filter instanceof AttributeValue)
            {
                if( $filter->getId() )
                    $attributeValueIds[] = $filter->getId();
                if( $filter->getCode() )
                    $attributeValueCodes[] = $filter->getCode();
                if( $filter->getValue() )
                    $attributeValueValues[] = $filter->getValue();
                if( $filter->getAttribute()->getId() )
                    $attributeIds[] = $filter->getAttribute()->getId();
            }
        }

        if( count($attributeIds) > 0 )
            $this->db->where_in('v.attribute_id', $attributeIds);
        if( count($attributeValueCodes) > 0 )
            $this->db->where_in('v.code', $attributeValueCodes);
        if( count($attributeValueIds) > 0 )
            $this->db->where_in('v.id', $attributeValueIds);
        if( count($attributeValueValues) > 0 )
            $this->db->where_in('v.value', $attributeValueValues);

        $this->db->order_by('v.value', 'asc');
        $query = $this->db->get();
        if( $query->num_rows () > 0 )
        {
            return $this->mapCollection($query->result(), new AttributeValueCollection(), $query->num_rows());
        }

        return false;
    }

    public function insert(AttributeValue $attr_val)
    {
        $created_at = IappsDateTime::now();
        $this->db->set('id', $attr_val->getId());
        $this->db->set('country_code', $attr_val->getCountryCode());
        $this->db->set('attribute_id', $attr_val->getAttribute()->getId());
        $this->db->set('code', $attr_val->getCode());
        $this->db->set('value', $attr_val->getValue());
        $this->db->set('option', $attr_val->getOption());
        $this->db->set('image_url', $attr_val->getImageUrl());
        $this->db->set('created_at', $created_at->getUnix());
        $this->db->set('created_by', $attr_val->getCreatedBy());

        if( $this->db->insert('iafb_payment.attribute_value') )
        {
            $attr_val->setCreatedAt($created_at);
            return $attr_val;
        }

        return false;
    }

    public function update(AttributeValue $attr_val)
    {
        $updated_at = IappsDateTime::now();
        $this->db->set('country_code', $attr_val->getCountryCode());
        $this->db->set('value', $attr_val->getValue());
        $this->db->set('option', $attr_val->getOption());
        $this->db->set('image_url', $attr_val->getImageUrl());
        $this->db->set('updated_at', $updated_at->getUnix());
        $this->db->set('updated_by', $attr_val->getUpdatedBy());

        $this->db->where('id', $attr_val->getId());
        $this->db->update('iafb_payment.attribute_value');
        if( $this->db->affected_rows() > 0 )
        {
            $attr_val->setUpdatedAt($updated_at);
            return $attr_val;
        }

        return false;
    }
}