<?php

use Iapps\Common\AuditLog\IAuditLogMapper;
use Iapps\Common\AuditLog\AuditLog;
use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\AuditLog\AuditLogCollection;
use Iapps\Common\Core\IpAddress;
use Iapps\Common\Core\IappsDateTime;

class Audit_log_model extends Base_Model implements IAuditLogMapper{

    public function map(\stdClass $data)
    {
        $entity = new AuditLog();

        if( isset($data->audit_log_id) )
            $entity->setId($data->audit_log_id);

        if( isset($data->parent_id) )
            $entity->setParentId($data->parent_id);

        if( isset($data->table_name) )
            $entity->setTableName($data->table_name);

        if( isset($data->before_value) )
            $entity->setBeforeValue($data->before_value);

        if( isset($data->after_value) )
            $entity->setAfterValue($data->after_value);

        if( isset($data->header_id) )
            $entity->setHeaderId($data->header_id);

        if( isset($data->action_type) )
            $entity->setType($data->action_type);

        if( isset($data->ip_address) )
            $entity->setIpAddress(IpAddress::fromInt($data->ip_address));

        if( isset($data->modified_at) )
            $entity->setModifiedAt(IappsDateTime::fromUnix($data->modified_at));

        if( isset($data->modified_by) )
            $entity->setModifiedBy($data->modified_by);

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
        $this->db->select('id as audit_log_id,
                           parent_id,
                           table_name,
                           before_value,
                           after_value,
                           header_id,
                           action_type,
                           ip_address,
                           ');
        $this->db->from('iafb_payment.audit_log');
        $this->db->where('id', $id);

        $query = $this->db->get();
        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByTableName($tableName, $limit, $page)
    {
        $offset = ($page - 1) * $limit;
        $this->db->start_cache(); //to cache active record query
        $this->db->select('id as audit_log_id,
                           parent_id,
                           table_name,
                           before_value,
                           after_value,
                           header_id,
                           action_type,
                           ip_address,
                           modified_at,
                           modified_by,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by');
        $this->db->from('iafb_payment.audit_log');
        $this->db->where('table_name', $tableName);
        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        $this->db->limit($limit, $offset);

        $query = $this->db->get();
        $this->db->flush_cache();
        if($query->num_rows() >  0)
        {
            return $this->mapCollection($query->result(), new AuditLogCollection(), $total);
        }

        return false;
    }

    public function findAll($limit, $page)
    {
        $offset = ($page - 1) * $limit;
        $this->db->start_cache(); //to cache active record query
        $this->db->select('id as audit_log_id,
                           parent_id,
                           table_name,
                           before_value,
                           after_value,
                           header_id,
                           action_type,
                           ip_address,
                           modified_at,
                           modified_by,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by');
        $this->db->from('iafb_payment.audit_log');
        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        $this->db->limit($limit, $offset);

        $query = $this->db->get();
        $this->db->flush_cache();

        if($query->num_rows() >  0)
        {
            return $this->mapCollection($query->result(), new AuditLogCollection(), $total);
        }

        return false;
    }

    public function findByTableNameId($tableName, $id, $limit = 10, $page = 1)
    {
        $offset = ($page - 1) * $limit;
        $this->db->start_cache(); //to cache active record query
        $this->db->select('id as audit_log_id,
                           parent_id,
                           table_name,
                           before_value,
                           after_value,
                           header_id,
                           action_type,
                           ip_address,
                           modified_at,
                           modified_by,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by');
        $this->db->from('iafb_payment.audit_log');
        $this->db->where('table_name', $tableName);
        $this->db->where('parent_id', $id);
        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        $this->db->limit($limit, $offset);

        $query = $this->db->get();
        $this->db->flush_cache();
        if($query->num_rows() >  0)
        {
            return $this->mapCollection($query->result(), new AuditLogCollection(), $total);
        }

        return false;
    }

    public function findByTableNameAndHeaderId($tableName, $id)
    {
        $this->db->select('id as audit_log_id,
                           parent_id,
                           table_name,
                           before_value,
                           after_value,
                           header_id,
                           action_type,
                           ip_address,
                           modified_at,
                           modified_by,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by');
        $this->db->from('iafb_payment.audit_log');
        $this->db->where('table_name', $tableName);
        $this->db->where('header_id', $id);

        $query = $this->db->get();
        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function save(AuditLog $log)
    {
        $this->db->set('id', $log->getId());
        $this->db->set('parent_id', $log->getParentId());
        $this->db->set('table_name', $log->getTableName());
        $this->db->set('before_value', $log->getBeforeValue());
        $this->db->set('after_value', $log->getAfterValue());
        $this->db->set('header_id', $log->getHeaderId());
        $this->db->set('action_type', $log->getType());
        $this->db->set('ip_address', $log->getIpAddress()->getInteger());
        $this->db->set('modified_at', $log->getModifiedAt()->getUnix());
        $this->db->set('modified_by', $log->getModifiedBy());
        $this->db->set('created_at', IappsDateTime::now()->getUnix());
        $this->db->set('created_by', $log->getCreatedBy());

        $this->db->insert('iafb_payment.audit_log');

        if( $this->db->affected_rows() > 0 )
        {
            return true;
        }

        return false;
    }
}