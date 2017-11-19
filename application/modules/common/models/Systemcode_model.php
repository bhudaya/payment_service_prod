<?php

use Iapps\Common\SystemCode\SystemCode;
use Iapps\Common\SystemCode\SystemCodeCollection;
use Iapps\Common\SystemCode\SystemCodeGroup;
use Iapps\Common\SystemCode\ISystemCodeMapperV2;

class Systemcode_model extends Base_Model
                       implements ISystemCodeMapperV2{

    public function map(\stdClass $data)
    {
        $entity = new SystemCode();

        if( isset($data->system_code_id) )
            $entity->setId($data->system_code_id);

        if( isset($data->code) )
            $entity->setCode($data->code);

        if( isset($data->display_name) )
            $entity->setDisplayName($data->display_name);

        if( isset($data->description) )
            $entity->setDescription($data->description);

        $obj_group = new SystemCodeGroup();
        if( isset($data->system_code_group_id) )
            $obj_group->setId($data->system_code_group_id);

        if( isset($data->group_code) )
            $obj_group->setCode($data->group_code);

        if( isset($data->group_display_name) )
            $obj_group->setDisplayName($data->group_display_name);

        if( isset($data->group_description) )
            $obj_group->setDescription($data->group_description);

        $entity->setGroup($obj_group);

        return $entity;
    }

    public function findById($id, $deleted = false)
    {
        $this->db->select('sc.id as system_code_id,
                           sc.code,
                           sc.display_name,
                           sc.description,
                           sg.id as system_code_group_id,
                           sg.code as group_code,
                           sg.display_name as group_display_name,
                           sg.description as group_description');
        $this->db->from('iafb_payment.system_code sc');
        $this->db->join('iafb_payment.system_code_group sg', 'sc.system_code_group_id = sg.id');
        if( !$deleted )
        {
            $this->db->where('sc.deleted_at', NULL);
            $this->db->where('sg.deleted_at', NULL);
        }
        $this->db->where('sc.id', $id);

        $query = $this->db->get();
        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByCode($code, $code_group)
    {
        $this->db->select('sc.id as system_code_id,
                           sc.code,
                           sc.display_name,
                           sc.description,
                           sg.id as system_code_group_id,
                           sg.code as group_code,
                           sg.display_name as group_display_name,
                           sg.description as group_description');
        $this->db->from('iafb_payment.system_code sc');
        $this->db->join('iafb_payment.system_code_group sg', 'sc.system_code_group_id = sg.id');
        $this->db->where('sc.deleted_at', NULL);
        $this->db->where('sg.deleted_at', NULL);
        $this->db->where('sc.code', $code);
        $this->db->where('sg.code', $code_group);

        $query = $this->db->get();
        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findBySystemCodeGroupCode($code)
    {
        $this->db->select('sc.id as system_code_id,
                           sc.code,
                           sc.display_name,
                           sc.description,
                           sg.id as system_code_group_id,
                           sg.code as group_code,
                           sg.display_name as group_display_name,
                           sg.description as group_description');
        $this->db->from('iafb_payment.system_code sc');
        $this->db->join('iafb_payment.system_code_group sg', 'sc.system_code_group_id = sg.id');
        $this->db->where('sc.deleted_at', NULL);
        $this->db->where('sg.deleted_at', NULL);
        $this->db->where('sg.code', $code);

        $query = $this->db->get();
        if($query->num_rows() >  0)
        {
            return $this->mapCollection($query->result(), new SystemCodeCollection(), $query->num_rows());
        }

        return false;
    }
    
    
    /*
     * @access public
     * @param string code
     * @usage get the system code
     * data basd from the given code
     * string param
     */
    public function getSystemCodeByCode($code)
    {
         $this->db->select('sc.id as system_code_id,
                           sc.code,
                           sc.display_name,
                           sc.description');
        $this->db->from('iafb_payment.system_code sc');
        $this->db->where('sc.code',$code);
        
        $query = $this->db->get();

        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }

        return false;    
   
    }    
}
