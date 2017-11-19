<?php

use Iapps\PaymentService\SwitcherMessage\SwitcherMessage;
use Iapps\PaymentService\SwitcherMessage\ISwitcherMessageMapper;
use Iapps\Common\Core\Language;


class Switcher_message_model extends Base_Model
                       implements ISwitcherMessageMapper{




    public function map(\stdClass $data)
    {
        $obj = new SwitcherMessage();

        $obj->setId($data->switcher_message_id);
        if( isset($data->country_language_code) )
        {
            $lang = new Language();
            $lang->setCode($data->country_language_code);
            $obj->setLang($lang);
        }
        $obj->setCode($data->code);
        $obj->setMessage($data->message);

        return $obj;
    }

    public function findById($id, $deleted = false)
    {
        $this->db->select('id as switcher_message_id,
                           lang,
                           code,
                           switcher_code,
                           message');
        $this->db->from('iafb_payment.switcher_message');
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


    public function findByParam(SwitcherMessage $obj)
    {
        $this->db->select('id as switcher_message_id,
                           lang,
                           code,
                           switcher_code,
                           message');
        $this->db->from('iafb_payment.switcher_message');

        if($obj->getCode() !== NULL)
            $this->db->where('code', $obj->getCode());

        if( $obj->getLang())
            $this->db->where('lang', $obj->getLang());

        if( $obj->getSwitcherCode())
            $this->db->where('switcher_code', $obj->getSwitcherCode());



        $query = $this->db->get(); 
        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }
        return false;
    }


    public function findListByParam(SwitcherMessage $obj)
    {
        $this->db->select('id as switcher_message_id,
                           lang,
                           code,
                           switcher_code,
                           message');
        $this->db->from('iafb_payment.switcher_message');
        

        $query = $this->db->get();
        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }

        return false;
    }


    public function findMessageByCodeArr(Array $codeArr, SwitcherMessage $obj)
    {
        $this->db->select('id as switcher_message_id,
                           lang,
                           code,
                           switcher_code,
                           message');
        $this->db->from('iafb_payment.switcher_message');
        
        $query = $this->db->get();
        if($query->num_rows() >  0)
        {
            return $this->map($query->row());
        }

        return false;
    }


   



    
}
