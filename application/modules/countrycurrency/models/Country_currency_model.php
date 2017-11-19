<?php

use Iapps\PaymentService\CountryCurrency\ICountryCurrencyDataMapper;
use Iapps\PaymentService\CountryCurrency\CountryCurrency;
use Iapps\PaymentService\CountryCurrency\CountryCurrencyCollection;
use Iapps\Common\Core\IappsDateTime;

class Country_currency_model extends Base_Model implements ICountryCurrencyDataMapper{

    public function map(stdClass $data)
    {
        $entity = new CountryCurrency();
        if( isset($data->country_currency_id) )
            $entity->setId($data->country_currency_id);

        if( isset($data->code) )
            $entity->setCode($data->code);

        if( isset($data->country_code) )
            $entity->setCountryCode($data->country_code);

        if( isset($data->currency_code) )
            $entity->setCurrencyCode($data->currency_code);

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
        $this->db->select('id as country_currency_id,
                           code,
                           country_code,
                           currency_code,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.country_currency');
        $this->db->where('id', $id);
        if( !$deleted )
            $this->db->where('deleted_at', NULL);

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
        $this->db->select('id as country_currency_id,
                           code,
                           country_code,
                           currency_code,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.country_currency');
        $this->db->where('deleted_at', NULL);
        $this->db->stop_cache();
        
        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        
        $this->db->limit($limit, $offset);
        $query = $this->db->get();
        $this->db->flush_cache();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new CountryCurrencyCollection(), $total);
        }

        return false;
    }

    public function findByCode($code)
    {
        $this->db->select('id as country_currency_id,
                           code,
                           country_code,
                           currency_code,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.country_currency');
        $this->db->where('code', $code);
        $this->db->where('deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByCountryCode($country_code)
    {
        $this->db->select('id as country_currency_id,
                           code,
                           country_code,
                           currency_code,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.country_currency');
        $this->db->where('country_code', $country_code);
        $this->db->where('deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new CountryCurrencyCollection(), 0);
        }

        return false;
    }

    public function add(CountryCurrency $country_currency)
    {
        $this->db->set('id', $country_currency->getId());
        $this->db->set('code', $country_currency->getCode());
        $this->db->set('country_code', $country_currency->getCountryCode());
        $this->db->set('currency_code', $country_currency->getCurrencyCode());
        $this->db->set('created_at', IappsDateTime::now()->getUnix());
        $this->db->set('created_by', $country_currency->getCreatedBy());

        if( $this->db->insert('iafb_payment.country_currency') )
        {
            return true;
        }

        return false;
    }
}