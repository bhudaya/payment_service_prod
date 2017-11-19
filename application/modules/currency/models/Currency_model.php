<?php

use Iapps\PaymentService\Currency\ICurrencyDataMapper;
use Iapps\PaymentService\Currency\Currency;
use Iapps\PaymentService\Currency\CurrencyCollection;
use Iapps\Common\Core\IappsDateTime;

class currency_model extends Base_Model implements ICurrencyDataMapper{

    public function map(stdClass $data)
    {
        $entity = new Currency();
        if( isset($data->currency_id) )
            $entity->setId($data->currency_id);

        if( isset($data->code) )
            $entity->setCode($data->code);

        if( isset($data->name) )
            $entity->setName($data->name);

        if( isset($data->symbol) )
            $entity->setSymbol($data->symbol);

        if( isset($data->denomination) )
            $entity->setDenomination($data->denomination);

        if( isset($data->effective_at) )
            $entity->setEffectiveAt(IappsDateTime::fromUnix($data->effective_at));

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
        $this->db->select('id as currency_id,
                           code,
                           name,
                           symbol,
                           denomination,
                           effective_at,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.currency');
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
        $this->db->select('id as currency_id,
                           code,
                           name,
                           symbol,
                           denomination,
                           effective_at,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.currency');
        $this->db->where('deleted_at', NULL);
        $this->db->stop_cache();
        
        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        
        $this->db->limit($limit, $offset);
        $query = $this->db->get();
        $this->db->flush_cache();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new CurrencyCollection(), $total);
        }

        return false;
    }

    public function findByCode($code)
    {
        $this->db->select('id as currency_id,
                           code,
                           name,
                           symbol,
                           denomination,
                           effective_at,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.currency');
        $this->db->where('code', $code);
        $this->db->where('deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByCodes(array $codes)
    {
        $this->db->select('id as currency_id,
                           code,
                           name,
                           symbol,
                           denomination,
                           effective_at,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.currency');
        $this->db->where_in('code', $codes);
        $this->db->where('deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new CurrencyCollection(), $query->num_rows());
        }

        return false;
    }

    public function add(Currency $currency)
    {
        $this->db->set('id', $currency->getId());
        $this->db->set('code', $currency->getCode());
        $this->db->set('name', $currency->getName());
        $this->db->set('symbol', $currency->getSymbol());
        $this->db->set('denomination', $currency->getDenomination());
        $this->db->set('effective_at', $currency->getEffectiveAt()->getUnix());
        $this->db->set('created_at', IappsDateTime::now()->getUnix());
        $this->db->set('created_by', $currency->getCreatedBy());

        if( $this->db->insert('iafb_payment.currency') )
        {
            return true;
        }

        return false;
    }

    public function update(Currency $currency)
    {
        $this->db->set('code', $currency->getCode());
        $this->db->set('name', $currency->getName());
        $this->db->set('symbol', $currency->getSymbol());
        $this->db->set('denomination', $currency->getDenomination());
        $this->db->set('effective_at', $currency->getEffectiveAt()->getUnix());
        $this->db->set('updated_at', IappsDateTime::now()->getUnix());
        $this->db->set('updated_by', $currency->getUpdatedBy());
        $this->db->where('id', $currency->getId());

        if( $this->db->update('iafb_payment.currency') )
        {
            return true;
        }

        return false;
    }

    public function findByCodeOrName($search_value, $limit, $page)
    {
        $total = 0;
        $offset = ($page - 1) * $limit;

        $this->db->start_cache(); //to cache active record query
        $this->db->select('id as currency_id,
                           code,
                           name,
                           symbol,
                           denomination,
                           effective_at,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.currency');
        $this->db->like('code', $search_value);
        $this->db->or_like('name', $search_value); 
        $this->db->where('deleted_at', NULL);
        $this->db->stop_cache();
        
        $total = $this->db->count_all_results(); //to get total num of result w/o limit

        $this->db->limit($limit, $offset);
        $query = $this->db->get();
        $this->db->flush_cache();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new CurrencyCollection(), $total);
        }

        return false;
    }
}