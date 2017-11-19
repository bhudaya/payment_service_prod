<?php

use Iapps\PaymentService\CountryCurrencyPaymentMode\ICountryCurrencyPaymentModeDataMapper;
use Iapps\PaymentService\CountryCurrencyPaymentMode\CountryCurrencyPaymentMode;
use Iapps\PaymentService\CountryCurrencyPaymentMode\CountryCurrencyPaymentModeCollection;
use Iapps\Common\Core\IappsDateTime;

class country_currency_payment_mode_model extends Base_Model implements ICountryCurrencyPaymentModeDataMapper{

    public function map(stdClass $data)
    {
        $entity = new CountryCurrencyPaymentMode();
        if( isset($data->country_currency_payment_mode_id) )
            $entity->setId($data->country_currency_payment_mode_id);

        if( isset($data->country_code) )
            $entity->setCountryCode($data->country_code);

        if( isset($data->country_currency_code) )
            $entity->setCountryCurrencyCode($data->country_currency_code);

        if( isset($data->payment_mode_code) )
            $entity->setPaymentModeCode($data->payment_mode_code);

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

        if( isset($data->currency_code) )
            $entity->setCurrencyCode($data->currency_code);
        return $entity;
    }

    public function findById($id, $deleted = false)
    {
        $this->db->select('id as country_currency_payment_mode_id,
                           country_code,
                           country_currency_code,
                           payment_mode_code,
                           effective_at,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.country_currency_payment_mode');
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
        $this->db->select('id as country_currency_payment_mode_id,
                           country_code,
                           country_currency_code,
                           payment_mode_code,
                           effective_at,
                           created_at,
                           created_by,
                           updated_at,
                           updated_by,
                           deleted_at,
                           deleted_by');
        $this->db->from('iafb_payment.country_currency_payment_mode');
        $this->db->where('deleted_at', NULL);
        $this->db->stop_cache();
        
        $total = $this->db->count_all_results(); //to get total num of result w/o limit
        
        $this->db->limit($limit, $offset);
        $query = $this->db->get();
        $this->db->flush_cache();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new CountryCurrencyPaymentModeCollection(), $total);
        }

        return false;
    }

    public function findByCountryCode($country_code)
    {
        $this->db->select('ccpm.id as country_currency_payment_mode_id,
                           ccpm.country_code,
                           ccpm.country_currency_code,
                           ccpm.payment_mode_code,
                           ccpm.effective_at,
                           ccpm.created_at,
                           ccpm.created_by,
                           ccpm.updated_at,
                           ccpm.updated_by,
                           ccpm.deleted_at,
                           ccpm.deleted_by,
                           cc.currency_code');
        $this->db->from('iafb_payment.country_currency_payment_mode AS ccpm');
        $this->db->join('iafb_payment.country_currency AS cc', '.ccpm.country_currency_code = cc.code');
        $this->db->where('ccpm.country_code', $country_code);
        $this->db->where('ccpm.deleted_at', NULL);
        $this->db->where('cc.deleted_at', NULL);

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new CountryCurrencyPaymentModeCollection(), 0);
        }

        return false;
    }

    public function findExistingPaymentMode($country_currency_code, $payment_mode_array)
    {
        $this->db->select('payment_mode_code');
        $this->db->from('iafb_payment.country_currency_payment_mode');
        $this->db->where('country_currency_code', $country_currency_code);
        $this->db->where_in('payment_mode_code', $payment_mode_array);
        $this->db->where('deleted_at', NULL);
        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $query->result_array();
        }

        return false;
    }

    public function add(CountryCurrencyPaymentMode $country_currency_payment_mode)
    {
        $this->db->set('id', $country_currency_payment_mode->getId());
        $this->db->set('country_code', $country_currency_payment_mode->getCountryCode());
        $this->db->set('country_currency_code', $country_currency_payment_mode->getCountryCurrencyCode());
        $this->db->set('payment_mode_code', $country_currency_payment_mode->getPaymentModeCode());
        $this->db->set('effective_at', $country_currency_payment_mode->getEffectiveAt()->getUnix());
        $this->db->set('created_at', IappsDateTime::now()->getUnix());
        $this->db->set('created_by', $country_currency_payment_mode->getCreatedBy());

        if( $this->db->insert('iafb_payment.country_currency_payment_mode') )
        {
            return true;
        }

        return false;
    }

    public function addBatch(CountryCurrencyPaymentModeCollection $country_currency_payment_mode_coll)
    {
        $data_to_be_insert = array();
        foreach ($country_currency_payment_mode_coll as $country_currency_payment_mode) 
        {
            $data_to_be_insert[] = array(
              'id' => $country_currency_payment_mode->getId(),
              'country_code' => $country_currency_payment_mode->getCountryCode(),
              'country_currency_code' => $country_currency_payment_mode->getCountryCurrencyCode(),
              'payment_mode_code' => $country_currency_payment_mode->getPaymentModeCode(),
              'effective_at' => $country_currency_payment_mode->getEffectiveAt()->getUnix(),
              'created_at' => IappsDateTime::now()->getUnix(),
              'created_by' => $country_currency_payment_mode->getCreatedBy()
            );
        };

        if($this->db->insert_batch('iafb_payment.country_currency_payment_mode', $data_to_be_insert))
        {
            return true;
        }

        return false;
    }

    public function removeBatch($country_currency_code, $payment_mode_array_to_be_deleted, $updated_by)
    {
        $data_delete = array(
           'deleted_at' => IappsDateTime::now()->getUnix(),
           'deleted_timestamp' => IappsDateTime::now()->getUnix(),
           'deleted_by' => $updated_by
        );
        $this->db->where('country_currency_code', $country_currency_code);
        $this->db->where_in('payment_mode_code', $payment_mode_array_to_be_deleted);
        $this->db->where('deleted_at', NULL);
        if($this->db->update('iafb_payment.country_currency_payment_mode', $data_delete))
        {
            return true;
        }

        return false;
    }
}