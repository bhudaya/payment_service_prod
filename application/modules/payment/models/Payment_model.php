<?php

use Iapps\PaymentService\Payment\IPaymentDataMapper;
use Iapps\PaymentService\Payment\Payment;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Payment\PaymentStatus;
use Iapps\PaymentService\Payment\PaymentCollection;
use Iapps\PaymentService\Common\ChannelType;


class Payment_model extends Base_Model
                    implements IPaymentDataMapper{

    public function map(stdClass $data)
    {
        $entity = new Payment();

        if( isset($data->payment_id) )
            $entity->setId($data->payment_id);

        if( isset($data->country_code) )
            $entity->setCountryCode($data->country_code);

        if( isset($data->module_code) )
            $entity->setModuleCode($data->module_code);

        if( isset($data->channelID))
            $entity->setChannelID($data->channelID);
        
        if( isset($data->transactionID) )
            $entity->setTransactionID($data->transactionID);

        if( isset($data->user_profile_id) )
            $entity->setUserProfileId($data->user_profile_id);

        if( isset($data->country_currency_code) )
            $entity->setCountryCurrencyCode($data->country_currency_code);

        if( isset($data->amount) )
            $entity->setAmount($data->amount);

        if( isset($data->status_id) )
            $entity->getStatus()->setId($data->status_id);

        if( isset($data->status_code) )
            $entity->getStatus()->setCode($data->status_code);

        if( isset($data->status_name) )
            $entity->getStatus()->setDisplayName($data->status_name);

        if( isset($data->status_group_id) )
            $entity->getStatus()->getGroup()->setId($data->status_group_id);

        if( isset($data->status_group_code) )
            $entity->getStatus()->getGroup()->setCode($data->status_group_code);

        if( isset($data->status_group_name) )
            $entity->getStatus()->getGroup()->setDisplayName($data->status_group_name);

        if( isset($data->payment_code) )
            $entity->setPaymentCode($data->payment_code);

        if( isset($data->ewallet_id) )
            $entity->setEwalletId($data->ewallet_id);

        if( isset($data->receipt_url) )
            $entity->setReceiptUrl($data->receipt_url);

        if( isset($data->payment_request_id) )
            $entity->setPaymentRequestId($data->payment_request_id);

        if( isset($data->description1) )
            $entity->getDescription1()->setEncryptedValue($data->description1);

        if( isset($data->description2) )
            $entity->getDescription2()->setEncryptedValue($data->description2);

        if( isset($data->agent_id) )
            $entity->setAgentId($data->agent_id);

        if( isset($data->requested_by) )
            $entity->setRequestedBy($data->requested_by);

        if( isset($data->user_type) )
            $entity->setUserType($data->user_type);

        if( isset($data->created_at) )
            $entity->setCreatedAt(IappsDateTime::fromUnix($data->created_at));
        
        if ( isset($data->status))
            $entity->setPaymentRequestStatus($data->status);
      
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
        $this->db->select('p.id as payment_id,
                           p.country_code,
                           p.module_code,
                           p.channelID,
                           p.transactionID,
                           p.user_profile_id,
                           p.country_currency_code,
                           p.amount,
                           p.status_id,
                           sc.code as status_code,
                           sc.display_name as status_name,
                           scg.id as status_group_id,
                           scg.code as status_group_code,
                           scg.display_name as status_group_name,
                           p.payment_code,
                           p.ewallet_id,
                           p.receipt_url,
                           p.payment_request_id,
                           p.description1,
                           p.description2,
                           p.agent_id,
                           p.requested_by,
                           p.user_type,
                           p.created_at,
                           p.created_by,
                           p.updated_at,
                           p.updated_by,
                           p.deleted_at,
                           p.deleted_by');
        $this->db->from('iafb_payment.payment p');
        $this->db->join('iafb_payment.system_code sc', 'p.status_id = sc.id');
        $this->db->join('iafb_payment.system_code_group scg', 'sc.system_code_group_id = scg.id');
        if( !$deleted )
            $this->db->where('p.deleted_at', NULL);
        $this->db->where('p.id', $id);
        $this->db->where('scg.code', PaymentStatus::getSystemGroupCode());

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->map($query->row());
        }

        return false;
    }
    

    public function findByTransactionID($module_code, $transactionID)
    {
        $this->db->select('p.id as payment_id,
                           p.country_code,
                           p.module_code,
                           p.channelID,
                           p.transactionID,
                           p.user_profile_id,
                           p.country_currency_code,
                           p.amount,
                           p.status_id,
                           sc.code as status_code,
                           sc.display_name as status_name,
                           scg.id as status_group_id,
                           scg.code as status_group_code,
                           scg.display_name as status_group_name,
                           p.payment_code,
                           p.ewallet_id,
                           p.receipt_url,
                           p.payment_request_id,
                           p.description1,
                           p.description2,
                           p.agent_id,
                           p.requested_by,
                           p.user_type,
                           p.created_at,
                           p.created_by,
                           p.updated_at,
                           p.updated_by,
                           p.deleted_at,
                           p.deleted_by');
        $this->db->from('iafb_payment.payment p');
        $this->db->join('iafb_payment.system_code sc', 'p.status_id = sc.id');
        $this->db->join('iafb_payment.system_code_group scg', 'sc.system_code_group_id = scg.id');
        $this->db->where('p.deleted_at', NULL);
        $this->db->where('p.module_code', $module_code);
        $this->db->where('p.transactionID', $transactionID);
        $this->db->where('scg.code', PaymentStatus::getSystemGroupCode());

        $query = $this->db->get();
        if( $query->num_rows() > 0)
        {
            return $this->map($query->row());
        }

        return false;
    }

    public function findByTransactionIDArr($module_code, $transactionIDArr)
    {
        $this->db->select('p.id as payment_id,
                           p.country_code,
                           p.module_code,
                           p.channelID,
                           p.transactionID,
                           p.user_profile_id,
                           p.country_currency_code,
                           p.amount,
                           p.status_id,
                           sc.code as status_code,
                           sc.display_name as status_name,
                           scg.id as status_group_id,
                           scg.code as status_group_code,
                           scg.display_name as status_group_name,
                           p.payment_code,
                           p.ewallet_id,
                           p.receipt_url,
                           p.payment_request_id,
                           p.description1,
                           p.description2,
                           p.agent_id,
                           p.requested_by,
                           p.user_type,
                           p.created_at,
                           p.created_by,
                           p.updated_at,
                           p.updated_by,
                           p.deleted_at,
                           p.deleted_by');
        $this->db->from('iafb_payment.payment p');
        $this->db->join('iafb_payment.system_code sc', 'p.status_id = sc.id');
        $this->db->join('iafb_payment.system_code_group scg', 'sc.system_code_group_id = scg.id');
        $this->db->where('p.deleted_at', NULL);
        $this->db->where('p.module_code', $module_code);
        $this->db->where_in('p.transactionID', $transactionIDArr);

        $query = $this->db->get();

        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentCollection(), $query->num_rows());
        }

        return false;
    }

    public function update(Payment $payment)
    {
        $updated_at = IappsDateTime::now();

        //todo add other fields to be updated
        if( $payment->getUserProfileId() )
            $this->db->set('user_profile_id', $payment->getUserProfileId());

        if( $payment->getStatus()->getId() )
        {
            $this->db->set('status_id', $payment->getStatus()->getId());
            $this->db->where('status_id <>', $payment->getStatus()->getId());   //make sure it doesnt update again
        }

        $this->db->set('updated_at', $updated_at->getUnix());
        $this->db->set('updated_by', $payment->getUpdatedBy());
        $this->db->where('id', $payment->getId());

        $this->db->update('iafb_payment.payment');
        if( $this->db->affected_rows() > 0 )
        {
            $payment->setUpdatedAt($updated_at);
            return $payment;
        }

        return false;
    }

    public function insert(Payment $payment)
    {
        $this->db->set('id', $payment->getId());
        $this->db->set('country_code', $payment->getCountryCode());
        $this->db->set('module_code', $payment->getModuleCode());
        $this->db->set('channelID', $payment->getChannelID());
        $this->db->set('transactionID', $payment->getTransactionID());
        $this->db->set('user_profile_id', $payment->getUserProfileId());
        $this->db->set('country_currency_code', $payment->getCountryCurrencyCode());
        $this->db->set('amount', $payment->getAmount());
        $this->db->set('status_id', $payment->getStatus()->getId());
        $this->db->set('payment_code', $payment->getPaymentCode());
        $this->db->set('ewallet_id', $payment->getEwalletId());
        $this->db->set('receipt_url', $payment->getReceiptUrl());
        $this->db->set('description1', $payment->getDescription1()->getEncryptedValue());
        $this->db->set('description2', $payment->getDescription2()->getEncryptedValue());
        $this->db->set('payment_request_id', $payment->getPaymentRequestId());
        $this->db->set('agent_id', $payment->getAgentId());
        $this->db->set('requested_by', $payment->getRequestedBy());
        $this->db->set('user_type', $payment->getUserType());
        $this->db->set('created_at', IappsDateTime::now()->getUnix());
        $this->db->set('created_by', $payment->getCreatedBy());

        if( $this->db->insert('iafb_payment.payment') )
        {
            return true;
        }

        return false;
    }
    
    //agent app
     public function findByParam(Payment $config, $limit, $page)
    {
        $init_predicate = true;
        $offset = ($page - 1) * $limit;
        $this->db->start_cache(); //to cache active record query
        $this->db->select('p.id as payment_id,
                           p.country_code,
                           p.module_code,
                           p.channelID,
                           p.transactionID,
                           p.user_profile_id,
                           p.country_currency_code,
                           p.amount,
                           p.channelID,
                           p.status_id,
                           sc.code as status_code,
                           sc.display_name as status_name,
                           scg.id as status_group_id,
                           scg.code as status_group_code,
                           scg.display_name as status_group_name,
                           p.payment_code,
                           p.ewallet_id,
                           p.receipt_url,
                           p.payment_request_id,
                           p.description1,
                           p.description2,
                           p.agent_id,
                           p.requested_by,
                           p.user_type,
                           p.created_at,
                           p.created_by,
                           p.updated_at,
                           p.updated_by,
                           p.deleted_at,
                           p.deleted_by');
        $this->db->from('iafb_payment.payment p');
        $this->db->join('iafb_payment.system_code sc', 'p.status_id = sc.id ');
        $this->db->join('iafb_payment.system_code sac','p.channelID = sac.id', 'LEFT');
        $this->db->join('iafb_payment.system_code_group scg', 'sc.system_code_group_id = scg.id');  
        $this->db->where('p.deleted_at', NULL);
        
         if($config->getTransactionID()) {
            $this->db->where('p.transactionID', $config->getTransactionID());
        }  
        
        if($config->getUserProfileId()) {
            $this->db->where('p.user_profile_id', $config->getUserProfileId());
        }


        if($config->getCreatedBy()) {
            $this->db->where('p.created_by', $config->getCreatedBy());
        }

        if($config->getRequestedBy()) {
            $this->db->where('p.requested_by', $config->getRequestedBy());
        }


        if($config->getDateFrom()){
            $this->db->where('p.created_at >=', $config->getDateFrom()->getUnix());
        }

        if($config->getDateTo()){
            $this->db->where('p.created_at <=', $config->getDateTo()->getUnix());
        }

        if($config->getUserType()) {
            $this->db->where('p.user_type', $config->getUserType());
        }

        if($config->getModuleCode()) {
            $this->db->where('p.module_code', $config->getModuleCode());
        }
        
        if($config->getChannelID()){
            $this->db->where('p.channelID', $config->getChannelID());
        }
        
        if($config->getPaymentCode()){
            $this->db->where('p.payment_code', $config->getPaymentCode());
        }
        
                
//        if($config->getIsAgentIdNull() > -1) {
//            if((bool)$config->getIsAgentIdNull()) {
//                $this->db->where('p.agent_id', NULL);
//            } else {
//                $this->db->where('p.agent_id is NOT NULL', NULL, FALSE);
//            }
//        }
        
        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit

        $this->db->order_by("p.created_at", "desc");
        $this->db->limit($limit, $offset);
        $query = $this->db->get();

        $this->db->flush_cache();

        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentCollection(), $total);
        }

        return false;
    }

    //partner web
    public function findByCreatorAndParam(Payment $payment, $create_by_arr, $limit, $page, IappsDateTime $date_from = NULL, IappsDateTime $date_to = NULL)
    {
        $offset = ($page - 1) * $limit;
        $this->db->start_cache(); //to cache active record query
        $this->db->select('p.id as payment_id,
                           p.country_code,
                           p.module_code,
                           p.channelID,
                           p.transactionID,
                           p.user_profile_id,
                           p.country_currency_code,
                           p.amount,
                           p.status_id,
                           sc.code as status_code,
                           sc.display_name as status_name,
                           scg.id as status_group_id,
                           scg.code as status_group_code,
                           scg.display_name as status_group_name,                          
                           p.payment_code,
                           p.ewallet_id,
                           p.receipt_url,
                           p.payment_request_id,
                           p.description1,
                           p.description2,
                           p.agent_id,
                           p.requested_by,
                           p.user_type,
                           p.created_at,
                           p.created_by,
                           p.updated_at,
                           p.updated_by,
                           p.deleted_at,
                           p.deleted_by');
        $this->db->from('iafb_payment.payment p');
        $this->db->join('iafb_payment.system_code sc', 'p.status_id = sc.id');
        $this->db->join('iafb_payment.system_code sac', 'p.channelID = sac.id');        
        $this->db->join('iafb_payment.system_code_group scg', 'sc.system_code_group_id = scg.id');
        $this->db->where('p.deleted_at', NULL);
//        $this->db->where('sac.code','agent_app');
//        $this->db->or_where('sac.code','pub_app');
        if($create_by_arr != NULL) {
            if (count($create_by_arr) > 0) {
                $this->db->where_in('p.requested_by', $create_by_arr); //3183: change to filter based on requested_by (created_by from payment_request)
            }
        }
        if($payment->getTransactionID()) {
            $this->db->where('p.transactionID', $payment->getTransactionID());
        }
        if($payment->getCreatedBy()) {
            $this->db->where('p.created_by', $payment->getCreatedBy());
        }
        if($payment->getUserProfileId()) {
            $this->db->where('p.user_profile_id', $payment->getUserProfileId());
        }
        if($payment->getModuleCode()) {
            $this->db->where('p.module_code', $payment->getModuleCode());
        }
        
        if($payment->getChannelID()){
            $this->db->where('p.channelID', $payment->getChannelID());
        }
        
        if($payment->getPaymentCode()){
            $this->db->where('p.payment_code', $payment->getPaymentCode());
        } 
        
        if($payment->getPaymentCode()) {
            $this->db->where('p.payment_code', $payment->getPaymentCode());
        }
        if($date_from != NULL) {
            $this->db->where('p.created_at >= ', $date_from->getUnix());
        }
        if($date_to != NULL) {
            $this->db->where('p.created_at <= ', $date_to->getUnix());
        }
        if($payment->getUserType()) {
            $this->db->where('p.user_type', $payment->getUserType());
        }
//        if($payment->getIsAgentIdNull() > -1) {
//            if((bool)$payment->getIsAgentIdNull()) {
//                $this->db->where('p.agent_id', NULL);
//            } else {
//                $this->db->where('p.agent_id is NOT NULL', NULL, FALSE);
//            }
//        }

        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit

        $this->db->order_by("p.created_at", "desc");
        $this->db->limit($limit, $offset);
        $query = $this->db->get();

        $this->db->flush_cache();

        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentCollection(), $total);
        }

        return false;
    }

    public function reportFindByParam(Payment $payment, IappsDateTime $date_from, IappsDateTime $date_to)
    {
        $this->db->start_cache(); //to cache active record query
        $this->db->select('p.id as payment_id,
                           p.country_code,
                           p.module_code,
                           p.channelID,
                           p.transactionID,
                           p.user_profile_id,
                           p.country_currency_code,
                           p.amount,
                           p.status_id,
                           sc.code as status_code,
                           sc.display_name as status_name,
                           scg.id as status_group_id,
                           scg.code as status_group_code,
                           scg.display_name as status_group_name,
                           p.payment_code,
                           p.ewallet_id,
                           p.receipt_url,
                           p.payment_request_id,
                           p.description1,
                           p.description2,
                           p.agent_id,
                           p.requested_by,
                           p.user_type,
                           p.created_at,
                           p.created_by,
                           p.updated_at,
                           p.updated_by,
                           p.deleted_at,
                           p.deleted_by');
        $this->db->from('iafb_payment.payment p');
        $this->db->join('iafb_payment.system_code sc', 'p.status_id = sc.id');
        $this->db->join('iafb_payment.system_code_group scg', 'sc.system_code_group_id = scg.id');
        $this->db->where('p.deleted_at', NULL);


        if($payment->getModuleCode()) {
            $this->db->where('p.module_code', $payment->getModuleCode());
        }
        
        if($payment->getChannelID()){
            $this->db->where('p.channelID', $payment->getChannelID());
        }

        if($payment->getPaymentCode()) {
            $this->db->where('p.payment_code', $payment->getPaymentCode());
        }

        if($date_from != NULL) {
            $this->db->where('p.created_at >= ', $date_from->getUnix());
        }

        if($date_to != NULL) {
            $this->db->where('p.created_at <= ', $date_to->getUnix());
        }

        if( $payment->getStatus()->getCode() ) {
            $this->db->where('sc.code', $payment->getStatus()->getCode());
        }

        $this->db->stop_cache();

        $total = $this->db->count_all_results(); //to get total num of result w/o limit

        $this->db->order_by("p.created_at", "desc");
        $query = $this->db->get();

        $this->db->flush_cache();

        if( $query->num_rows() > 0)
        {
            return $this->mapCollection($query->result(), new PaymentCollection(), $total);
        }

        return false;
    }
}

