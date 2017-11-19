<?php

namespace Iapps\PaymentService\Common\HoldingAccountClient;

class HoldingAccountCollectionClient extends HoldingAccountClient{

    protected $_requestUri = 'holdingaccount/collection/request';
    protected $_cancelUri = 'holdingaccount/collection/cancel';
    protected $_completeUri = 'holdingaccount/collection/complete';

    protected $user_profile_id;
    protected $payment_code;
    protected $is_collection = false; //default is refund

    public function setUserProfileId($user_id)
    {
        $this->user_profile_id = $user_id;
        return $this;
    }

    public function getUserProfileId()
    {
        return $this->user_profile_id;
    }

    public function setPaymentCode($payment_code)
    {
        $this->payment_code = $payment_code;
        return $this;
    }

    public function getPaymentCode()
    {
        return $this->payment_code;
    }

    public function setIsCollection($is_collection)
    {
        $this->is_collection = $is_collection;
        return $this;
    }

    public function getIsCollection()
    {
        return $this->is_collection;
    }

    public function request()
    {
        $option = array(
            'method' => 'post',
            'uri' => $this->_requestUri,
            'param' => array('user_profile_id' => $this->getUserProfileId(),
                             'module_code' => $this->getModuleCode(),
                             'transactionID' => $this->getTransactionID(),
                             'country_currency_code' => $this->getCountryCurrencyCode(),
                             'payment_code' => $this->getPaymentCode(),
                             'amount' => $this->getAmount(),
                             'is_collection' => $this->getIsCollection(),
                             'holding_account_type' => $this->getHoldingAccountType(),
                             'reference_id' => $this->getReferenceId()
                            ),
            'header' => $this->_getHeaders()
        );

        if( $resp = $this->_microServ->call($option) )
            $response['success'] = true;
        else
            $response['success'] = false;

        $response['response'] = $this->_microServ->getLastReponse();

        $this->setLastResponse($this->_microServ->getLastReponse());
        return new HoldingAccountCollectionClientResponse($response);
    }

    public function cancel()
    {
        $option = array(
            'method' => 'post',
            'uri' => $this->_cancelUri,
            'param' => array('request_token' => $this->getToken(),
                             'is_collection' => $this->getIsCollection()),
            'header' => $this->_getHeaders()
        );

        if( $resp = $this->_microServ->call($option) )
        {//cancelled
            $this->setLastResponse($this->_microServ->getLastReponse());
            return true;
        }

        $this->setLastResponse($this->_microServ->getLastReponse());
        return false;
    }

    public function complete()
    {
        $option = array(
            'method' => 'post',
            'uri' => $this->_completeUri,
            'param' => array('request_token' => $this->getToken(),
                             'is_collection' => $this->getIsCollection()),
            'header' => $this->_getHeaders()
        );

        if( $resp = $this->_microServ->call($option) )
        {//completed
            $this->setLastResponse($this->_microServ->getLastReponse());
            return true;
        }

        $this->setLastResponse($this->_microServ->getLastReponse());
        return false;
    }
}