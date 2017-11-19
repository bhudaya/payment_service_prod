<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class WorkCreditCommisionClient extends EwalletClient{

    protected $beneficiary_id;

    protected $_requestUri = 'agent/workcredit/commision/request';
    protected $_cancelUri = 'agent/workcredit/commision/cancel';
    protected $_completeUri = 'agent/workcredit/commision/complete';

    public static function fromOption(array $option)
    {
        $c = parent::fromOption($option);

        if( isset($option['beneficial_user_id']) )
            $c->setBeneficiaryId($option['beneficial_user_id']);

        return $c;
    }

    public function setBeneficiaryId($id)
    {
        $this->beneficiary_id = $id;
        return $this;
    }

    public function getBeneficiaryId()
    {
        return $this->beneficiary_id;
    }

    public function getOption()
    {
        $option = array('headers' => $this->_getHeaders(),
            'module_code' => $this->getModuleCode(),
            'transactionID' => $this->getTransactionID(),
            'country_currency_code' => $this->getCountryCurrencyCode(),
            'amount' => $this->getAmount(),
            'beneficial_user_id' => $this->getBeneficiaryId());

        return json_encode($option);
    }

    public function request()
    {
        $option = array(
            'method' => 'post',
            'uri' => $this->_requestUri,
            'param' => array('module_code' => $this->getModuleCode(),
                'transactionID' => $this->getTransactionID(),
                'country_currency_code' => $this->getCountryCurrencyCode(),
                'amount' => $this->getAmount(),
                'beneficial_user_id' => $this->getBeneficiaryId()),
            'header' => $this->_getHeaders()
        );

        if( $resp = $this->_microServ->call($option) )
            $response['success'] = true;
        else
            $response['success'] = false;

        $response['response'] = $this->_microServ->getLastReponse();

        return new WorkCreditCommisionClientResponse($response);
    }
}