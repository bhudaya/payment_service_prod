<?php

namespace Iapps\PaymentService\Common\HoldingAccountClient;

class DownlineHoldingAccountClient extends HoldingAccountClient{

    //require to pass upline agent id
    protected $agent_id;

    public static function fromOption(array $option)
    {
        $c = parent::fromOption($option);

        if( isset($option['agent_id']) )
            $c->setAgentId($option['agent_id']);

        return $c;
    }

    public function setAgentId($agent_id)
    {
        $this->agent_id = $agent_id;
        return $this;
    }

    public function getAgentId()
    {
        return $this->agent_id;
    }

    public function getOption()
    {
        $option = array('headers' => $this->_getHeaders(),
            'agent_id' => $this->getAgentId(),
            'module_code' => $this->getModuleCode(),
            'transactionID' => $this->getTransactionID(),
            'country_currency_code' => $this->getCountryCurrencyCode(),
            'amount' => $this->getAmount() );

        return json_encode($option);
    }

    public function request()
    {
        $option = array(
            'method' => 'post',
            'uri' => $this->_requestUri,
            'param' => array(
                'agent_id' => $this->getAgentId(),
                'module_code' => $this->getModuleCode(),
                'transactionID' => $this->getTransactionID(),
                'country_currency_code' => $this->getCountryCurrencyCode(),
                'amount' => abs($this->getAmount()) ),
            'header' => $this->_getHeaders()
        );

        if( $resp = $this->_microServ->call($option) )
            $response['success'] = true;
        else
            $response['success'] = false;

        $response['response'] = $this->_microServ->getLastReponse();

        $this->setLastResponse($this->_microServ->getLastReponse());
        return new HoldingAccountClientResponse($response);
    }
}