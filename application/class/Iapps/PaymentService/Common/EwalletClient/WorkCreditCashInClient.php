<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class WorkCreditCashInClient extends EwalletClient{

    protected $_requestUri = 'agent/workcredit/cashin/request';
    protected $_cancelUri = 'agent/workcredit/cashin/cancel';
    protected $_completeUri = 'agent/workcredit/cashin/complete';

    public function request()
    {
        $response = parent::request();
        return new WorkCreditCashInClientResponse($response->getRaw());
    }

    public function getAmount()
    {
        return abs(parent::getAmount());
    }
}