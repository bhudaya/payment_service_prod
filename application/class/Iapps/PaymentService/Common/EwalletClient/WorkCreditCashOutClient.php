<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class WorkCreditCashOutClient extends EwalletClient{

    protected $_requestUri = 'agent/workcredit/cashout/request';
    protected $_cancelUri = 'agent/workcredit/cashout/cancel';
    protected $_completeUri = 'agent/workcredit/cashout/complete';

    public function request()
    {
        $response = parent::request();
        return new WorkCreditCashOutClientResponse($response->getRaw());
    }

    public function getAmount()
    {
        return abs(parent::getAmount());
    }
}