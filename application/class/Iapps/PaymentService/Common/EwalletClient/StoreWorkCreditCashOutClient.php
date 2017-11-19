<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class StoreWorkCreditCashOutClient extends DownlineEwalletClient{

    protected $_requestUri = 'store/workcredit/cashout/request';
    protected $_cancelUri = 'store/workcredit/cashout/cancel';
    protected $_completeUri = 'store/workcredit/cashout/complete';

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