<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class StoreWorkCreditCashInClient extends DownlineEwalletClient{

    protected $_requestUri = 'store/workcredit/cashin/request';
    protected $_cancelUri = 'store/workcredit/cashin/cancel';
    protected $_completeUri = 'store/workcredit/cashin/complete';

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