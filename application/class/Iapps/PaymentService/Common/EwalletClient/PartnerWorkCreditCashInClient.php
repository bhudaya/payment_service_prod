<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class PartnerWorkCreditCashInClient extends DownlineEwalletClient{

    protected $_requestUri = 'partner/workcredit/cashin/request';
    protected $_cancelUri = 'partner/workcredit/cashin/cancel';
    protected $_completeUri = 'partner/workcredit/cashin/complete';

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