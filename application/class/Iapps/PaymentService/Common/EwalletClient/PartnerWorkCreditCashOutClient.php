<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class PartnerWorkCreditCashOutClient extends DownlineEwalletClient{

    protected $_requestUri = 'partner/workcredit/cashout/request';
    protected $_cancelUri = 'partner/workcredit/cashout/cancel';
    protected $_completeUri = 'partner/workcredit/cashout/complete';

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