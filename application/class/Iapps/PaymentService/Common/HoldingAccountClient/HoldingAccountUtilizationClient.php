<?php

namespace Iapps\PaymentService\Common\HoldingAccountClient;


class HoldingAccountUtilizationClient extends HoldingAccountClient
{
    protected $_requestUri = 'user/holdingaccount/utilize/request';
    protected $_cancelUri = 'user/holdingaccount/utilize/cancel';
    protected $_completeUri = 'user/holdingaccount/utilize/complete';

    public function request()
    {
        $response = parent::request();
        return new HoldingAccountUtilizationClientResponse($response->getRaw());
    }
}