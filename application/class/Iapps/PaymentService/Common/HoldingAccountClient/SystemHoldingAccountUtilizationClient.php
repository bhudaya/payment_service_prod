<?php

namespace Iapps\PaymentService\Common\HoldingAccountClient;

use Iapps\Common\Helper\MicroserviceHelper\MicroserviceHelper;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClientInterface;

class SystemHoldingAccountUtilizationClient extends HoldingAccountClient
{
    protected $_requestUri = 'system/holdingaccount/utilize/request';
    protected $_cancelUri = 'system/holdingaccount/utilize/cancel';
    protected $_completeUri = 'system/holdingaccount/utilize/complete';

    public function request()
    {
        $response = parent::request();
        return new HoldingAccountUtilizationClientResponse($response->getRaw());
    }
}