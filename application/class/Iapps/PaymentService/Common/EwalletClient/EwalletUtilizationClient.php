<?php

namespace Iapps\PaymentService\Common\EwalletClient;

use Iapps\Common\Helper\MicroserviceHelper\MicroserviceHelper;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClientInterface;

class EwalletUtilizationClient extends EwalletClient
{
    protected $_requestUri = 'user/ewallet/utilize/request';
    protected $_cancelUri = 'user/ewallet/utilize/cancel';
    protected $_completeUri = 'user/ewallet/utilize/complete';

    public function request()
    {
        $response = parent::request();
        return new EwalletUtilizationClientResponse($response->getRaw());
    }
}