<?php

namespace Iapps\PaymentService\Common\EwalletClient;

use Iapps\Common\Helper\MicroserviceHelper\MicroserviceHelper;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClientInterface;

class SystemEwalletUtilizationClient extends EwalletClient
{
    protected $_cancelUri = 'system/ewallet/utilize/cancel';
    protected $_completeUri = 'system/ewallet/utilize/complete';

    public function request()
    {
        $response = parent::request();
        return new EwalletUtilizationClientResponse($response->getRaw());
    }
}