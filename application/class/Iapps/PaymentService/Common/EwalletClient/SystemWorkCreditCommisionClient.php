<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class SystemWorkCreditCommisionClient extends WorkCreditCommisionClient{

    protected $_cancelUri = 'system/workcredit/commision/cancel';
    protected $_completeUri = 'system/workcredit/commision/complete';

}