<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class StoreWorkCreditCommisionClient extends WorkCreditCommisionClient{

    protected $_requestUri = 'store/workcredit/commision/request';
    protected $_cancelUri = 'store/workcredit/commision/cancel';
    protected $_completeUri = 'store/workcredit/commision/complete';
}