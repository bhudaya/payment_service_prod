<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class PartnerWorkCreditCommisionClient extends WorkCreditCommisionClient{

    protected $_requestUri = 'partner/workcredit/commision/request';
    protected $_cancelUri = 'partner/workcredit/commision/cancel';
    protected $_completeUri = 'partner/workcredit/commision/complete';
}