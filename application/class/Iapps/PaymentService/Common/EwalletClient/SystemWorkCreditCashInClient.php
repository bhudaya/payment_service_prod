<?php

namespace Iapps\PaymentService\Common\EwalletClient;

class SystemWorkCreditCashInClient extends WorkCreditCashInClient{

    protected $_cancelUri = 'system/workcredit/cashin/cancel';
    protected $_completeUri = 'system/workcredit/cashin/complete';

}