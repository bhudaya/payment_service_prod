<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class FranchiseCashPaymentRequestService extends StoreCashPaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::FRANCHISE_CASH;
    }

    protected function _getStaffType()
    {
        if( $this->_staffType )
            return $this->_staffType;

        $acc_serv = AccountServiceFactory::build();
        if( $acc_serv->checkAccessByUserProfileId($this->getUpdatedBy(), FunctionCode::STORE_FRANCHISE_STAFF_FUNCTIONS))
        {
            $this->_staffType = FunctionCode::STORE_FRANCHISE_STAFF_FUNCTIONS;
            return $this->_staffType;
        }

        return false;
    }
}