<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

use Iapps\Common\Helper\RequestHeader;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Validator\IappsValidator;
use Iapps\PaymentService\CountryCurrency\CountryCurrencyServiceFactory;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\PaymentAccess\PaymentAccessCheckerFactory;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;

class NilPaymentRequestValidator extends PaymentRequestValidator{

    protected function _validateAmount()
    {
        return ($this->request->getAmount() == 0.0);
    }

    protected function _validateAccess()
    {
        //temp no need to validate
        return true;
    }

}