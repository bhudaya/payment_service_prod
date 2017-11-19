<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

class SirManualBankTransferPaymentRequestValidator extends BTIndoOCBCPaymentRequestValidator{

    protected function _validateCountryCurrency()
    {
        return PaymentRequestValidator::_validateCountryCurrency();
    }
}