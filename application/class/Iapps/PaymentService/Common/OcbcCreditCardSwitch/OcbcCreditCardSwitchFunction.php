<?php

namespace Iapps\PaymentService\Common\OcbcCreditCardSwitch;

class OcbcCreditCardSwitchFunction {

    const CODE_AUTHORIZATION = 'authorization';
    const CODE_SALES = 'sales';
    const CODE_QUERY_STATUS  = 'query';

    const OCBC_STATUS_PENDING = 'N';
    const OCBC_STATUS_AUTHORIZED = 'A';
    const OCBC_STATUS_CAPTURED = 'C';
    const OCBC_STATUS_SALES_COMPLETED = 'S';
    const OCBC_STATUS_VOID = 'V';
    const OCBC_STATUS_ERROR = 'E';
    const OCBC_STATUS_FAILED = 'F';
    const OCBC_STATUS_BLACKLISTED = 'BL';
    const OCBC_STATUS_BLOCKED = 'B';

    const OCBC_APPROVED_OR_COMPLETED = '0';
    const OCBC_REFUND_COMPLETED = '7001';
    const OCBC_CUSTOMER_CANCEL_PAYMENT = '9935';
    const OCBC_BANK_REJECTED_PAYMENT = "9967";
}