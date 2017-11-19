<?php

namespace Iapps\PaymentService\Common\TMoneySwitch;

class TMoneySwitchFunction {

    const CODE_REMIT             = 'remit';
    const CODE_INQUIRY           = 'inquiry';


    const BDO_REMIT_BDO_SOAP_REQUEST = 'urn:RemitAPI#creditCASAOnLine';
    const BDO_REMIT_OTHER_BANK_SOAP_REQUEST = 'urn:RemitAPI#creditOtherBank';

    const TMONEY_STATUS_INPROCESS = "INPROCESS";
    const TMONEY_STATUS_OUTSTANDING = "OUTSTANDING";
    const TMONEY_STATUS_FOR_VERIFICATION = "FOR VERIFICATION";

    CONST TMONEY_TIMEZONE = 'tmoney_timezone';
}