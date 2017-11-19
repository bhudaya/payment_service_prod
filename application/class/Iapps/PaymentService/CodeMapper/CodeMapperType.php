<?php

namespace Iapps\PaymentService\CodeMapper;

use Iapps\Common\SystemCode\SystemCodeInterface;

class CodeMapperType implements SystemCodeInterface{

    const GPL_SENDER_IDENTITY_TYPE = 'GPL_SENDER_IDENTITY_TYPE';
    const GPL_REMITTANCE_PURPOSE = 'GPL_REMITTANCE_PURPOSE';
    const GPL_FUND_OF_SOURCE = 'GPL_FUND_OF_SOURCE';
    const GPL_BANK_CODE = 'GPL_BANK_CODE';
    const GPL_NATIONALITY = 'GPL_NATIONALITY';
    const GPL_PAYMENT_METHOD = 'GPL_PAYMENT_METHOD';
    const GPL_PAYMENT_DESCRIPTION = 'GPL_PAYMENT_DESCRIPTION';

    public static function getSystemGroupCode()
    {
        return 'code_mapper_type';
    }
}
