<?php

namespace Iapps\PaymentService\Common;

/*
* Predefined Access Function Code Is Here
*/
class FunctionCode{
    const PUBLIC_FUNCTIONS = 'public_functions';
    const AGENT_FUNCTIONS = 'agent_functions';
    const ADMIN_PAYMENT = 'admin_payment';
    const ADMIN_VOID = 'admin_void';
    const ADMIN_PAYMENT_IN = 'admin_payment_in';
    const ADMIN_PAYMENT_OUT = 'admin_payment_out';
    const PARTNER_PAYMENT = 'partner_payment';
    const PARTNER_PAYMENT_IN = 'partner_payment_in';
    const PARTNER_PAYMENT_OUT = 'partner_payment_out';
    const COUNTER_CASHIN = 'counter_cashin';
    const COUNTER_CASHOUT = 'counter_cashout';
    const MOBILE_CASHIN = 'mobile_cashin';
    const MOBILE_CASHOUT = 'mobile_cashout';
    const FRANCHISE_CASHIN = 'franchise_cashin';
    const FRANCHISE_CASHOUT = 'franchise_cashout';


    const ADMIN_LIST_TRANSACTION_FOR_OTHERS    = 'admin_list_transaction_for_others';
    const ADMIN_LIST_PAYMENT_BY_CREATOR = 'admin_list_payment_by_creator';
    const ADMIN_LIST_MANUAL_BANK_TRANSFER_REQUEST_FIRST_CHECK = 'admin_list_manual_bank_transfer_first_check';
    const ADMIN_MANUAL_BANK_TRANSFER_REQUEST_UPDATE_FIRST_CHECK = 'admin_manual_bank_transfer_update_first_check';

    const PARTNER_LIST_TRANSACTION_FOR_OTHERS  = 'partner_list_transaction_for_others';

    const VIEW_TEKTAYA_REPORT    = 'view_tektaya_report';

}