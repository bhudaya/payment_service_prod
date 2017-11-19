<?php

namespace Iapps\PaymentService\PaymentMode;

class PaymentModeType{
    const BANK_TRANSFER_INDO_OCBC = 'BT1';
    const STORE_CASH = 'CA1';
    const MOBILE_AGENT_CASH = 'CA2';
    const ADMIN_CASH = 'CA3';
    const ADMIN_BANK_TRANSFER = 'BT4';
    const PARTNER_CASH = 'CA4';
    const FRANCHISE_CASH = 'CA5';
    const SINGAPORE_POST = 'SGP';
    const KIOSK = 'KSK';
    const EWALLET = 'EWA';
    const BANK_TRANSFER_MANUAL = 'BT2';
    const SIR_BANK_TRANSFER_MANUAL = 'BT3';
    const BANK_TRANSFER_GPL = 'BT8';
    const CASH_PICKUP = 'CP1';
    const NIL = 'NIL';
    const BANK_TRANSFER_TMONEY = 'BT7';
    const OCBC_CREDIT_CARD = 'CC1';
    const ENETS_DEBIT_CARD = 'CC2';
    const ENETS_CREDIT_CARD = 'CC3';
    const HOLDING_ACCOUNT_BORROWER = 'HA1';
    const HOLDING_ACCOUNT_PROJECT = 'HA2';
    const HOLDING_ACCOUNT_INVESTMENT = 'HA3';
}
