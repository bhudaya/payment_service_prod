<?php

namespace Iapps\PaymentService\PaymentAccess;

use Iapps\PaymentService\PaymentMode\PaymentModeGroupType;
use Iapps\PaymentService\PaymentMode\PaymentModeServiceFactory;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class PaymentAccessCheckerFactory{

    public static function build($payment_mode)
    {
        $pmServ = PaymentModeServiceFactory::build();
        $pmInfo = $pmServ->getPaymentModeInfo($payment_mode);

        //check payment mode group first
        if( isset( $pmInfo['payment_mode_group']) )
        {
            switch($pmInfo['payment_mode_group'])
            {
                case PaymentModeGroupType::GROUP_KIOSK:
                    return new KioskPaymentAccessChecker();
            }
        }

        //come back to by payment mode
        switch($payment_mode)
        {
            case PaymentModeType::BANK_TRANSFER_INDO_OCBC:
                return new BTIndoOCBCPaymentAccessChecker();
            case PaymentModeType::SIR_BANK_TRANSFER_MANUAL:
                return new SirManualBankTransferPaymentAccessChecker();
            case PaymentModeType::STORE_CASH:
                return new StoreCashPaymentAccessChecker();
            case PaymentModeType::FRANCHISE_CASH:
                return new StoreFranchiseCashPaymentAccessChecker();
            case PaymentModeType::ADMIN_CASH:
                return new AdminCashPaymentAccessChecker();
            case PaymentModeType::ADMIN_BANK_TRANSFER:
                return new AdminBTPaymentAccessChecker();
            case PaymentModeType::PARTNER_CASH:
                return new PartnerCashPaymentAccessChecker();
            case PaymentModeType::MOBILE_AGENT_CASH:
                return new MobileCashPaymentAccessChecker();
            case PaymentModeType::EWALLET:
                return new EWalletPaymentAccessChecker();
            case PaymentModeType::BANK_TRANSFER_MANUAL:
                return new ManualBankTransferPaymentAccessChecker();
            case PaymentModeType::CASH_PICKUP:
                return new CashPickupPaymentAccessChecker();
            case PaymentModeType::BANK_TRANSFER_GPL:
                return new GPLPaymentAccessChecker();

            case PaymentModeType::BANK_TRANSFER_TMONEY:
                return new TMoneyPaymentAccessChecker();
            case PaymentModeType::OCBC_CREDIT_CARD:
                return new OcbcCreditCardPaymentAccessChecker();
            case PaymentModeType::HOLDING_ACCOUNT_BORROWER:
            case PaymentModeType::HOLDING_ACCOUNT_PROJECT:
            case PaymentModeType::HOLDING_ACCOUNT_INVESTMENT:
                return new HoldingAccountPaymentAccessChecker();
            default:
                return new PaymentAccessChecker();
        }
    }
}