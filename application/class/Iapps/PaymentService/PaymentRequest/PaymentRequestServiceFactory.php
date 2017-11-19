<?php

namespace Iapps\PaymentService\PaymentRequest;

require_once './application/modules/paymentrequest/models/Payment_request_model.php';

use Iapps\PaymentService\Payment\EWalletPaymentService;
use Iapps\PaymentService\Payment\PaymentServiceFactory;
use Iapps\PaymentService\PaymentMode\PaymentMode;
use Iapps\PaymentService\PaymentMode\PaymentModeGroupType;
use Iapps\PaymentService\PaymentMode\PaymentModeServiceFactory;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class PaymentRequestServiceFactory{
    protected static $_instance = array();
    protected static $channelID;

    public static function build($payment_mode)
    {


        if( !array_key_exists($payment_mode, self::$_instance ) )
        {
            $dm = new \Payment_request_model();
            $repo = new PaymentRequestRepository($dm);

            //get paymet mode group
            $pmServ = PaymentModeServiceFactory::build();
            $pmInfo = $pmServ->getPaymentModeInfo($payment_mode);

            //based on group first
            if( is_array($pmInfo) )
            {
                switch ($pmInfo['payment_mode_group'])
                {
                    case PaymentModeGroupType::GROUP_KIOSK:
                        switch ($payment_mode) {
                            case PaymentModeType::SINGAPORE_POST:
                                self::$_instance[$payment_mode] = new SamPaymentRequestService($repo);
                                break;
                            default: //for kiosk group that doesnt have specified payment request service, default will be used
                                self::$_instance[$payment_mode] = new KioskPaymentRequestService($repo, '127.0.0.1', NULL, $payment_mode);
                                break;
                        }
                        break;
                }

                if( isset(self::$_instance[$payment_mode]) )
                    return self::$_instance[$payment_mode];
            }

            //normal
            switch($payment_mode)
            {
                case PaymentModeType::BANK_TRANSFER_INDO_OCBC:
                    self::$_instance[$payment_mode] = new BTIndoOCBCPaymentRequestService($repo);
                    break;
                case PaymentModeType::SIR_BANK_TRANSFER_MANUAL:
                    self::$_instance[$payment_mode] = new SirManualTransferPaymentRequest($repo);
                    break;
                case PaymentModeType::STORE_CASH:
                    self::$_instance[$payment_mode] = new StoreCashPaymentRequestService($repo);
                    break;
                case PaymentModeType::EWALLET:
                    self::$_instance[$payment_mode] = new EWalletPaymentRequestService($repo);
                    break;
                case PaymentModeType::ADMIN_CASH:
                    self::$_instance[$payment_mode] = new AdminCashPaymentRequestService($repo);
                    break;
                case PaymentModeType::ADMIN_BANK_TRANSFER:
                    self::$_instance[$payment_mode] = new AdminBTPaymentRequestService($repo);
                    break;
                case PaymentModeType::PARTNER_CASH:
                    self::$_instance[$payment_mode] = new PartnerCashPaymentRequestService($repo);
                    break;
                case PaymentModeType::MOBILE_AGENT_CASH:
                    self::$_instance[$payment_mode] = new MobileCashPaymentRequestService($repo);
                    break;
                case PaymentModeType::FRANCHISE_CASH:
                    self::$_instance[$payment_mode] = new FranchiseCashPaymentRequestService($repo);
                    break;
                case PaymentModeType::BANK_TRANSFER_MANUAL:
                    self::$_instance[$payment_mode] = new ManualBankTransferPaymentRequestService($repo);
                    break;
                case PaymentModeType::CASH_PICKUP:
                    self::$_instance[$payment_mode] = new CashPickupPaymentRequestService($repo);
                    break;
                case PaymentModeType::BANK_TRANSFER_GPL:
                    self::$_instance[$payment_mode] = new GPLBTPaymentRequestService($repo);
                    break;
                case PaymentModeType::NIL:
                    self::$_instance[$payment_mode] = new NilPaymentRequestService($repo);
                    break;
                case PaymentModeType::BANK_TRANSFER_TMONEY:
                    self::$_instance[$payment_mode] = new TMoneyPaymentRequestService($repo);
                    break;
                case PaymentModeType::OCBC_CREDIT_CARD:
                    self::$_instance[$payment_mode] = new OcbcCreditCardPaymentRequestService($repo);
                    break;
                case PaymentModeType::HOLDING_ACCOUNT_BORROWER:
                    self::$_instance[$payment_mode] = new HoldingAccountBorrowerPaymentRequestService($repo);
                    break;
                case PaymentModeType::HOLDING_ACCOUNT_PROJECT:
                    self::$_instance[$payment_mode] = new HoldingAccountProjectPaymentRequestService($repo);
                    break;
                case PaymentModeType::HOLDING_ACCOUNT_INVESTMENT:
                    self::$_instance[$payment_mode] = new HoldingAccountInvestmentPaymentRequestService($repo);
                    break;
                default:
                    return false;
            }
        }

        return self::$_instance[$payment_mode];
    }
}
