<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

use Iapps\PaymentService\PaymentMode\PaymentModeGroupType;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;
use Iapps\PaymentService\PaymentMode\PaymentModeServiceFactory;

class PaymentRequestValidatorFactory{

    public static function build($payment_mode, PaymentRequest $request)
    {
        $pmServ = PaymentModeServiceFactory::build();
        $pmInfo = $pmServ->getPaymentModeInfo($payment_mode);

        //check payment mode group first
        if( isset( $pmInfo['payment_mode_group']) )
        {
            switch($pmInfo['payment_mode_group'])
            {
                case PaymentModeGroupType::GROUP_KIOSK:
                    return KioskPaymentRequestValidator::make($request);
            }
        }

        switch($payment_mode)
        {
            case PaymentModeType::BANK_TRANSFER_INDO_OCBC:
                return BTIndoOCBCPaymentRequestValidator::make($request);
                break;
            case PaymentModeType::SIR_BANK_TRANSFER_MANUAL:
                return SirManualBankTransferPaymentRequestValidator::make($request);
                break;
            case PaymentModeType::BANK_TRANSFER_MANUAL:
                return ManualBankTransferPaymentRequestValidator::make($request);
                break;
            case PaymentModeType::BANK_TRANSFER_GPL:
                return GPLPaymentRequestValidator::make($request);
                break;
            case PaymentModeType::NIL:
                return NilPaymentRequestValidator::make($request);
                break;

            case PaymentModeType::BANK_TRANSFER_TMONEY:
                return TMoneyPaymentRequestValidator::make($request);
                break;
                
            case PaymentModeType::OCBC_CREDIT_CARD:
                return OcbcCreditCardPaymentRequestValidator::make($request);
                break;
            default:
                return PaymentRequestValidator::make($request);
        }
    }
}