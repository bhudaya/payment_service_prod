<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\ArrayExtractor;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\Helper\RequestHeader;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\Payment\PaymentStatus;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\PaymentService\Common\PaymentEventProducer;
use Iapps\PaymentService\Common\SystemCodeServiceFactory;
use Iapps\Common\Microservice\AccountService\User;

class ManualBankTransferPaymentRequestService extends PaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::BANK_TRANSFER_MANUAL;
    }

    public function request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, array $option)
    {
        //add admin access token as option
        $headers = RequestHeader::get();
        $option['token'] = NULL;
        if( array_key_exists(ResponseHeader::FIELD_X_AUTHORIZATION, $headers) )
            $option['token'] = $headers[ResponseHeader::FIELD_X_AUTHORIZATION];

        return parent::request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, $option);
    }

    protected function _generateDetail1(PaymentRequest $request)
    {
        $desc = new PaymentDescription();

        //add transfer type
        if($request->getPaymentModeRequestType() != NULL) {
            if($request->getPaymentModeRequestType()->getDisplayName() != NULL) {
                $desc->add('Transfer Type', $request->getPaymentModeRequestType()->getDisplayName());
            }
        }

        if($request->getPaymentModeRequestType()->getCode() == PaymentModeRequestType::IBANKING) {

            $acc_serv = AccountServiceFactory::build();
            if($userProfile = $acc_serv->getUserProfile($request->getUserProfileId())) {
                if($userProfile instanceof User) {
                    if ($userProfile->getMobileNumberObj() != NULL) {
                        $request->setUserProfileMobileNo($userProfile->getMobileNumberObj()->getCombinedNumber());
                    }
                    $request->setUserProfileName($userProfile->getName());
                }
            }
            $desc->add('SLIDE Transfer Number', $request->getTransactionNo());

        }

        if ($request->getOption() != NULL) {
            $option_array = $request->getOption()->toArray();
            if ($option_array != NULL) {
                if (array_key_exists('transfer_reference_number', $option_array)) {
                    $desc->add('Transfer Ref No.', $option_array['transfer_reference_number']);
                }
                if (array_key_exists('bank_name', $option_array)) {
                    $desc->add('From Bank', $option_array['bank_name']);
                }
                if (array_key_exists('to_bank_name', $option_array)) {
                    $desc->add('To SLIDE Bank Acc', $option_array['to_bank_name']);
                }
                if (array_key_exists('date_of_transfer', $option_array)) {
                    $desc->add('Date of Transfer', $option_array['date_of_transfer']);
                }
            }
        }

        $request->setDetail1($desc);

        return true;
    }


    protected function _requestAction(PaymentRequest $request)
    {
        $option_array = $request->getOption()->toArray();
        if(array_key_exists('transfer_reference_number', $option_array)) {
            $request->setReferenceID($option_array['transfer_reference_number']);
        }
        if(array_key_exists('receipt_reference_image_name', $option_array)) {
            $request->setReceiptReferenceImageUrl($option_array['receipt_reference_image_name']);
        }

        //temp set to ibanking if not passed
        if (!array_key_exists('payment_mode_request_type', $option_array)) {
            $option_array['payment_mode_request_type'] = 'ibanking';
            $request->getOption()->setArray($option_array);
        }

        if($this->_updatePaymentModeType($request)) {
            return true;
        }

        return false;
    }

    protected function _updatePaymentModeType(PaymentRequest $request)
    {
        $systemcode_serv = SystemCodeServiceFactory::build();
        $option_array = $request->getOption()->toArray();
        if(array_key_exists('payment_mode_request_type', $option_array)) {
            if( $code = $systemcode_serv->getByCode($option_array['payment_mode_request_type'], PaymentModeRequestType::getSystemGroupCode()) ) {
                $request->setPaymentModeRequestType($code);
                return true;
            }
        }

        return false;
    }

    protected function _publishQueue(PaymentRequest $request)
    {
        PaymentEventProducer::publishPaymentRequestInitiated($request->getModuleCode(), $request->getTransactionID(), $request->getId());
    }

    public function updateRequestFirstCheck($payment_request_id, $status, $remarks = NULL)
    {
        $paymentRequest = new PaymentRequest();
        if ($paymentRequest = $this->getRepository()->findById($payment_request_id)) {
            if($paymentRequest instanceof PaymentRequest) {
                $oriPaymentRequest = clone($paymentRequest);
                if ($paymentRequest->getFirstCheckStatus() == NULL && $paymentRequest->getStatus() == PaymentStatus::PENDING) {
                    if ($status == PaymentRequestCheckStatus::APPROVE || $status == PaymentRequestCheckStatus::REJECT) {
                        $paymentRequest->setFirstCheckStatus($status);
                        $paymentRequest->setFirstCheckBy($this->getUpdatedBy());
                        if ($remarks != NULL) {
                            $paymentRequest->setFirstCheckRemarks($remarks);
                        }

                        $this->getRepository()->startDBTransaction();
                        if ($updatedPaymentRequest = $this->_updatePaymentRequestFirstCheck($paymentRequest, $oriPaymentRequest)) {
                            $commit_trans = FALSE;
                            if ($status == PaymentRequestCheckStatus::APPROVE) {
                                //call complete
                                if (parent::complete($paymentRequest->getUserProfileId(), $payment_request_id, $paymentRequest->getPaymentCode(), array())) {
                                    $commit_trans = TRUE;
                                }
                            } else if ($status == PaymentRequestCheckStatus::REJECT) {
                                //call cancel
                                if (parent::cancel($paymentRequest->getUserProfileId(), $payment_request_id, $paymentRequest->getPaymentCode())) {
                                    $commit_trans = TRUE;
                                }
                            }

                            if ($commit_trans) {
                                $this->getRepository()->completeDBTransaction();
                                $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_CHECK_UPDATE_SUCCESS);

                                PaymentEventProducer::publishPaymentRequestChanged($paymentRequest->getModuleCode(), $paymentRequest->getTransactionID());

                                return true;
                            }
                        }

                        $this->getRepository()->rollbackDBTransaction();
                    } else {
                        $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_CHECK_UPDATE_INVALID_STATUS);
                    }
                } else {
                    $this->setResponseCode(MessageCode::CODE_REQUEST_NOT_FOUND);
                }
            }
        }
        else
        {
            $this->setResponseCode(MessageCode::CODE_REQUEST_NOT_FOUND);
        }

        if( $this->getResponseCode() == NULL )
            $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_CHECK_UPDATE_FAIL);

        return false;
    }

    protected function _updatePaymentRequestFirstCheck(PaymentRequest $request, PaymentRequest $ori_request)
    {
        $request->setUpdatedBy($this->getUpdatedBy());
        if( $this->getRepository()->updateFirstCheck($request) )
        {
            //fire log
            $this->fireLogEvent('iafb_payment.payment_request', AuditLogAction::UPDATE, $request->getId(), $ori_request);

            return $request;
        }

        return false;
    }

}