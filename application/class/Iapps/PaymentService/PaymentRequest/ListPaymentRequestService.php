<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\ArrayExtractor;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\Helper\RequestHeader;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Core\IappsBaseEntityCollection;
use Iapps\Common\Microservice\AccountService\User;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Common\ModuleCode;
use Iapps\Common\Microservice\EwalletService\EwalletTransactionServiceFactory;
use Iapps\Common\Microservice\EwalletService\EwalletClient;
use Iapps\Common\Microservice\EwalletService\EwalletTransactionCollection;
use Iapps\PaymentService\Common\SystemCodeServiceFactory;

class ListPaymentRequestService extends PaymentRequestService{



    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);
    }

    public function getPaymentRequestBySearchFilter(PaymentRequest $paymentRequest, $limit, $page)
    {
        $user_profile_id_search_arr = NULL;

        $account_serv = AccountServiceFactory::build();
        if($paymentRequest->getUserProfileAccountID() != NULL || $paymentRequest->getUserProfileFullName() != NULL || $paymentRequest->getUserProfileMobileNo() != NULL) {
            $user = new User();
            $user->setAccountID($paymentRequest->getUserProfileAccountID());
            $user->setFullName($paymentRequest->getUserProfileFullName());
            $user->getMobileNumberObj()->setMobileNumber($paymentRequest->getUserProfileMobileNo());

            $userProfileSearchColl = new IappsBaseEntityCollection();
            if($userProfileSearchColl = $account_serv->adminSearchUser($user)) {

                foreach($userProfileSearchColl as $userProfileSearchEach) {
                    $user_profile_id_search_arr[] = $userProfileSearchEach->getId();
                }

            }
        }

        if($paymentRequest->getPaymentModeRequestType()) {
            if ($paymentRequest->getPaymentModeRequestType()->getCode() != NULL) {
                $this->_updatePaymentModeType($paymentRequest);
            }
        }

        if ($paymentRequestColl = $this->getRepository()->findBySearchFilter($paymentRequest, $user_profile_id_search_arr,  $limit, $page)) {
            $user_profile_id_arr = array();
            $ewallet_transactionID_arr = array();
            foreach($paymentRequestColl->result as $paymentRequestEach)
            {
                $user_profile_id_arr[] = $paymentRequestEach->getUserProfileId();
                $user_profile_id_arr[] = $paymentRequestEach->getFirstCheckBy();
                if($paymentRequestEach->getModuleCode() == ModuleCode::EWALLET_MODULE_CODE) {
                    $ewallet_transactionID_arr[] = $paymentRequestEach->getTransactionID();
                }
            }

            $ewalletTransColl = new EwalletTransactionCollection();
            if(count($ewallet_transactionID_arr) > 0) {
                $ewalletserv = EwalletTransactionServiceFactory::build(EwalletClient::ADMIN);
                $ewalletTransColl = $ewalletserv->getTransactionListForUserByIdArr($ewallet_transactionID_arr, NULL);
            }

            $userProfileColl = new IappsBaseEntityCollection();
            if(count($user_profile_id_arr) > 0) {
                $userProfileColl = $account_serv->getUsers($user_profile_id_arr);
            }

            $option_array = array();
            if($userProfileColl->count() > 0 || $ewalletTransColl != NULL)
            {
                foreach($paymentRequestColl->result as $paymentRequestEach)
                {
                    if($paymentRequestEach->getOption() != NULL) {
                        $option_array = $paymentRequestEach->getOption()->toArray();
                        if (array_key_exists('bank_name', $option_array)) {
                            $paymentRequestEach->setBankName($option_array['bank_name']);
                        }
                        if (array_key_exists('transfer_reference_number', $option_array)) {
                            $paymentRequestEach->setTransferReferenceNumber($option_array['transfer_reference_number']);
                        }
                        if (array_key_exists('date_of_transfer', $option_array)) {
                            $paymentRequestEach->setDateOfTransfer($option_array['date_of_transfer']);
                        }
                        if (array_key_exists('to_bank_name', $option_array)) {
                            $paymentRequestEach->setToBankName($option_array['to_bank_name']);
                        }
                    }

                    foreach($userProfileColl as $userProfileEach)
                    {
                        if($paymentRequestEach->getUserProfileId() == $userProfileEach->getId()) {
                            $paymentRequestEach->setUserProfileAccountID($userProfileEach->getAccountID());
                            $paymentRequestEach->setUserProfileMobileNo($userProfileEach->getMobileNumberObj()->getCombinedNumber());
                            $paymentRequestEach->setUserProfileName($userProfileEach->getName());
                            $paymentRequestEach->setUserProfileFullName($userProfileEach->getFullName());
                        }
                        if($paymentRequestEach->getFirstCheckBy() == $userProfileEach->getId()) {
                            $paymentRequestEach->setFirstCheckByAccountID($userProfileEach->getAccountID());
                            $paymentRequestEach->setFirstCheckByName($userProfileEach->getName());
                        }
                    }

                    if($ewalletTransColl != NULL) {
                        foreach ($ewalletTransColl->result as $ewalletTransEach) {
                            if ($paymentRequestEach->getTransactionID() == $ewalletTransEach->getTransactionID()) {
                                //set transaction type desc
                                $paymentRequestEach->setTransactionTypeDesc($ewalletTransEach->getTransactionType()->getDescription());
                            }
                        }
                    }
                }
            }

            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_REQUEST_LIST_SUCCESS);
            return $paymentRequestColl;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_REQUEST_LIST_FAILED);
        return false;
    }

    public function getPaymentRequestInfo($payment_request_id)
    {
        if ($paymentRequest = $this->getRepository()->findById($payment_request_id)) {
            if($paymentRequest->getOption() != NULL) {
                $option_array = $paymentRequest->getOption()->toArray();
                if (array_key_exists('bank_name', $option_array)) {
                    $paymentRequest->setBankName($option_array['bank_name']);
                }
                if (array_key_exists('transfer_reference_number', $option_array)) {
                    $paymentRequest->setTransferReferenceNumber($option_array['transfer_reference_number']);
                }
                if (array_key_exists('date_of_transfer', $option_array)) {
                    $paymentRequest->setDateOfTransfer($option_array['date_of_transfer']);
                }
                if (array_key_exists('to_bank_name', $option_array)) {
                    $paymentRequest->setToBankName($option_array['to_bank_name']);
                }
            }

            $acc_serv = AccountServiceFactory::build();
            if($userProfile = $acc_serv->getUserProfile($paymentRequest->getUserProfileId())) {
                if($userProfile instanceof User) {
                    if ($userProfile->getMobileNumberObj() != NULL) {
                        $paymentRequest->setUserProfileMobileNo($userProfile->getMobileNumberObj()->getCombinedNumber());
                    }
                    $paymentRequest->setUserProfileName($userProfile->getName());
                }
            }

            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_REQUEST_LIST_SUCCESS);
            return $paymentRequest;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_REQUEST_LIST_FAILED);
        return false;
    }

    protected function _updatePaymentModeType(PaymentRequest $request)
    {
        $systemcode_serv = SystemCodeServiceFactory::build();

        if ($code = $systemcode_serv->getByCode($request->getPaymentModeRequestType()->getCode(), PaymentModeRequestType::getSystemGroupCode())) {
            $request->setPaymentModeRequestType($code);
            return true;
        }

        return false;
    }
}