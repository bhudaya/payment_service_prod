<?php

use Iapps\PaymentService\PaymentRequest\PaymentRequestServiceFactory;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\Common\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IpAddress;
use Iapps\Common\Microservice\AccountService\SessionType;
use Iapps\PaymentService\PaymentRequest\PaymentRequestRepository;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;
use Iapps\PaymentService\PaymentRequest\ListPaymentRequestService;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\PaymentRequest\PaymentRequestStatus;
use Iapps\PaymentService\PaymentRequest\PaymentRequestCheckStatus;
use Iapps\Common\Helper\InputValidator;


class Admin_payment_request extends Admin_Base_Controller{

    function __construct()
    {
        parent::__construct();
        $this->load->model('paymentrequest/Payment_request_model');

        $this->_service_audit_log->setTableName('iafb_payment.payment_request');
    }


    public function getPaymentRequestListForFirstChecker()
    {
        if( !$admin_id = $this->_getUserProfileId(FunctionCode::ADMIN_LIST_MANUAL_BANK_TRANSFER_REQUEST_FIRST_CHECK, AccessType::READ) )
            return false;

        $limit = $this->_getLimit();
        $page = $this->_getPage();

        $country_code = $this->input->get('country_code');
        $transaction_no = $this->input->get('transaction_no');
        $payment_mode_request_type = $this->input->get('payment_mode_request_type');
        $transactionID = $this->input->get('transactionID');
        $accountID = $this->input->get('accountID');
        $full_name = $this->input->get('full_name');

        $paymentRequest = new PaymentRequest();
        $paymentRequest->setPaymentCode(PaymentModeType::BANK_TRANSFER_MANUAL);
        if($country_code != NULL)
        {
            $paymentRequest->setCountryCode($country_code);
        }
        if($transaction_no != NULL) {

            if(strlen($transaction_no) > 2) {

                $space = 0;
                if (strpos($transaction_no, ' ') > 0) {
                    $space = strpos($transaction_no, ' ');
                }

                $transaction_no_search = $transaction_no;
                if($space > 0) {
                    $transaction_no_search = substr($transaction_no, $space, strlen($transaction_no) - $space);
                }
                $paymentRequest->setUserProfileMobileNo($transaction_no_search);

            } else {
                $errMsg = InputValidator::getInvalidParamMessage('transaction_no');
                $this->_response(InputValidator::constructInvalidParamResponse($errMsg));
                return false;
            }

        }
        if($transactionID != NULL) {
            $paymentRequest->setTransactionID($transactionID);
        }
        if($payment_mode_request_type != NULL) {
            $paymentRequest->getPaymentModeRequestType()->setCode($payment_mode_request_type);
        }
        if($accountID != NULL) {
            $paymentRequest->setUserProfileAccountID($accountID);
        }
        if($full_name != NULL) {
            $paymentRequest->setUserProfileFullName($full_name);
        }
        //$paymentRequest->setStatus(PaymentRequestStatus::PENDING);

        $repo = new PaymentRequestRepository($this->Payment_request_model);
        $this->_list_serv = new ListPaymentRequestService($repo);
        $this->_list_serv->setIpAddress(IpAddress::fromString($this->_getIpAddress()));

        if( $object = $this->_list_serv->getPaymentRequestBySearchFilter($paymentRequest, $limit, $page))
        {
            $this->_respondWithSuccessCode($this->_list_serv->getResponseCode(),array('result' => $object->result->toArray(), 'total' => $object->total));

            return true;
        }

        $this->_respondWithCode($this->_list_serv->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }


    public function updatePaymentRequestForFirstCheckerResult()
    {
        if (!$admin_id = $this->_getUserProfileId(FunctionCode::ADMIN_MANUAL_BANK_TRANSFER_REQUEST_UPDATE_FIRST_CHECK, AccessType::WRITE) ) {
            return false;
        }

        if( !$this->is_required($this->input->post(), array('payment_request_id','status') ) )
            return false;

        $payment_request_id = $this->input->post('payment_request_id');
        $status = $this->input->post('status');
        $remarks = $this->input->post('remarks');

        $payment_request_serv = PaymentRequestServiceFactory::build(PaymentModeType::BANK_TRANSFER_MANUAL);
        $payment_request_serv->setUpdatedBy($admin_id);

        if( $payment_request_serv->updateRequestFirstCheck($payment_request_id, $status, $remarks) )
        {
            $this->_respondWithSuccessCode($payment_request_serv->getResponseCode());
            return true;
        }

        $this->_respondWithCode($payment_request_serv->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
}