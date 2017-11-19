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


class User_payment_request extends User_Base_Controller{

    function __construct()
    {
        parent::__construct();
        $this->load->model('paymentrequest/Payment_request_model');

        $this->_service_audit_log->setTableName('iafb_payment.payment_request');
    }


    public function getPaymentRequestList()
    {
        if( !$user_id = $this->_getUserProfileId() )
            return false;

        $limit = $this->_getLimit();
        $page = $this->_getPage();

        $paymentRequest = new PaymentRequest();
        $paymentRequest->setPaymentCode(PaymentModeType::BANK_TRANSFER_MANUAL);
        $paymentRequest->setUserProfileId($user_id);

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

}