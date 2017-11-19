<?php

use Iapps\PaymentService\PaymentRequest\PaymentRequestServiceFactory;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\Common\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IpAddress;
use Iapps\Common\Microservice\AccountService\SessionType;
use Iapps\PaymentService\Payment\PaymentRepository;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Payment\PaymentService;
use Iapps\PaymentService\Payment\Payment;

class Partner_payment extends Partner_Base_Controller{

    function __construct()
    {
        parent::__construct();
        $this->load->model('payment/Payment_model');
    }

    public function request()
    {
        if( !$admin_id = $this->_getUserProfileId(FunctionCode::PARTNER_PAYMENT) )
            return false;

        if( !$this->is_required($this->input->post(), array(
            'payment_code',
            'country_currency_code',
            'amount',
            'module_code',
            'transactionID')) )
        {
            return false;
        }

        $user_profile_id = $this->input->post('user_profile_id') ? $this->input->post('user_profile_id') : NULL;
        $payment_code = $this->input->post('payment_code');
        $country_currency_code = $this->input->post('country_currency_code');
        $amount = $this->input->post('amount');
        $module_code = $this->input->post('module_code');
        $transactionID = $this->input->post('transactionID');
        $option = $this->input->post('option') ? json_decode($this->input->post('option'), true) : array();

        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($admin_id);
            $payment_service->setAdminAccessToken($this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION));
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
            if( $result = $payment_service->request($user_profile_id,
                $module_code, $transactionID,
                $country_currency_code, $amount, $option) )
            {
                $this->_respondWithSuccessCode($payment_service->getResponseCode(), array('result' => $result));
                return true;
            }

            $this->_respondWithCode($payment_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND, NULL, NULL, $payment_service->getResponseMessage());
            return false;
        }


        $this->_respondWithCode(MessageCode::CODE_COUNTRY_CURRENCY_INVALID_PAYMENT_MODE, ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function complete()
    {
        if( !$admin_id = $this->_getUserProfileId(FunctionCode::PARTNER_PAYMENT) )
            return false;

        if( !$this->is_required($this->input->post(), array(
            'payment_request_id',
            'payment_code')) )
        {
            return false;
        }

        $user_profile_id = $this->input->post('user_profile_id') ? $this->input->post('user_profile_id') : NULL;
        $payment_code = $this->input->post('payment_code');
        $payment_request_id = $this->input->post('payment_request_id');
        $response = $this->input->post('response') ? json_decode($this->input->post('response'), true) : array();


        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($admin_id);
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
            $payment_service->setAdminAccessToken($this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION));

            if( $result = $payment_service->complete($user_profile_id, $payment_request_id, $payment_code, $response) )
            {
                $this->_respondWithSuccessCode($payment_service->getResponseCode(), array('result' => $result));
                return true;
            }

            $this->_respondWithCode($payment_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND, NULL, NULL, $payment_service->getResponseMessage());
            return false;
        }

        $this->_respondWithCode(MessageCode::CODE_COUNTRY_CURRENCY_INVALID_PAYMENT_MODE, ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function cancel()
    {
        if( !$admin_id = $this->_getUserProfileId(FunctionCode::PARTNER_PAYMENT) )
            return false;

        if( !$this->is_required($this->input->post(), array(
            'payment_request_id',
            'payment_code')) )
        {
            return false;
        }

        $user_profile_id = $this->input->post('user_profile_id') ? $this->input->post('user_profile_id') : NULL;
        $payment_code = $this->input->post('payment_code');
        $payment_request_id = $this->input->post('payment_request_id');


        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($admin_id);
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
            $payment_service->setAdminAccessToken($this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION));

            if( $payment_service->cancel($user_profile_id, $payment_request_id, $payment_code) )
            {
                $this->_respondWithSuccessCode($payment_service->getResponseCode());
                return true;
            }

            $this->_respondWithCode($payment_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND, NULL, NULL, $payment_service->getResponseMessage());
            return false;
        }

        $this->_respondWithCode(MessageCode::CODE_COUNTRY_CURRENCY_INVALID_PAYMENT_MODE, ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function makePayment()
    {
        if( !$admin_id = $this->_getUserProfileId(FunctionCode::PARTNER_PAYMENT) )
            return false;

        if( !$this->is_required($this->input->post(), array('payment_code',
            'country_currency_code',
            'amount',
            'module_code',
            'transactionID')) )
        {
            return false;
        }

        $user_profile_id = $this->input->post('user_profile_id') ? $this->input->post('user_profile_id') : NULL;
        $payment_code = $this->input->post('payment_code');
        $country_currency_code = $this->input->post('country_currency_code');
        $amount = $this->input->post('amount');
        $module_code = $this->input->post('module_code');
        $transactionID = $this->input->post('transactionID');
        $option = $this->input->post('option') ? json_decode($this->input->post('option'), true) : array();

        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($admin_id);
            $payment_service->setAdminAccessToken($this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION));
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
            if( $result = $payment_service->make($user_profile_id,
                $module_code, $transactionID,
                $country_currency_code, $amount, $option) )
            {
                $this->_respondWithSuccessCode($payment_service->getResponseCode(), array('result' => $result));
                return true;
            }

            $this->_respondWithCode($payment_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND, NULL, NULL, $payment_service->getResponseMessage());
            return false;
        }


        $this->_respondWithCode(MessageCode::CODE_COUNTRY_CURRENCY_INVALID_PAYMENT_MODE, ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getPaymentByCreatorArrAndSearchFilter()
    {
        if( !$agent_id = $this->_getUserProfileId(FunctionCode::PARTNER_LIST_TRANSACTION_FOR_OTHERS, AccessType::READ) )
            return false;

        //TODO check if the log in partner admin is upline of the agent

        if( !$this->is_required($this->input->post(), array('created_by_arr', 'limit', 'page')) )
        {
            return false;
        }

        $limit = $this->input->post("limit");
        $page = $this->input->post("page");

        $created_by_arr = $this->input->post("created_by_arr");
        if(!is_array($created_by_arr))
        {
            return false;
        }
        $date_from = $this->input->post('date_from') ? IappsDateTime::fromString($this->input->post('date_from') . ' 00:00:00') : NULL;
        $date_to = $this->input->post('date_to') ? IappsDateTime::fromString($this->input->post('date_to') . ' 23:59:59' ) : NULL;
        $transactionID = $this->input->post('transactionID') ? $this->input->post('transactionID') : NULL;
        $module_code = $this->input->post('module_code') ? $this->input->post('module_code') : NULL;
        $payment_code = $this->input->post('payment_code') ? $this->input->post('payment_code') : NULL;
        $payment_user_type = $this->input->post('payment_user_type') ? $this->input->post('payment_user_type') : NULL;

        $payment = new Payment();
        if($transactionID != NULL) {
            $payment->setTransactionID($transactionID);
        }
        if($module_code != NULL) {
            $payment->setModuleCode($module_code);
        }
        if($payment_code != NULL) {
            $payment->setPaymentCode($payment_code);
        }
        if($payment_user_type != NULL) {
            $payment->setUserType($payment_user_type);
        }

        $repo = new PaymentRepository($this->Payment_model);
        $this->_service = new PaymentService($repo);

        if( $object = $this->_service->getPaymentCreatorAndSearchFilter($payment, $created_by_arr, $limit, $page, $date_from, $date_to) )
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object->result->toArray(), 'total' => $object->total));

            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
}