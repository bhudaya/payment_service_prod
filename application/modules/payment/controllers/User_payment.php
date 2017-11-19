<?php

use Iapps\PaymentService\PaymentRequest\PaymentRequestServiceFactory;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IpAddress;
use Iapps\Common\Microservice\AccountService\SessionType;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Payment\PaymentService;
use Iapps\PaymentService\Payment\PaymentRepository;
use Iapps\PaymentService\Payment\Payment;
use Iapps\PaymentService\Payment\PaymentUserType;
use Iapps\PaymentService\PaymentRequest\PaymentRequestStaticChannel;


class User_payment extends User_Base_Controller{

    function __construct()
    {

        parent::__construct();
        $this->load->model('payment/Payment_model');

        $repo = new PaymentRepository($this->Payment_model);
        $this->_service = new PaymentService($repo);
        $this->_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
    }

    public function request()
    {
        if( !$user_id = $this->_getUserProfileId(NULL, NULL, SessionType::TRANSACTION) )
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

        $payment_code = $this->input->post('payment_code');
        $country_currency_code = $this->input->post('country_currency_code');
        $amount = $this->input->post('amount');
        $module_code = $this->input->post('module_code');
        $transactionID = $this->input->post('transactionID');
        $option = $this->input->post('option') ? json_decode($this->input->post('option'), true) : array();

        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($user_id);
            $payment_service->setAdminAccessToken($this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION));
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
            if( $result = $payment_service->request($user_id,
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
        if( !$user_id = $this->_getUserProfileId(NULL, NULL, SessionType::TRANSACTION) )
            return false;

        if( !$this->is_required($this->input->post(), array(
                                                        'payment_request_id',
                                                        'payment_code')) )
        {
            return false;
        }

        $payment_code = $this->input->post('payment_code');
        $payment_request_id = $this->input->post('payment_request_id');
        $response = $this->input->post('response') ? json_decode($this->input->post('response'), true) : array();


        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($user_id);
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
            $payment_service->setAdminAccessToken($this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION));

            if( $result = $payment_service->complete($user_id, $payment_request_id, $payment_code, $response) )
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
        if( !$user_id = $this->_getUserProfileId(NULL, NULL, SessionType::TRANSACTION) )
            return false;

        if( !$this->is_required($this->input->post(), array(
            'payment_request_id',
            'payment_code')) )
        {
            return false;
        }

        $payment_code = $this->input->post('payment_code');
        $payment_request_id = $this->input->post('payment_request_id');

        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($user_id);
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
            $payment_service->setAdminAccessToken($this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION));

            if( $payment_service->cancel($user_id, $payment_request_id, $payment_code) )
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
        if( !$user_id = $this->_getUserProfileId(NULL, NULL, SessionType::TRANSACTION) )
            return false;

        if( !$this->is_required($this->input->post(), array('payment_code',
                                                            'country_currency_code',
                                                            'amount',
                                                            'module_code',
                                                            'transactionID')) )
        {
            return false;
        }

        $payment_code = $this->input->post('payment_code');
        $country_currency_code = $this->input->post('country_currency_code');
        $amount = $this->input->post('amount');
        $module_code = $this->input->post('module_code');
        $transactionID = $this->input->post('transactionID');
        $option = $this->input->post('option') ? json_decode($this->input->post('option'), true) : array();

        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($user_id);
            $payment_service->setAdminAccessToken($this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION));
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
            if( $result = $payment_service->make($user_id,
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

//user app
    public function getPaymentByUserId()
    {
        if( !$user_id = $this->_getUserProfileId() )
            return false;


        $limit = $this->input->get("limit");
        $page = $this->input->get("page");

        $user_profile_id = $user_id;
        $payment = new \Iapps\PaymentService\Payment\Payment();
        $payment->setUserProfileId($user_profile_id);

        $include_cancelled = $this->input->get('include_cancelled') ? $this->input->get('include_cancelled') : 'false';
        if( $include_cancelled == 'true' )
            $include_cancelled = true;
        else
            $include_cancelled = false;

        $date_from= $this->input->get('date_from') ? $this->input->get('date_from') : NULL;
        if ($date_from){
            $payment->setDateFrom(IappsDateTime::fromString($date_from. ' 00:00:00' ));
        }
        $date_to= $this->input->get('date_to') ? $this->input->get('date_to') : NULL;
        if ($date_to){
            $payment->setDateTo(IappsDateTime::fromString($date_to. ' 23:59:59' ));
        }
        $module_code= $this->input->get('module_code') ? $this->input->get('module_code') : NULL;
        if($module_code){
            $payment->setModuleCode($module_code);
        }
        $payment_code = $this->input->get('payment_code') ? $this->input->get('payment_code'):NULL;
        if($payment_code){
            $payment->setPaymentCode($payment_code);
        }
        $transactionID = $this->input->get('transactionID') ? $this->input->get('transactionID'):NULL;
        if($transactionID){
            $payment->setTransactionID($transactionID);
        }
//        $payment->setChannelCode(PaymentRequestStaticChannel::$channelCode);
//        $payment->setChannelID(PaymentRequestStaticChannel::$channelID);

        $payment->setUserType(PaymentUserType::USER);

        if( $object = $this->_service->getPaymentByParam($payment,$limit,$page, $include_cancelled) )
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object->result->toArray(), 'total' => $object->total));

            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;


    }

    public function checkAccount(){

        if( !$user_id = $this->_getUserProfileId(NULL, NULL, SessionType::TRANSACTION) )
            return false;

        $payment_code = $this->input->post('payment_code');
        $bank_code = $this->input->post('bank_code');
        $account_number = $this->input->post('account_number');
        $acc_holder_name = $this->input->post('account_holder_name');
        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            if($result = $payment_service->checkAccount($bank_code,$account_number,$acc_holder_name) )
            {
                $this->_respondWithSuccessCode($payment_service->getResponseCode(), array('result' => $result));
                return true;
            }
            $this->_respondWithCode($payment_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND, NULL, NULL, $payment_service->getResponseMessage());
            return false;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
}
