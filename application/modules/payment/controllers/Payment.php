<?php

use Iapps\PaymentService\PaymentRequest\PaymentRequestServiceFactory;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Core\IpAddress;
use Iapps\PaymentService\Payment\PaymentService;
use Iapps\PaymentService\Payment\PaymentRepository;
use Iapps\Common\Helper\InputValidator;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\PaymentOptionValidator\CollectionInfoValidatorFactory;
use Iapps\PaymentService\PaymentRequest\PaymentRequestClient;

class Payment extends Base_Controller{

    /*
     * todo add access token for system processing job!!!
     */
    function __construct()
    {
        parent::__construct();

        $this->_authoriseClient();

        $this->load->model('payment/Payment_model');
        
        $this->_service_audit_log->setTableName('iafb_payment.payment');

        $repo = new PaymentRepository($this->Payment_model);
        $this->_service = new PaymentService($repo);
        $this->_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));

    }

    public function request()
    {
        if( !$admin_id = $this->_getUserProfileId() )
            return false;

        if( !$this->is_required($this->input->post(), array('payment_code',
                                                            'country_currency_code',
                                                            //'amount',
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

        if($amount == NULL) {
            $errMsg = InputValidator::getInvalidParamMessage('amount');
            $this->_response(InputValidator::constructInvalidParamResponse($errMsg));
            return false;
        }

        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setPaymentRequestClient(PaymentRequestClient::SYSTEM);
            $payment_service->setUpdatedBy($admin_id);
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
        if( !$admin_id = $this->_getUserProfileId() )
            return false;

        if( !$this->is_required($this->input->post(), array('payment_request_id',
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
            $payment_service->setPaymentRequestClient(PaymentRequestClient::SYSTEM);
            $payment_service->setUpdatedBy($admin_id);
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));

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
        if( !$admin_id = $this->_getUserProfileId() )
            return false;

        if( !$this->is_required($this->input->post(), array(
            'payment_request_id',
            'payment_code')) )
        {
            return false;
        }

        $user_id = $this->input->post('user_profile_id') ? $this->input->post('user_profile_id') : NULL;
        $payment_code = $this->input->post('payment_code');
        $payment_request_id = $this->input->post('payment_request_id');


        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($admin_id);
            $payment_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
            $payment_service->setAdminAccessToken($this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION));
            $payment_service->setPaymentRequestClient(PaymentRequestClient::SYSTEM);

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
        if( !$this->is_required($this->input->post(), array('user_profile_id',
                                                            'payment_code',
                                                            'country_currency_code',
                                                            'amount',
                                                            'module_code',
                                                            'transactionID')) )
        {
            return false;
        }

        $user_profile_id = $this->input->post('user_profile_id');
        $admin_id = $user_profile_id;
        $payment_code = $this->input->post('payment_code');
        $country_currency_code = $this->input->post('country_currency_code');
        $amount = $this->input->post('amount');
        $module_code = $this->input->post('module_code');
        $transactionID = $this->input->post('transactionID');
        $option = $this->input->post('option') ? json_decode($this->input->post('option'), true) : array();

        if( $payment_service = PaymentRequestServiceFactory::build($payment_code))
        {
            $payment_service->setUpdatedBy($admin_id);
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

    public function convertUser()
    {
        if( !$admin_id = $this->_getUserProfileId() )
            return false;

        if( !$this->is_required($this->input->post(), array('user_profile_id',
                                                            'module_code',
                                                            'transactionID')) )
            return false;

        $module_code = $this->input->post('module_code');
        $transactionID = $this->input->post('transactionID');
        $user_profile_id = $this->input->post('user_profile_id');

        $this->_service->setUpdatedBy($admin_id);
        if( $this->_service->updateUserProfileId($module_code, $transactionID, $user_profile_id) )
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode());
            return false;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getPaymentByTransactionID()
    {
        if( !$user_profile_id = $this->_getUserProfileId(NULL, NULL, NULL) )
            return false;

        if( !$this->is_required($this->input->get(), array('transactionID')) )
        {
            return false;
        }

        $limit = $this->input->get("limit");
        $page = $this->input->get("page");

        $transactionID = $this->input->get("transactionID");
        $payment = new \Iapps\PaymentService\Payment\Payment();
        $payment->setTransactionID($transactionID);

        if( $object = $this->_service->getPaymentByParam($payment,$limit,$page) )
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object->result->toArray(), 'total' => $object->total));

            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;


    }

    public function getPaymentByTransactionIDArr()
    {
        if( !$user_profile_id = $this->_getUserProfileId(NULL, NULL, NULL) )
            return false;

        if( !$this->is_required($this->input->post(), array('transactionIDs', 'module_code')) )
        {
            return false;
        }

        $limit = $this->input->post("limit");
        $page = $this->input->post("page");

        $transactionIDs = $this->input->post("transactionIDs");
        $module_code = $this->input->post("module_code");

        if( $object = $this->_service->getByTransactionIDArr($module_code, $transactionIDs) )
        {
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object->result->toArray(), 'total' => $object->total));

            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;


    }

    public function getPaymentByPaymentCodeAndDate()
    {
        if( !$user_profile_id = $this->_getUserProfileId(NULL, NULL, NULL) )
            return false;

        if( !$this->is_required($this->input->post(), array('payment_code', 'date_from', 'date_to')) )
        {
            return false;
        }


        $payment = new \Iapps\PaymentService\Payment\Payment();

        $payment->setPaymentCode($this->input->post("payment_code"));

        if ($this->input->post("module_code")) {
            $payment->setModuleCode($this->input->post("module_code"));
        }

        $date_from = IappsDateTime::fromString($this->input->post('date_from'));
        $date_to = IappsDateTime::fromString($this->input->post('date_to'));

        if( $object = $this->_service->reportFindByParam($payment, $date_from, $date_to) )
        {   
            $this->_respondWithSuccessCode($this->_service->getResponseCode(),array('result' => $object->result, 'total' => $object->total));
            return true;
        }

        $this->_respondWithCode($this->_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function validateCollectionInfo()
    {
        if( !$user_profile_id = $this->_getUserProfileId(NULL, NULL, NULL) )
            return false;

        if( !$this->is_required($this->input->post(), array('option')) )
            return false;

        $payment_code = $this->input->post('payment_code') ? $this->input->post('payment_code') : NULL;
        $country_code = $this->input->post('country_code') ? $this->input->post('country_code') : NULL;
        $option = json_decode($this->input->post('option'), true) ? json_decode($this->input->post('option'), true) : array();

        $validator = CollectionInfoValidatorFactory::build($country_code);
        $validator->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
        $validator->setUpdatedBy($user_profile_id);
        if( $result = $validator->validate($payment_code, $country_code, $option) )
        {
            $this->_respondWithSuccessCode($validator->getResponseCode(), array('result' => $result));
            return true;
        }

        $this->_respondWithCode($validator->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND, NULL, NULL, $validator->getResponseMessage());
        return false;
    }
}