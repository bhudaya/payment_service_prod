<?php


use Iapps\PaymentService\PaymentRequest\PaymentRequestServiceFactory;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\Common\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IpAddress;
use Iapps\Common\Microservice\AccountService\SessionType;
use Iapps\PaymentService\Payment\PaymentRepository;
use Iapps\PaymentService\Payment\Payment;
use Iapps\PaymentService\Payment\PaymentService;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Payment\PaymentUserType;
use Iapps\PaymentService\Common\ReceiptReferenceImageS3Uploader;
use Iapps\Common\Helper\GuidGenerator;

class User_self_payment extends User_Base_Controller{

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

    public function uploadReceiptRefereceImage()
    {
        if (!$user_id = $this->_getUserProfileId())
            return false;


        if (!$this->is_required($_FILES, array('receipt_reference_image'))) {
            return false;
        }

        $s3Image = new ReceiptReferenceImageS3Uploader(GuidGenerator::generate());
        if( $s3Image->uploadtoS3('receipt_reference_image') )
        {
            $this->_respondWithSuccessCode(MessageCode::CODE_UPLOAD_RECEIPT_REFERENCE_IMAGE_SUCCESS, array('result' => $s3Image->getFileName()));
            return true;
        }

        $this->_respondWithCode(MessageCode::CODE_UPLOAD_RECEIPT_REFERENCE_IMAGE_FAIL, ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

}