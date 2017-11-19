<?php defined('BASEPATH') OR exit('No direct script access allowed');

use Iapps\PaymentService\PaymentRequest\PaymentRequestRepository;
use Iapps\PaymentService\PaymentRequest\PaymentRequestReconciliationService;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;
use Iapps\PaymentService\PaymentRequest\SearchPaymentRequestServiceFactory;
use Iapps\Common\Core\IpAddress;

class Payment_request extends Base_Controller {

    protected $_payment_request_reconciliation_service;
    
    function __construct()
    {
        parent::__construct();
        $this->load->model('paymentrequest/payment_request_model');
        $repo = new PaymentRequestRepository($this->payment_request_model);
        $this->_payment_request_reconciliation_service = new PaymentRequestReconciliationService($repo);
        
        $this->_service_audit_log->setTableName('iafb_payment.payment_request');
    }
    
    public function reconciliationCompare()
    {
        if( !$this->is_required($this->input->post(), array('module_code','date')) )
        {
            return false;
        }
        
        $uploadFile = $this->upload('file');
        if($uploadFile == false || !empty($uploadFile['error']))
        {
//            var_dump($uploadFile['error']);
            
            $this->_payment_request_reconciliation_service->setResponseCode(MessageCode::CODE_RECONCILIATION_FAILED);
            $this->_respondWithCode($this->_payment_request_reconciliation_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND, array("error" => $uploadFile['error']));
            return false;
        }
        
        $module_code = $this->input->post("module_code");
        $date = $this->input->post('date');
        $file_path = $uploadFile['full_path'];
        
        if($result = $this->_payment_request_reconciliation_service->reconciliationCompare($module_code, $date, $file_path))
        {
            $this->_respondWithSuccessCode($this->_payment_request_reconciliation_service->getResponseCode());
            return true;
        }
        
        $this->_respondWithCode($this->_payment_request_reconciliation_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    //TODO: limit the access! This allows any user to search any transaction!
    public function getPaymentBySearchFilter()
    {
        if( !$user_profile_id = $this->_getUserProfileId(NULL, NULL, NULL) )
            return false;


        if( !$this->is_required($this->input->post(), array('module_code')) )
        {
            return false;
        }

        $paymentRequest = new PaymentRequest();

        if ($this->input->post("module_code")) {
            $paymentRequest->setModuleCode($this->input->post("module_code"));
        }


        if ($this->input->post("reference_id")) {
            $paymentRequest->setReferenceID($this->input->post("reference_id"));
        }

        if ($this->input->post("payment_code")) {
            $paymentRequest->setPaymentCode($this->input->post("payment_code"));
        }

        if ($this->input->post("transactionID")) {
            $paymentRequest->setTransactionID($this->input->post("transactionID"));
        }

        $limit = $this->input->post("limit");
        $page = $this->input->post("page");

        $_searchService = SearchPaymentRequestServiceFactory::build();
        $_searchService->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
        if( $object = $_searchService->getPaymentBySearchFilter($paymentRequest, $limit, $page) )
        {
            $this->_respondWithSuccessCode($_searchService->getResponseCode(),array('result' => $object->result->toArray(), 'total' => $object->total));

            return true;
        }

        $this->_respondWithCode($_searchService->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;


    }

    //TODO: limit the access! This allows any user to get detail of any transaction!
    public function getPaymentRequestByTransactionID()
    {
        if( !$user_profile_id = $this->_getUserProfileId(NULL, NULL, NULL) )
            return false;

        if( !$this->is_required($this->input->get(), array('transactionID')) )
        {
            return false;
        }

        $transactionID = $this->input->get("transactionID");
        $status = $this->input->get("status");

        $payment_request = new PaymentRequest();
        $payment_request->setTransactionID($transactionID);

        if($status){
            $payment_request->setStatus($status);
        }

        $_searchService = SearchPaymentRequestServiceFactory::build();
        $_searchService->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
        if( $object = $_searchService->getPaymentRequestByParam($payment_request)) {
            $this->_respondWithSuccessCode($_searchService->getResponseCode(), array('result' => $object->result->toArray()));
            return true;
        }
        $this->_respondWithCode($_searchService->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    //TODO: limit the access! This allows any user to search any transaction!
    public function getPaymentRequestByPaymentRequestID()
    {
        if( !$user_profile_id = $this->_getUserProfileId(NULL, NULL, NULL) )
            return false;

        if( !$this->is_required($this->input->post(), array('payment_request_id')) )
        {
            return false;
        }

        $payment_request_id = $this->input->post("payment_request_id");

        $_searchService = SearchPaymentRequestServiceFactory::build();
        $_searchService->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
        if( $object = $_searchService->getPaymentByPaymentRequestID($payment_request_id)) {
            $this->_respondWithSuccessCode($_searchService->getResponseCode(), array('result' => $object));
            return true;
        }
        $this->_respondWithCode($_searchService->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
}