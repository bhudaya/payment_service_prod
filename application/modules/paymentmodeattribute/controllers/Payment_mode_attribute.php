<?php

use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeRepository;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeService;
use Iapps\Common\Helper\ResponseHeader;

class Payment_mode_attribute extends Base_Controller{

    protected $_attr_serv;
    function __construct()
    {
        parent::__construct();

        $this->load->model('paymentmodeattribute/Payment_mode_attribute_model');
        $repo = new PaymentModeAttributeRepository($this->Payment_mode_attribute_model);
        $this->_attr_serv = new PaymentModeAttributeService($repo, $this->_getIpAddress());

        $this->_service_audit_log->setTableName('iafb_payment.payment_mode_attribute');
    }

    public function getPaymentModeAttribute()
    {
        if( !$userId = $this->_getUserProfileId() )
            return false;

        $this->_attr_serv->setUpdatedBy($userId);

        if( !$this->is_required($this->input->get(), array('payment_code')) )
            return false;

        $payment_code = $this->input->get('payment_code');

        if( $result = $this->_attr_serv->getAttributesByPaymentCode($payment_code) )
        {
            $this->_respondWithSuccessCode($this->_attr_serv->getResponseCode(), array('result' => $result));
            return true;
        }

        $this->_respondWithCode($this->_attr_serv->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
    
    public function getAllBankNames(){
        if( $result = $this->_attr_serv->getAllBankNames())
        {
            $this->_respondWithSuccessCode($this->_attr_serv->getResponseCode(), array('result' => $result));
            return true;
        }

        $this->_respondWithCode($this->_attr_serv->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;        
    }
}