<?php

use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;
use Iapps\Common\Core\IpAddress;

class Payment_mode_attribute_agent extends Agent_Base_Controller{

    protected $_attr_serv;

    function __construct()
    {
        parent::__construct();

        $this->_attr_serv = PaymentModeAttributeServiceFactory::build();
        $this->_attr_serv->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
        
        $this->_service_audit_log->setTableName('iafb_payment.payment_mode_attribute');
    }

    //override
    protected function _get_admin_id($function = NULL, $access_type = NULL)
    {
        return $this->_getUserProfileId(FunctionCode::AGENT_FUNCTIONS, AccessType::WRITE);
    }

    public function getPaymentModeAttribute()
    {
        if( !$adminId = $this->_get_admin_id() )
            return false;

        $this->_attr_serv->setUpdatedBy($adminId);

        if( !$this->is_required($this->input->get(), array('payment_code')) )
            return false;

        $payment_code = $this->input->get('payment_code');
        $country_code = $this->input->get('country_code');

        if( $result = $this->_attr_serv->getAttributesByPaymentCode($payment_code, $country_code) )
        {
            $this->_respondWithSuccessCode($this->_attr_serv->getResponseCode(), array('result' => $result));
            return true;
        }

        $this->_respondWithCode($this->_attr_serv->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getAllByPaymentCode()
    {
        if( !$adminId = $this->_get_admin_id() )
            return false;

        if( !$this->is_required($this->input->get(), array('payment_code')) )
            return false;

        $payment_code = $this->input->get('payment_code');

        if( $result = $this->_attr_serv->getAllByPaymentCode($payment_code) )
        {
            $this->_respondWithSuccessCode($this->_attr_serv->getResponseCode(), array('result' => $result));
            return true;
        }

        $this->_respondWithCode($this->_attr_serv->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
}