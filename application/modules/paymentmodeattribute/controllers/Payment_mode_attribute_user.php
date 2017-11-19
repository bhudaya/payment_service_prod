<?php

use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;
use Iapps\Common\Core\IpAddress;

class Payment_mode_attribute_user extends User_Base_Controller{

    protected $_attr_serv;

    function __construct()
    {
        parent::__construct();

        $this->_attr_serv = PaymentModeAttributeServiceFactory::build();
        $this->_attr_serv->setIpAddress(IpAddress::fromString($this->_getIpAddress()));
        
        $this->_service_audit_log->setTableName('iafb_payment.payment_mode_attribute');
    }

    public function getPaymentModeAttribute()
    {
        if( !$user_id = $this->_getUserProfileId() )
            return false;

        $this->_attr_serv->setUpdatedBy($user_id);

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
        if( !$user_id = $this->_getUserProfileId() )
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

    public function getCollectionOption()
    {
        if( !$user_id = $this->_getUserProfileId() )
            return false;

        if( $result = $this->_attr_serv->getCollectionOption() )
        {
            $this->_respondWithSuccessCode($this->_attr_serv->getResponseCode(), array('result' => $result));
            return true;
        }

        $this->_respondWithCode($this->_attr_serv->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

}