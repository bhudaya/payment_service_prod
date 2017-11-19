<?php defined('BASEPATH') OR exit('No direct script access allowed');

use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\PaymentMode\PaymentModeLocation;
use Iapps\PaymentService\PaymentMode\PaymentModeLocationServiceFactory;

class Payment_Mode_Location extends Base_Controller
{
    protected $_payment_mode_location_service;

    function __construct()
    {
        parent::__construct();

        $this->_payment_mode_location_service = PaymentModeLocationServiceFactory::build();
        
        $this->_service_audit_log->setTableName('iafb_payment.payment_mode_location');
    }

    public function getSupportedLocation()
    {
        if( !$userId = $this->_getUserProfileId() )
            return false;

        if( !$this->is_required($this->input->get(), array('payment_code')) )
        {
            return false;
        }

        $payment_code = $this->input->get("payment_code");

        if( $info = $this->_payment_mode_location_service->getSupportedLocationByPaymentCode($payment_code) )
        {
            $this->_respondWithSuccessCode($this->_payment_mode_location_service->getResponseCode(), array('result' => $info));
            return false;
        }

        $this->_respondWithCode($this->_payment_mode_location_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
}