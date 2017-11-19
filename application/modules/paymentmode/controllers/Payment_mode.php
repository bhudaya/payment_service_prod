<?php defined('BASEPATH') OR exit('No direct script access allowed');

use Iapps\PaymentService\PaymentMode\PaymentModeRepository;
use Iapps\PaymentService\PaymentMode\PaymentModeService;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\PaymentMode\PaymentMode;

class Payment_Mode extends Base_Controller {

    protected $_payment_mode_service;
    function __construct()
    {
        parent::__construct();

        $this->load->model('paymentmode/payment_mode_model');
        $repo = new PaymentModeRepository($this->payment_mode_model);
        $this->_payment_mode_service = new PaymentModeService($repo);
        
        $this->_service_audit_log->setTableName('iafb_payment.payment_mode');
    }

    public function getAllPaymentModes()
    {
        if( !$userId = $this->_getUserProfileId() )
            return false;

        $limit = $this->input->post_get('limit') ? $this->input->post_get('limit') : MAX_VALUE;
        $page = $this->_getPage();
        if( $is_collection = $this->input->get_post("is_collection") )
        {
            if( $is_collection == 'true' )
                $is_collection = true;
            else
                $is_collection = false;
        }
        if( $is_payment = $this->input->get_post("is_payment") )
        {
            if( $is_payment == 'true' )
                $is_payment = true;
            else
                $is_payment = false;
        }
        $attribute_values = $this->input->get_post("attribute_value") ? json_decode($this->input->get_post("attribute_value"), true) : NULL;
        $attributeCol = NULL;
        if( $attribute_values )
        {//map to attribute collection
            $attributeCol = new \Iapps\PaymentService\Attribute\AttributeCollection();
            foreach($attribute_values AS $attribute_value)
            {
                $attribute = new \Iapps\PaymentService\Attribute\Attribute();
                if( isset($attribute_value['attribute']) )
                    $attribute->setCode($attribute_value['attribute']);
                if( isset($attribute_value['value']) )
                {
                    foreach($attribute_value['value'] AS $value)
                    {
                        $attributeValue = new \Iapps\PaymentService\Attribute\AttributeValue();
                        $attributeValue->setCode($value);
                        $attribute->getAttributeValues()->addData($attributeValue);
                    }
                }
                $attributeCol->addData($attribute);
            }
        }

        $delivery_codes = $this->input->get_post("delivery_time") ? json_decode($this->input->get_post("delivery_time"), true) : NULL;
        $group_codes = $this->input->get_post("group_code") ? json_decode($this->input->get_post("group_code"), true) : NULL;

        if( $object = $this->_payment_mode_service->getPaymentModeList($limit, $page, $is_collection, $is_payment, $attributeCol, $delivery_codes, $group_codes, true) )
        {
            $this->_respondWithSuccessCode($this->_payment_mode_service->getResponseCode(), array('result' => $object->result, 'total' => $object->total));
            return false;
        }

        $this->_respondWithCode($this->_payment_mode_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getPaymentModeInfo()
    {
        if( !$this->is_required($this->input->get(), array('code')) )
        {
            return false;
        }

        $code = $this->input->get("code");

        if( $info = $this->_payment_mode_service->getPaymentModeInfo($code) )
        {
            $this->_respondWithSuccessCode($this->_payment_mode_service->getResponseCode(), array('result' => $info));
            return false;
        }

        $this->_respondWithCode($this->_payment_mode_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getPaymentModesForRefund()
    {
        $paymentMode = new PaymentMode();
        $paymentMode->setForRefund((int)true);

        if( $object = $this->_payment_mode_service->getPaymentModeByParam($paymentMode) )
        {
            $this->_respondWithSuccessCode($this->_payment_mode_service->getResponseCode(), array('result' => $object->result, 'total' => $object->total));
            return false;
        }

        $this->_respondWithCode($this->_payment_mode_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }


    public function getSupportedPaymentMode()
    {
        if(!$admin_id = $this->_getAdminId())
        {
            return FALSE;
        }

        if( !$this->is_required($this->input->get(), array('direction')) )
        {
            return false;
        }

        $access_token = $this->input->get_request_header(ResponseHeader::FIELD_X_AUTHORIZATION);
        $direction = $this->input->get("direction");

        if( $info = $this->_payment_mode_service->getSupportedPaymentModeByFunction($access_token, $direction) )
        {
            $this->_respondWithSuccessCode($this->_payment_mode_service->getResponseCode(), array('result' => $info));
            return false;
        }

        $this->_respondWithCode($this->_payment_mode_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getAgentSupportedPaymentMode()
    {
        //if(!$user_id = $this->_getUserProfileId())
 //           return FALSE;

        if( !$this->is_required($this->input->get(), array('agent_id','direction')) )
        {
            return false;
        }

        $agent_id = $this->input->get("agent_id");
        $direction = $this->input->get("direction");

        if( $info = $this->_payment_mode_service->getSupportedPaymentModeByUserId($agent_id, $direction) )
        {
            $this->_respondWithSuccessCode($this->_payment_mode_service->getResponseCode(), array('result' => $info));
            return false;
        }

        $this->_respondWithCode($this->_payment_mode_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
}