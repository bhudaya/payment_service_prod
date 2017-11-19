<?php defined('BASEPATH') OR exit('No direct script access allowed');

use Iapps\PaymentService\CountryCurrencyPaymentMode\CountryCurrencyPaymentModeRepository;
use Iapps\PaymentService\CountryCurrencyPaymentMode\CountryCurrencyPaymentModeService;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Core\IappsDateTime;

class Country_currency_payment_mode extends Base_Controller {

    protected $_country_currency_payment_mode_service;
    function __construct()
    {
        parent::__construct();

        $this->load->model('countrycurrencypaymentmode/country_currency_payment_mode_model');
        $repo = new CountryCurrencyPaymentModeRepository($this->country_currency_payment_mode_model);
        $this->_country_currency_payment_mode_service = new CountryCurrencyPaymentModeService($repo);
        
        $this->_service_audit_log->setTableName('iafb_payment.country_currency_payment_mode');
    }

    public function getAllCountryCurrencyPaymentModes()
    {
        $limit = $this->input->get("limit");
        $page = $this->input->get("page");

        if( $object = $this->_country_currency_payment_mode_service->getCountryCurrencyPaymentModeList($limit, $page) )
        {//todo Pagination
            $this->_respondWithSuccessCode($this->_country_currency_payment_mode_service->getResponseCode(), array('result' => $object->result, 'total' => $object->total));
            return false;
        }

        $this->_respondWithCode($this->_country_currency_payment_mode_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getCountryCurrencyPaymentModeInfoByCountryCode()
    {
        if( !$this->is_required($this->input->get(), array('country_code')) )
        {
            return false;
        }

        $country_code = $this->input->get("country_code");

        if( $info = $this->_country_currency_payment_mode_service->getCountryCurrencyPaymentModeInfoByCountryCode($country_code) )
        {
            $this->_respondWithSuccessCode($this->_country_currency_payment_mode_service->getResponseCode(), array('result' => $info));
            return false;
        }

        $this->_respondWithCode($this->_country_currency_payment_mode_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function addCountryCurrencyPaymentMode()
    {
        if( !$this->is_required($this->input->post(), array('country_currency_code','payment_mode_code','effective_at','admin_id')) )
        {
            return false;
        }

        $country_currency_code = $this->input->post("country_currency_code");
        $payment_mode_code = $this->input->post("payment_mode_code");
        $effective_at = $this->input->post("effective_at");
        $admin_id = $this->input->post("admin_id");

        $country_currency_payment_mode = new \Iapps\PaymentService\CountryCurrencyPaymentMode\CountryCurrencyPaymentMode();
        $country_currency_payment_mode->setCountryCurrencyCode($country_currency_code);
        $country_currency_payment_mode->setPaymentModeCode($payment_mode_code);
        $country_currency_payment_mode->setEffectiveAt(IappsDateTime::fromString($effective_at));

        $this->_country_currency_payment_mode_service->setUpdatedBy($admin_id);
        if( $country_currency_payment_mode = $this->_country_currency_payment_mode_service->addCountryCurrencyPaymentMode($country_currency_payment_mode) )
        {
            $this->_respondWithSuccessCode($this->_country_currency_payment_mode_service->getResponseCode(), array('result' => $country_currency_payment_mode));
            return true;
        }

        $this->_respondWithCode($this->_country_currency_payment_mode_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function addCountryCurrencyPaymentModeBatch()
    {
        if( !$this->is_required($this->input->post(), array('country_currency_code','admin_id')) )
        {
            return false;
        }

        $is_list_valid = isset($_POST["payment_mode_list"]) && !empty($_POST["payment_mode_list"]) ? 
                            is_array($this->input->post("payment_mode_list")) ? 
                                count($this->input->post("payment_mode_list")) > 0 : 
                            false :
                        false;
        if( !$is_list_valid )
        {
            return false;
        }

        $country_currency_code = $this->input->post("country_currency_code");
        $payment_mode_list = $this->input->post("payment_mode_list");
        $admin_id = $this->input->post("admin_id");

        if( $this->_country_currency_payment_mode_service->addCountryCurrencyPaymentModeBatch($country_currency_code, $payment_mode_list, $admin_id) )
        {
            $this->_respondWithSuccessCode($this->_country_currency_payment_mode_service->getResponseCode());
            return true;
        }

        $this->_respondWithCode($this->_country_currency_payment_mode_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }
}