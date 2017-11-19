<?php defined('BASEPATH') OR exit('No direct script access allowed');

use Iapps\PaymentService\CountryCurrency\CountryCurrencyRepository;
use Iapps\PaymentService\CountryCurrency\CountryCurrencyService;
use Iapps\PaymentService\CountryCurrencyPaymentMode\CountryCurrencyPaymentModeRepository;
use Iapps\PaymentService\CountryCurrencyPaymentMode\CountryCurrencyPaymentModeService;
use Iapps\PaymentService\Currency\CurrencyRepository;
use Iapps\PaymentService\Currency\CurrencyService;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Helper\ResponseHeader;

class Country_currency extends Base_Controller {

    protected $_country_currency_service;
    function __construct()
    {
        parent::__construct();

        $this->load->model('countrycurrency/country_currency_model');
        $repo = new CountryCurrencyRepository($this->country_currency_model);
        $this->_country_currency_service = new CountryCurrencyService($repo);

        $this->load->model('countrycurrencypaymentmode/country_currency_payment_mode_model');
        $repo2 = new CountryCurrencyPaymentModeRepository($this->country_currency_payment_mode_model);
        $this->_country_currency_payment_mode_service = new CountryCurrencyPaymentModeService($repo2);
        $this->_country_currency_service->addCountryCurrencyPaymentModeService($this->_country_currency_payment_mode_service);  

        $this->load->model('currency/currency_model');
        $repo3 = new CurrencyRepository($this->currency_model);
        $this->_currency_service = new CurrencyService($repo3);
        $this->_country_currency_service->addCurrencyService($this->_currency_service);  
        
        $this->_service_audit_log->setTableName('iafb_payment.country_currency');
    }

    public function getAllCountryCurrencies()
    {
        $limit = $this->input->get("limit");
        $page = $this->input->get("page");

        if( $object = $this->_country_currency_service->getCountryCurrencyList($limit, $page) )
        {
            $this->_respondWithSuccessCode($this->_country_currency_service->getResponseCode(), array('result' => $object->result, 'total' => $object->total));
            return false;
        }

        $this->_respondWithCode($this->_country_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getAllCountryCurrenciesByFromCountryCode()
    {
        $country_code = $this->input->get("country_code");

        if( $object = $this->_country_currency_service->getCurrencyInfoByCountryCode($country_code) )
        {
            $this->_respondWithSuccessCode($this->_country_currency_service->getResponseCode(), array('result' => $object->result, 'total' => $object->total));
            return false;
        }

        $this->_respondWithCode($this->_country_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getCountryCurrencyInfo()
    {
        if( !$this->is_required($this->input->get(), array('code')) )
        {
            return false;
        }

        $code = $this->input->get("code");

        if( $info = $this->_country_currency_service->getCountryCurrencyInfo($code) )
        {
            $this->_respondWithSuccessCode($this->_country_currency_service->getResponseCode(), array('result' => $info));
            return false;
        }

        $this->_respondWithCode($this->_country_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function addCountryCurrency()
    {
        if( !$this->is_required($this->input->post(), array('country_code','currency_code','admin_id')) )
        {
            return false;
        }

        $country_code = $this->input->post("country_code");
        $currency_code = $this->input->post("currency_code");
        $admin_id = $this->input->post("admin_id");

        $country_currency = new \Iapps\PaymentService\CountryCurrency\CountryCurrency();
        $country_currency->setCountryCode($country_code);
        $country_currency->setCurrencyCode($currency_code);

        $this->_country_currency_service->setUpdatedBy($admin_id);
        if( $country_currency = $this->_country_currency_service->addCountryCurrency($country_currency) )
        {
            $this->_respondWithSuccessCode($this->_country_currency_service->getResponseCode(), array('result' => $country_currency));
            return true;
        }

        $this->_respondWithCode($this->_country_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function addCountryCurrencyWithPaymentMode()
    {
        if( !$this->is_required($this->input->post(), array('country_code','admin_id')) )
        {
            return false;
        }

        $is_list_valid = isset($_POST["currency_list"]) && !empty($_POST["currency_list"]) ? 
                            is_array($this->input->post("currency_list")) ? 
                                count($this->input->post("currency_list")) > 0 : 
                            false :
                        false;

        if( !$is_list_valid )
        {
            return false;
        }

        $country_code = $this->input->post("country_code");
        $currency_list = $this->input->post("currency_list");
        $admin_id = $this->input->post("admin_id");

        if( $this->_country_currency_service->addCountryCurrencyWithPaymentMode($country_code, $currency_list, $admin_id ))
        {
            $this->_respondWithSuccessCode($this->_country_currency_service->getResponseCode());
            return true;
        }

        $this->_respondWithCode($this->_country_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getCurrencyInfoWithPaymentModeByCountryCode()
    {
        if( !$this->is_required($this->input->get(), array('code')) )
        {
            return false;
        }

        $code = $this->input->get("code");

        if( $info = $this->_country_currency_service->getCurrencyInfoWithPaymentModeByCountryCode($code) )
        {
            $this->_respondWithSuccessCode($this->_country_currency_service->getResponseCode(), array('result' => $info));
            return false;
        }

        $this->_respondWithCode($this->_country_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

}