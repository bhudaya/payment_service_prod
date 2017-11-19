<?php defined('BASEPATH') OR exit('No direct script access allowed');

use Iapps\PaymentService\Currency\CurrencyRepository;
use Iapps\PaymentService\Currency\CurrencyService;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Core\IappsDateTime;
use Iapps\Common\AuditLog\AuditLogRepository;
use Iapps\Common\AuditLog\AuditLogService;

class Currency extends Base_Controller {

    protected $_currency_service;
    function __construct()
    {
        parent::__construct();

        $this->load->model('currency/currency_model');
        $repo = new CurrencyRepository($this->currency_model);
        $this->_currency_service = new CurrencyService($repo);
        
        $this->_service_audit_log->setTableName('iafb_payment.currency');
    }

    public function getAllCurrencies()
    {
        $limit = $this->input->get("limit");
        $page = $this->input->get("page");

        if( $object = $this->_currency_service->getCurrencyList($limit, $page) )
        {//todo Pagination
            $this->_respondWithSuccessCode($this->_currency_service->getResponseCode(), array('result' => $object->result, 'total' => $object->total));
            return false;
        }

        $this->_respondWithCode($this->_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getCurrencyInfo()
    {
        if( !$this->is_required($this->input->get(), array('code')) )
        {
            return false;
        }

        $code = $this->input->get("code");

        if( $info = $this->_currency_service->getCurrencyInfo($code) )
        {
            $this->_respondWithSuccessCode($this->_currency_service->getResponseCode(), array('result' => $info));
            return false;
        }

        $this->_respondWithCode($this->_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function addCurrency()
    {
        if( !$this->is_required($this->input->post(), array('code','name','symbol','denomination','effective_at','admin_id')) )
        {
            return false;
        }

        $code = $this->input->post("code");
        $name = $this->input->post("name");
        $symbol = $this->input->post("symbol");
        $denomination = $this->input->post("denomination");
        $effective_at = $this->input->post("effective_at");
        $admin_id = $this->input->post("admin_id");

        $currency = new \Iapps\PaymentService\Currency\Currency();
        $currency->setCode($code);
        $currency->setName($name);
        $currency->setSymbol($symbol);
        $currency->setDenomination($denomination);
        $currency->setEffectiveAt(IappsDateTime::fromString($effective_at));

        $this->_currency_service->setUpdatedBy($admin_id);
        if( $currency = $this->_currency_service->addCurrency($currency) )
        {
            $this->_respondWithSuccessCode($this->_currency_service->getResponseCode(), array('result' => $currency));
            return true;
        }

        $this->_respondWithCode($this->_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function editCurrency()
    {
        if( !$this->is_required($this->input->post(), array('code','name','symbol','denomination','effective_at','admin_id')) )
        {
            return false;
        }

        $code = $this->input->post("code");
        $name = $this->input->post("name");
        $symbol = $this->input->post("symbol");
        $denomination = $this->input->post("denomination");
        $effective_at = $this->input->post("effective_at");
        $admin_id = $this->input->post("admin_id");

        $currency = new \Iapps\PaymentService\Currency\Currency();
        $currency->setCode($code);
        $currency->setName($name);
        $currency->setSymbol($symbol);
        $currency->setDenomination($denomination);
        $currency->setEffectiveAt(IappsDateTime::fromString($effective_at));

        $this->_currency_service->setUpdatedBy($admin_id);
        if( $currency = $this->_currency_service->editCurrency($currency) )
        {
            $this->_respondWithSuccessCode($this->_currency_service->getResponseCode(), array('result' => $currency));
            return true;
        }

        $this->_respondWithCode($this->_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getCurrencyInfoByCodeOrName()
    {
        if( !$this->is_required($this->input->get(), array('search_value')) )
        {
            return false;
        }

        $search_value = $this->input->get("search_value");
        $limit = $this->input->get("limit");
        $page = $this->input->get("page");

        if( $object = $this->_currency_service->getCurrencyInfoByCodeOrName($search_value, $limit, $page) )
        {
            $this->_respondWithSuccessCode($this->_currency_service->getResponseCode(), array('result' => $object->result, 'total' => $object->total));
            return false;
        }

        $this->_respondWithCode($this->_currency_service->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

}