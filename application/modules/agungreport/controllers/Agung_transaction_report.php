<?php

use Iapps\Common\Core\IpAddress;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Payment\PaymentRepository;
use Iapps\PaymentService\Payment\PaymentService;
use Iapps\PaymentService\Common\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\PaymentService\Report\AgungReportService;

class Agung_transaction_report extends Base_Controller{

    protected $_service;
    function __construct()
    {
        parent::__construct();
                
        $this->_service = new AgungReportService();
        $this->_service->setIpAddress(IpAddress::fromString($this->_getIpAddress()));  
    }

    protected function _checkDate($date_from, $date_to)
    {
        if ($date_from > $date_to)
            return false;

        return true;
    }

    public function getAgungTransactionReport()
    {   

        if( !$admin_id = $this->_getUserProfileId(FunctionCode::VIEW_TEKTAYA_REPORT, AccessType::READ) )
            return false;

        // $admin_id = '2ad948a1-8848-40cd-bce5-9c5a73f639a5';
        if( !$this->is_required($this->input->post(), array('date_from','date_to','report_lang')))
        {
            return false;
        }

        $date_from = $this->input->post('date_from');
        $date_to = $this->input->post('date_to');
        $report_lang = $this->input->post('report_lang');

        if (!$this->_checkDate($date_from, $date_to))
            return false;

        $date_from = IappsDateTime::fromString($date_from);
        $date_to = IappsDateTime::fromString($date_to);

        $display_date_from = $date_from;
        $display_date_from = $display_date_from->addDay('1');

        $display_date_to = $date_to;

        $result = $this->_service->getAgungTransactionReport($admin_id,$date_from,$date_to);

        $this->_service->export_agung_transaction_csv($result,$display_date_from->getString(),$display_date_to->getString(),$report_lang);

    }

}