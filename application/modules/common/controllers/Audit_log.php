<?php

use Iapps\Common\AuditLog\AuditLogRepository;
use Iapps\Common\AuditLog\AuditLogService;
use Iapps\Common\AuditLog\AuditLogEventConsumer;
use Iapps\Common\AuditLog\AuditLogCollection;

class Audit_log extends Base_Controller{

    protected $_AuditLogServ;
    function __construct()
    {
        parent::__construct();

        $this->load->model('common/Audit_log_model');
        $repo = new AuditLogRepository($this->Audit_log_model);
        $this->_auditLogServ = new AuditLogService($repo);

    }

    public function listenLogEvent()
    {
        if( $key = getenv('LOG_ROUTING_KEY') )
        {
            $event = new AuditLogEventConsumer($this->_auditLogServ);
            $event->listenLogEvent($key);
            return true;
        }

        echo "LOG_ROUTING_KEY Not Defined";
    }

    public function getAuditLogByTableName()
    {
        $limit = $this->input->get("limit");
        $page = $this->input->get("page");
        $table_name = $this->input->get("table_name");

        if( $object = $this->_auditLogServ->getAuditLogByTableName($table_name, $limit, $page) )
        {
            $this->_respondWithSuccessCode($this->_auditLogServ->getResponseCode(), array('result' => $object->result->toArray(), 'total' => $object->total));
            return true;
        }

        $this->_respondWithCode($this->_auditLogServ->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }

    public function getAllAuditLog()
    {
        $limit = $this->input->get("limit");
        $page = $this->input->get("page");

        if( $object = $this->_auditLogServ->getAllAuditLog($limit, $page) )
        {
            $this->_respondWithSuccessCode($this->_auditLogServ->getResponseCode(), array('result' => $object->result->toArray(), 'total' => $object->total));
            return true;
        }

        $this->_respondWithCode($this->_auditLogServ->getResponseCode(), ResponseHeader::HEADER_NOT_FOUND);
        return false;
    }


}