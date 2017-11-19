<?php

namespace Iapps\PaymentService\Common;


use Iapps\Common\Helper\MessageBroker\BroadcastEventProducer;

class PaymentEventProducer extends BroadcastEventProducer{

    protected $payment_request_id;
    protected $transactionID;
    protected $module_code;

    public function setPaymentRequestId($payment_request_id)
    {
        $this->payment_request_id = $payment_request_id;
        return $this;
    }

    public function getPaymentRequestId()
    {
        return $this->payment_request_id;
    }


    public function setTransactionID($transactionID)
    {
        $this->transactionID = $transactionID;
        return $this;
    }

    public function getTransactionID()
    {
        return $this->transactionID;
    }

    public function setModuleCode($module_code)
    {
        $this->module_code = $module_code;
        return $this;
    }

    public function getModuleCode()
    {
        return $this->module_code;
    }

    public function getMessage()
    {
        $temp['payment_request_id'] = $this->getPaymentRequestId();
        $temp['module_code'] = $this->getModuleCode();
        $temp['transactionID'] = $this->getTransactionID();
        return json_encode($temp);
    }

    public static function publishPaymentRequestChanged($module_code, $transactionID)
    {
        $e = new PaymentEventProducer();

        $e->setModuleCode($module_code);
        $e->setTransactionID($transactionID);
        return $e->trigger(PaymentEventType::PAYMENT_REQUEST_CHANGED, NULL, $e->getMessage());
    }

    public static function publishPaymentRequestInitiated($module_code, $transactionID, $payment_request_id)
    {
        $e = new PaymentEventProducer();

        $e->setPaymentRequestId($payment_request_id);
        $e->setModuleCode($module_code);
        $e->setTransactionID($transactionID);
        return $e->trigger(PaymentEventType::PAYMENT_REQUEST_INITIATED, NULL, $e->getMessage());
    }
}