<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Core\IappsBasicBaseService;
use Iapps\PaymentService\Common\PaymentEventProducer;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class GPLInquireTransactionStatusService extends IappsBasicBaseService{

    public function process()
    {
        $GPLPaymentReqServ = PaymentRequestServiceFactory::build(PaymentModeType::BANK_TRANSFER_GPL);
        $GPLPaymentReqServ->setUpdatedBy($this->getUpdatedBy());
        $GPLPaymentReqServ->setIpAddress($this->getIpAddress());
        $this->_inquiryRequest($GPLPaymentReqServ);

        return true;
    }

    protected function _inquiryRequest(GPLBTPaymentRequestService $paymentRequestServ)
    {
        $i = 0;
        if ($requests = $paymentRequestServ->findPendingRequest()){
            foreach ($requests->result as $req) {
                if ($req instanceof PaymentRequest) {
                    if(!empty($req->getReferenceID())){
                        if ($response = $paymentRequestServ->reprocessRequest($req)) {
                            PaymentEventProducer::publishPaymentRequestChanged($req->getModuleCode(), $req->getTransactionID(), $req->getPaymentCode());
                        }
                    }
                }
                $i++;
            }
        }
    }
}