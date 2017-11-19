<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\PaymentMode\PaymentModeServiceFactory;

class KioskPaymentRequestService extends PaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL, $payment_code)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = $payment_code;
    }

    protected function _updatePaymentRequestStatus(PaymentRequest $request, PaymentRequest $ori_request)
    {
        $request->setUpdatedBy($this->getUpdatedBy());
        if( $externalResponse = $request->getResponse()->getValue('external_response') )
        {
            $externalResponse = json_decode($externalResponse, true);
            if( isset($externalResponse['reference_no']) )
                $request->setReferenceID($externalResponse['reference_no']);
        }

        if( $this->getRepository()->updateResponse($request) )
        {
            //fire log
            $this->fireLogEvent('iafb_payment.payment_request', AuditLogAction::UPDATE, $request->getId(), $ori_request);

            return $request;
        }

        return false;
    }

    protected function _generateDetail1(PaymentRequest $request)
    {
    	$desc = new PaymentDescription();
		
    	$code = $request->getPaymentCode();
		$pmServ = PaymentModeServiceFactory::build();
		if( $pm = $pmServ->getPaymentModeInfo($code) AND isset($pm['name']) )
			$desc->add('', 'You were served by ' . $pm['name']);
		else
			$desc->add('', 'You were served at kiosk');
		                
        $request->setDetail1($desc);
        return true;
    }
}