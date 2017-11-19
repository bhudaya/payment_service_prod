<?php

use Iapps\Common\Helper\RequestHeader;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\PaymentService\PaymentRequest\GPLInquireTransactionStatusService;
use Iapps\Common\Core\IpAddress;
use Iapps\PaymentService\Common\MessageCode;

class Cli_batch_job extends Cli_Base_Controller{

    public function inquireGPLTransactionStatus()
    {
        if (!$system_user_id = $this->_getUserProfileId())
            return false;

        RequestHeader::set(ResponseHeader::FIELD_X_AUTHORIZATION, $this->clientToken);

        $bdo_inquiry_serv = new GPLInquireTransactionStatusService();
        $bdo_inquiry_serv->setUpdatedBy($system_user_id);
        $bdo_inquiry_serv->setIpAddress(IpAddress::fromString($this->_getIpAddress()));

        $bdo_inquiry_serv->process();
        $this->_respondWithSuccessCode(MessageCode::CODE_JOB_PROCESS_PASSED);
        return true;
    }
}