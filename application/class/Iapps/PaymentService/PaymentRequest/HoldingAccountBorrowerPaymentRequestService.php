<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\PaymentService\Common\HoldingAccountClient\HoldingAccountCollectionClient;
use Iapps\PaymentService\Common\HoldingAccountClient\HoldingAccountUtilizationClientFactory;
use Iapps\PaymentService\Common\Logger;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Payment\Payment;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class HoldingAccountBorrowerPaymentRequestService extends PaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::HOLDING_ACCOUNT_BORROWER;
    }

    protected function _isCollectionRequest(PaymentRequest $request)
    {
        $option = $request->getOption();

        if( $isCollection = $option->getValue('is_collection') )
        {
            if( $isCollection == 1)
                return true;
        }

        return false;
    }

    protected function _requestAction(PaymentRequest $request)
    {
        //make request to holding account service
        $client = HoldingAccountUtilizationClientFactory::build($request->getAmount(), $this->getPaymentRequestClient(), $request->getUserProfileId());
        $client->setModuleCode($request->getModuleCode());
        $client->setTransactionID($request->getTransactionID());
        $client->setCountryCurrencyCode($request->getCountryCurrencyCode());
        $client->setAmount($request->getAmount());
        $client->setHoldingAccountType($request->getOption()->getValue('holding_account_type'));
        $client->setReferenceId($request->getOption()->getValue('reference_id'));
        $client->setPaymentCode($request->getPaymentCode());

        if( $this->_isCollectionRequest($request) )
            $client->setIsCollection(true);

        $response = $client->request();

        $request->getOption()->add('holding_account_request', $client->getOption());
        $request->getResponse()->add('holding_account_request', $response->getResponse());

        if( !$response->isSuccess() )
        {
            $lastResponse = $client->getLastResponse();
            if( isset($lastResponse['status_code']) )
                $this->setResponseCode($lastResponse['status_code']);

            if( isset($lastResponse['message']) )
                $this->setResponseMessage($lastResponse['message']);

            $request->setStatus(PaymentRequestStatus::FAIL);
        }
        else
        {
            $request->setReferenceID($response->getRequestToken());
            $request->setStatus(PaymentRequestStatus::PENDING);
        }


        return $response->isSuccess();
    }

    protected function _cancelAction(PaymentRequest $request)
    {
        //make request to holding account service
        $client = HoldingAccountUtilizationClientFactory::build($request->getAmount(), $this->getPaymentRequestClient(), $request->getUserProfileId());

        $client->setToken($request->getReferenceID());
        if( $this->_isCollectionRequest($request) )
            $client->setIsCollection(true);

        if( $client->cancel() )
        {
            return true;
        }

        $lastResponse = $client->getLastResponse();
        if( isset($lastResponse['status_code']) )
            $this->setResponseCode($lastResponse['status_code']);

        if( isset($lastResponse['message']) )
            $this->setResponseMessage($lastResponse['message']);

        return false;
    }

    protected function _completeAction(PaymentRequest $request)
    {
        //make request to holding account service
        $client = HoldingAccountUtilizationClientFactory::build($request->getAmount(), $this->getPaymentRequestClient(), $request->getUserProfileId());

        $client->setToken($request->getReferenceID());
        if( $this->_isCollectionRequest($request) )
            $client->setIsCollection(true);

        if( $client->complete() )
        {
            $request->getResponse()->add('holding_account_complete', $client->getLastResponse());

            return parent::_completeAction($request);
        }

        $lastResponse = $client->getLastResponse();
        if( isset($lastResponse['status_code']) )
            $this->setResponseCode($lastResponse['status_code']);

        if( isset($lastResponse['message']) )
            $this->setResponseMessage($lastResponse['message']);

        return false;
    }

}
