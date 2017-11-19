<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\PaymentService\Common\EwalletClient\WorkCreditCashClientFactory;
use Iapps\PaymentService\Common\EwalletClient\WorkCreditCashInClient;
use Iapps\PaymentService\Common\EwalletClient\WorkCreditCommisionClientFactory;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class MobileCashPaymentRequestService extends PaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::MOBILE_AGENT_CASH;
    }

    public function request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, array $option)
    {
        //add admin access token as option
        $option['token'] = $this->getAdminAccessToken();

        return parent::request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, $option);
    }

    protected function _requestAction(PaymentRequest $request)
    {
        //make request to ewallet service
        $client = WorkCreditCashClientFactory::build($request->getAmount());

        $client->setModuleCode($request->getModuleCode());
        $client->setTransactionID($request->getTransactionID());
        $client->setCountryCurrencyCode($request->getCountryCurrencyCode());
        $client->setAmount($request->getAmount());

        $response = $client->request();

        $request->getOption()->add('ewallet_request',$client->getOption());
        $request->getResponse()->add('ewallet_request', $response->getResponse());

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

            $commisionService = new PaymentCommissionService($request, WorkCreditCommisionClientFactory::build());
            if( !$commisionService->request() )
            {
                $client->setToken($response->getRequestToken());
                $client->cancel();

                $lastResponse = $commisionService->getEwalletClient()->getLastResponse();
                if( isset($lastResponse['status_code']) )
                    $this->setResponseCode($lastResponse['status_code']);
                if( isset($lastResponse['message']) )
                    $this->setResponseMessage($lastResponse['message']);

                $request->setStatus(PaymentRequestStatus::FAIL);
                return false;
            }
        }

        return $response->isSuccess();
    }

    protected function _cancelAction(PaymentRequest $request)
    {
        //make request to ewallet service
        $client = WorkCreditCashClientFactory::build($request->getAmount(), $this->getPaymentRequestClient());

        $client->setToken($request->getReferenceID());

        if( $client->cancel() )
        {
            $commisionService = new PaymentCommissionService($request, WorkCreditCommisionClientFactory::build($this->getPaymentRequestClient()));
            $commisionService->cancel();

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
        //make request to ewallet service
        $client = WorkCreditCashClientFactory::build($request->getAmount(), $this->getPaymentRequestClient());

        $client->setToken($request->getReferenceID());

        if( $client->complete() )
        {
            $commisionService = new PaymentCommissionService($request, WorkCreditCommisionClientFactory::build($this->getPaymentRequestClient()));
            $commisionService->complete();

            $request->setAgentId($request->getCreatedBy());

            return parent::_completeAction($request);
        }

        $lastResponse = $client->getLastResponse();
        if( isset($lastResponse['status_code']) )
            $this->setResponseCode($lastResponse['status_code']);

        if( isset($lastResponse['message']) )
            $this->setResponseMessage($lastResponse['message']);

        return false;
    }

    protected function _generateDetail1(PaymentRequest $request)
    {
        $storeName = 'unknown';

        if( $mainAgent = $this->_getMainAgent() )
            $storeName = $mainAgent->getName();

        //get agent detail
        $acc_serv = AccountServiceFactory::build();
        if( $agent = $acc_serv->getUser(NULL, $this->getUpdatedBy()) )
        {
            $desc = new PaymentDescription();
            $desc->add('', 'You were served by ' . $storeName);

            $request->setDetail1($desc);
        }

        return true;
    }

    protected function _generateDetail2(PaymentRequest $request)
    {
        //get agent detail
        $acc_serv = AccountServiceFactory::build();
        if( $agent = $acc_serv->getUser(NULL, $this->getUpdatedBy()) )
        {
            $desc = new PaymentDescription();
            $desc->add('', $agent->getName() . ', ID: ' . $agent->getAccountID());

            $request->setDetail2($desc);
        }

        return true;
    }

    protected function _getMainAgent()
    {
        $acc_serv = AccountServiceFactory::build();
        if( $structure = $acc_serv->getAgentUplineStructure() )
        {
            if( $upline = $structure->first_upline )
            {
                if( $upline->getRoles()->hasRole(array('main_agent')) )
                {
                    return $upline->getUser();
                }
            }
        }

        return false;
    }
}