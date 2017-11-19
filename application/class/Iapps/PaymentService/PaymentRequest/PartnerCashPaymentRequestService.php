<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\RequestHeader;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Microservice\AccountService\PartnerAccountServiceFactory;
use Iapps\PaymentService\Common\EwalletClient\PartnerWorkCreditCashClientFactory;
use Iapps\PaymentService\Common\EwalletClient\PartnerWorkCreditCashInClient;
use Iapps\PaymentService\Common\EwalletClient\PartnerWorkCreditCommisionClient;
use Iapps\PaymentService\Common\EwalletClient\PartnerWorkCreditCommisionClientFactory;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class PartnerCashPaymentRequestService extends PaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::PARTNER_CASH;
    }

    public function request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, array $option)
    {
        //add admin access token as option
        $headers = RequestHeader::get();
        $option['token'] = NULL;
        if( array_key_exists(ResponseHeader::FIELD_X_AUTHORIZATION, $headers) )
            $option['token'] = $headers[ResponseHeader::FIELD_X_AUTHORIZATION];

        return parent::request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, $option);
    }

    protected function _requestAction(PaymentRequest $request)
    {
        $agent = $this->_getMainAgent();

        $agent_id = $agent->getId();
        if( $agent_id )
        {
            //make request to ewallet service
            $client = PartnerWorkCreditCashClientFactory::build($request->getAmount());

            $client->setAgentId($agent_id);
            $client->setModuleCode($request->getModuleCode());
            $client->setTransactionID($request->getTransactionID());
            $client->setCountryCurrencyCode($request->getCountryCurrencyCode());
            $client->setAmount($request->getAmount());

            $response = $client->request();

            $request->getOption()->add('ewallet_request', $client->getOption());
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

                $commisionService = new PaymentCommissionService($request, PartnerWorkCreditCommisionClientFactory::build());
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

        return false;
    }

    protected function _cancelAction(PaymentRequest $request)
    {
        //make request to ewallet service
        $client = PartnerWorkCreditCashClientFactory::build($request->getAmount());

        $client->setToken($request->getReferenceID());

        if( $client->cancel() )
        {
            $commisionService = new PaymentCommissionService($request, PartnerWorkCreditCommisionClientFactory::build());
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
        $client = PartnerWorkCreditCashClientFactory::build($request->getAmount());

        $client->setToken($request->getReferenceID());

        if( $client->complete() )
        {
            $commisionService = new PaymentCommissionService($request, PartnerWorkCreditCommisionClientFactory::build());
            $commisionService->complete();

            if( $request->getOption()->getValue('ewallet_request') )
            {
                if( $option = json_decode($request->getOption()->getValue('ewallet_request'), true) )
                {
                    $retrievedClient = PartnerWorkCreditCashInClient::fromOption($option);
                    $request->setAgentId($retrievedClient->getAgentId());
                }
            }

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
        //get agent detail
        $acc_serv = AccountServiceFactory::build();
        if( $agent = $acc_serv->getUser(NULL, $this->getUpdatedBy()) )
        {
            $desc = new PaymentDescription();
            $desc->add('', 'You were served by ' . $agent->getName());

            $request->setDetail1($desc);
        }

        return true;
    }

    protected function _getMainAgent()
    {
        $acc_serv = PartnerAccountServiceFactory::build();
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