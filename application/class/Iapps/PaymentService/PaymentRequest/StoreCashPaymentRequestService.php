<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\PaymentService\Common\EwalletClient\StoreWorkCreditCashClientFactory;
use Iapps\PaymentService\Common\EwalletClient\StoreWorkCreditCashInClient;
use Iapps\PaymentService\Common\EwalletClient\StoreWorkCreditCommisionClient;
use Iapps\PaymentService\Common\EwalletClient\StoreWorkCreditCommisionClientFactory;
use Iapps\PaymentService\Common\EwalletClient\WorkCreditCommisionClientFactory;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class StoreCashPaymentRequestService extends PaymentRequestService{

    protected $_staffType;

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::STORE_CASH;
    }

    public function request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, array $option)
    {
        //add admin access token as option
        $option['token'] = $this->getAdminAccessToken();

        return parent::request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, $option);
    }

    protected function _requestAction(PaymentRequest $request)
    {
        $agent_id = null;

        if( $staffType = $this->_getStaffType() )
        {
            if( $staffType == FunctionCode::STORE_FRANCHISE_STAFF_FUNCTIONS )
            {
                $agent_id = $this->_getBranchAgent();
            }
            else
            {
                $agent_id = $this->_getMainAgent();
            }
        }
        else
        {
            $this->setResponseCode(MessageCode::CODE_PAYMENT_NOT_ACCESSIBLE);
            return false;
        }

        if( $agent_id )
        {
            //make request to ewallet service
            $client = StoreWorkCreditCashClientFactory::build($request->getAmount());

            $client->setAgentId($agent_id->getId());
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

                $commisionService = new PaymentCommissionService($request, StoreWorkCreditCommisionClientFactory::build());
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
        $client = StoreWorkCreditCashClientFactory::build($request->getAmount());

        $client->setToken($request->getReferenceID());

        if( $client->cancel() )
        {
            $commisionService = new PaymentCommissionService($request, StoreWorkCreditCommisionClientFactory::build());
            $commisionService->cancel();

            return true;
        }

        $lastResponse = $client->getLastResponse();
        if( isset($lastResponse['status_code']) )
            $this->setResponseCode($client->getLastResponse()['status_code']);
        if( isset($lastResponse['message']) )
            $this->setResponseMessage($client->getLastResponse()['message']);

        return false;
    }

    protected function _completeAction(PaymentRequest $request)
    {
        //make request to ewallet service
        $client = StoreWorkCreditCashClientFactory::build($request->getAmount());

        $client->setToken($request->getReferenceID());

        if( $client->complete() )
        {
            $commisionService = new PaymentCommissionService($request, StoreWorkCreditCommisionClientFactory::build());
            $commisionService->complete();

            if( $request->getOption()->getValue('ewallet_request') )
            {
                if( $option = json_decode($request->getOption()->getValue('ewallet_request'), true) )
                {
                    $retrievedClient = StoreWorkCreditCashInClient::fromOption($option);
                    $request->setAgentId($retrievedClient->getAgentId());
                }
            }

            return parent::_completeAction($request);
        }

        $lastResponse = $client->getLastResponse();
        if( isset($lastResponse['status_code']) )
            $this->setResponseCode($client->getLastResponse()['status_code']);
        if( isset($lastResponse['message']) )
            $this->setResponseMessage($client->getLastResponse()['message']);

        return false;
    }

    protected function _generateDetail1(PaymentRequest $request)
    {
        $storeName = 'unknown';
        $branchName = 'unknown';

        if( $mainAgent = $this->_getMainAgent() )
            $storeName = $mainAgent->getName();

        if( $branchAgent = $this->_getBranchAgent() )
            $branchName = $branchAgent->getName();

        $desc = new PaymentDescription();
        $desc->add('', 'You were served by ' . $storeName . " - " . $branchName);

        $request->setDetail1($desc);

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

    protected function _getStaffType()
    {
        if( $this->_staffType )
            return $this->_staffType;

        $acc_serv = AccountServiceFactory::build();
        if( $acc_serv->checkAccessByUserProfileId($this->getUpdatedBy(), FunctionCode::STORE_BRANCH_STAFF_FUNCTIONS))
        {
            $this->_staffType = FunctionCode::STORE_BRANCH_STAFF_FUNCTIONS;
            return $this->_staffType;
        }

        return false;
    }

    protected function _getMainAgent()
    {
        $acc_serv = AccountServiceFactory::build();
        if( $structure = $acc_serv->getAgentUplineStructure() )
        {
            if( $upline = $structure->second_upline )
            {
                if( $upline->getRoles()->hasRole(array('main_agent')) )
                {
                    return $upline->getUser();
                }
            }
        }

        return false;
    }

    protected function _getBranchAgent()
    {
        $acc_serv = AccountServiceFactory::build();
        if( $structure = $acc_serv->getAgentUplineStructure() )
        {
            if( $upline = $structure->first_upline )
            {
                if( $this->_getStaffType() == FunctionCode::STORE_FRANCHISE_STAFF_FUNCTIONS )
                {
                    if( $upline->getRoles()->hasRole(array('store_franchise_agent')) )
                        return $upline->getUser();
                }
                else if( $this->_getStaffType() == FunctionCode::STORE_BRANCH_STAFF_FUNCTIONS )
                {
                    if( $upline->getRoles()->hasRole(array('store_branch_agent')) )
                        return $upline->getUser();
                }
            }
        }

        return false;
    }
}