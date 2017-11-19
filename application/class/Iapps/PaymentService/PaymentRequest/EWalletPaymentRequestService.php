<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\PaymentService\Common\EwalletClient\EwalletCollectionClient;
use Iapps\PaymentService\Common\EwalletClient\EwalletRefundClient;
use Iapps\PaymentService\Common\EwalletClient\EwalletUtilizationClientFactory;
use Iapps\PaymentService\Common\EwalletClient\EwalletVoidClientFactory;
use Iapps\PaymentService\Common\Logger;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Payment\Payment;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class EWalletPaymentRequestService extends PaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::EWALLET;
    }

    public function void($user_profile_id, $module_code, $transactionID)
    {
        $this->getRepository()->startDBTransaction();

        if( $payment = parent::void($user_profile_id, $module_code, $transactionID) )
        {//revert ewallet payment...

            if( $payment instanceof Payment ) {

                try{
                    //make request to ewallet service
                    $client = EwalletVoidClientFactory::build($this->getPaymentRequestClient());
                    $client->setUserProfileId($payment->getUserProfileId());
                    $client->setModuleCode($payment->getModuleCode());
                    $client->setTransactionID($payment->getTransactionID());
                    $client->setCountryCurrencyCode($payment->getCountryCurrencyCode());
                    $client->setAmount(-1*$payment->getAmount());

                    $response = $client->request();
                    if( $response->isSuccess() )
                    {//proceed to complete to request

                        $client->setToken($response->getRequestToken());
                        if( $client->complete() )
                        {//ok...done
                            $this->getRepository()->completeDBTransaction();
                            return $payment;
                        }
                        else //something wrong, cancel the request
                            $client->cancel();
                    }
                }
                catch(\Exception $e)
                {
                    Logger::debug('Void paymnet request failed: ' . $e->getMessage());
                }
            }

            $this->setResponseCode(MessageCode::CODE_PAYMENT_VOIDED_FAILED);
        }

        $this->getRepository()->rollbackDBTransaction();
        return false;
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
        //make request to ewallet service
        $client = EwalletUtilizationClientFactory::build($request->getAmount(), $this->getPaymentRequestClient(), $request->getUserProfileId());
        
        $client->setModuleCode($request->getModuleCode());
        $client->setTransactionID($request->getTransactionID());
        $client->setCountryCurrencyCode($request->getCountryCurrencyCode());
        $client->setAmount($request->getAmount());

        if( $this->_isCollectionRequest($request) )
            $client->setIsCollection(true);

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
        }


        return $response->isSuccess();
    }

    protected function _cancelAction(PaymentRequest $request)
    {
        //make request to ewallet service
        $client = EwalletUtilizationClientFactory::build($request->getAmount(), $this->getPaymentRequestClient(), $request->getUserProfileId());

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
        //make request to ewallet service
        $client = EwalletUtilizationClientFactory::build($request->getAmount(), $this->getPaymentRequestClient(), $request->getUserProfileId());

        $client->setToken($request->getReferenceID());
        if( $this->_isCollectionRequest($request) )
            $client->setIsCollection(true);

        if( $client->complete() )
        {
            $request->getResponse()->add('ewallet_complete', $client->getLastResponse());

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
        if($this->getPaymentRequestClient() == PaymentRequestClient::AGENT) {
            //get main agent detail
            $storeName = 'unknown';

            if ($mainAgent = $this->_getMainAgent())
                $storeName = $mainAgent->getName();

            $desc = new PaymentDescription();
            $desc->add('', 'You were served by ' . $storeName);

            $request->setDetail1($desc);
            return true;
        }

        /*
         * The balance info available in different response regard of utilize or refund
         */
        if( $request->getAmount() >= 0 )
            $resp = $request->getResponse()->getValue('ewallet_request');
        else
            $resp = $request->getResponse()->getValue('ewallet_complete');

        //get agent detail
        if( $resp )
        {
            if( !is_array($resp) )
                $resp = json_decode($resp, true);

            $resp = json_decode(json_encode($resp), true);

            $initial_balance = null;
            if( isset($resp['response']['result']['balance']['initial'] ) )
            {
                $initial_balance = $resp['response']['result']['balance']['initial'];
            }
            elseif( isset($resp['result']['balance']['initial']) )
            {
                $initial_balance = $resp['result']['balance']['initial'];
            }

            $desc = new PaymentDescription();
            $desc->add('Initial Balance', $initial_balance);

            $request->setDetail1($desc);
        }

        return true;
    }

    //get agent detail
    protected function _generateDetail2(PaymentRequest $request)
    {
        if($this->getPaymentRequestClient() == PaymentRequestClient::AGENT) {
            //get agent detail
            $acc_serv = AccountServiceFactory::build();
            if ($agent = $acc_serv->getUser(NULL, $this->getUpdatedBy())) {
                $desc = new PaymentDescription();
                $desc->add('', $agent->getName() . ', ID: ' . $agent->getAccountID());

                $request->setDetail2($desc);
                return true;
            }
        }

        /*
         * The balance info available in different response regard of utilize or refund
         */
        if( $request->getAmount() >= 0 )
            $resp = $request->getResponse()->getValue('ewallet_request');
        else
            $resp = $request->getResponse()->getValue('ewallet_complete');

        if( $resp )
        {
            if( !is_array($resp) )
                $resp = json_decode($resp, true);

            $resp = json_decode(json_encode($resp), true);
            $new_balance = null;
            if( isset($resp['response']['result']['balance']['new']) )
            {
                $new_balance = $resp['response']['result']['balance']['new'];
            }
            elseif( isset($resp['result']['balance']['new']) )
            {
                $new_balance = $resp['result']['balance']['new'];
            }

            $desc = new PaymentDescription();
            $desc->add('New Balance', $new_balance);

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
}
