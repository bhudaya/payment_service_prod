<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\PaymentService\Common\EwalletClient\WorkCreditCommisionClient;
use Iapps\PaymentService\Common\EwalletClient\WorkCreditCommisionClientResponse;

class PaymentCommissionService{

    protected $_request;
    protected $_commissionClient;

    function __construct(PaymentRequest $request, WorkCreditCommisionClient $client)
    {
        $this->_request = $request;
        $this->_commissionClient = $client;
    }

    public function getEwalletClient()
    {
        return $this->_commissionClient;
    }

    public function request()
    {
        if( $commissionStructure = $this->_request->getOption()->getValue('commission') )
        {
            if( !is_array($commissionStructure) )
                return false;

            $this->_commissionClient->setModuleCode($this->_request->getModuleCode());
            $this->_commissionClient->setTransactionID($this->_request->getTransactionID());
            $this->_commissionClient->setCountryCurrencyCode($this->_request->getCountryCurrencyCode());

            $commissionOptions = array();
            $commissionResponses = array();
            foreach( $commissionStructure AS $beneficiary)
            {
                if( array_key_exists('user_profile_id', $beneficiary) AND
                    array_key_exists('commission', $beneficiary) )
                {
                    $this->_commissionClient->setBeneficiaryId($beneficiary['user_profile_id']);
                    $this->_commissionClient->setAmount($beneficiary['commission']);
                    $response = $this->_commissionClient->request();

                    if( $response->isSuccess() )
                    {
                        $commissionOptions[] = $this->_commissionClient->getOption();
                        $commissionResponses[] = $response->getResponse();
                    }
                    else
                        return false;
                }
                else
                {
                    return false;
                }
            }

            $this->_request->getOption()->add('commission_request', $commissionOptions);
            $this->_request->getResponse()->add('commission_request', $commissionResponses);

            return $this->_request;
        }

        //no commission given, its ok
        return true;
    }

    public function complete()
    {
        if( $requests = $this->_request->getResponse()->getValue('commission_request') )
        {
            $status = true;
            foreach($requests AS $requestResponse)
            {
                $response = new WorkCreditCommisionClientResponse(json_decode($requestResponse, true));

                if( $response->getRequestToken() )
                {
                    $this->_commissionClient->setToken($response->getRequestToken());
                    if(!$this->_commissionClient->complete() )
                    {
                       $status = false;
                    }
                }
                else
                    $status = false;
            }

            return $status;
        }

        //no commission given, its ok
        return true;
    }

    public function cancel()
    {
        if( $requests = $this->_request->getResponse()->getValue('commission_request') )
        {
            $status = true;
            foreach($requests AS $requestResponse)
            {
                $response = new WorkCreditCommisionClientResponse(json_decode($requestResponse, true));

                if( $response->getRequestToken() )
                {
                    $this->_commissionClient->setToken($response->getRequestToken());
                    if(!$this->_commissionClient->cancel() )
                    {
                        $status = false;
                    }
                }
                else
                    $status = false;
            }

            return $status;
        }

        //no commission given, its ok
        return true;
    }
}