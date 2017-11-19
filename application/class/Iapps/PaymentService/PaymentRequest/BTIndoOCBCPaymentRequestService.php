<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Common\IndoOcbcSwitch\IndoOcbcSwitchClientFactory;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeCode;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;
use Iapps\PaymentService\PaymentRequestValidator\BTIndoOCBCPaymentRequestValidator;
use Iapps\PaymentService\Common\Logger;

class BTIndoOCBCPaymentRequestService extends PaymentRequestService{
    
    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::BANK_TRANSFER_INDO_OCBC;
    }

    public function complete($user_profile_id, $request_id, $payment_code, array $response)
    {
        if( $response =  parent::complete($user_profile_id, $request_id, $payment_code, $response) )
        {
            if( $this->_request instanceof PaymentRequest )
            {
                $response['additional_info'] = $this->_request->getResponseFields(array('dest_bankcode', 'dest_bankacc', 'trx_refferenceid', 'timestamp'));
            }

            return $response;
        }

        return false;
    }

    /*
     * BT Indo OCBC only call to switch upon complete
     */
    public function _requestAction(PaymentRequest $request)
    {
        try{
            $indo_switch_client = IndoOcbcSwitchClientFactory::build();
        }
        catch(\Exception $e)
        {//this is internal error, should not happen
            $this->setResponseCode(MessageCode::CODE_INVALID_SWITCH_SETTING);
            return false;
        }

        $indo_switch_client->setTerminalCode($this->getUpdatedBy());
        $indo_switch_client->setDestRefNumber( substr($request->getTransactionID(), 0, 8) . substr($request->getTransactionID(), -6) );
        if( $code = $request->getOption()->getValue('bank_code') )
            $indo_switch_client->setDestBankCode($code);
        if( $account = $request->getOption()->getValue('bank_account') )
            $indo_switch_client->setDestBankAccount($account);
        $indo_switch_client->setDestAmount(-1*$request->getAmount());

        $option_array = json_decode($indo_switch_client->getOption(), true);
        //set user type
        if( $user_type = $request->getOption()->getValue('user_type')) {
            $option_array['user_type'] = $user_type;
        }

        $request->getOption()->setArray($option_array);

        //this validation in main class
        //$v = BTIndoOCBCPaymentRequestValidator::make($request);
        //if( !$v->fails() )
        {
            $request->setStatus(PaymentRequestStatus::PENDING);
            return true;
        }

        $this->setResponseCode(MessageCode::CODE_PAYMENT_INVALID_INFO);
        return false;
    }

    public function _completeAction(PaymentRequest $request)
    {
        //make request to switch
        try{
            $indo_switch_client = IndoOcbcSwitchClientFactory::build($request->getOption()->toArray());
        }
        catch(\Exception $e)
        {//this is internal error, should not happen
            $this->setResponseCode(MessageCode::CODE_INVALID_SWITCH_SETTING);
            return false;
        }

        if($response = $indo_switch_client->bankTransfer() )
        {
            $request->getResponse()->setJson($response->getResponse());
            $request->setReferenceID($response->getTrxRefferenceId());

            $result = $this->_checkResponse($request, $response);

            if( $result )
            {
                return parent::_completeAction($request);
            }
            else
            {
                //set error message
                $this->setResponseMessage($response->getErrDescription());
                Logger::debug('Tektaya failed: ' . $response->getResponse());
            }
        }

        return false;
    }
    
    protected function _generateDetail1(PaymentRequest $request)
    {
        //get bank transfer detail
        if( $response = $request->getResponse() )
        {
            $account_holder_name = $response->getValue('dest_custname');
            $attrServ = PaymentModeAttributeServiceFactory::build();
            $bank_name = null;
            if( $value = $bank_name = $attrServ->getValueByCode($this->payment_code, PaymentModeAttributeCode::BANK_CODE, $response->getValue('dest_bankcode')) )
                $bank_name = $value->getValue();

            $bank_code = $response->getValue('dest_bankcode');
            $bank_acc = $response->getValue('dest_bankacc');

            $desc = new PaymentDescription();
            $desc->add("Account Holder's Name", $account_holder_name);
            $desc->add('Bank', $bank_name . "(" . $bank_code . ")");
            $desc->add('Bank Account No.', $bank_acc);

            $request->setDetail1($desc);
        }

        return true;
    }

    /*
    protected function _generateDetail2(PaymentRequest $request)
    {
        //get bank transfer detail
        if( $response = $request->getResponse() )
        {
            $account_holder_name = $response->getValue('dest_custname');

            $desc = new PaymentDescription();
            $desc->add('', $account_holder_name);

            $request->setDetail2($desc);
        }

        return true;
    }*/
}