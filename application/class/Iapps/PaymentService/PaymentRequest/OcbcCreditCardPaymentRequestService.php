<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\Core\IappsDateTime;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Common\Logger;
use Iapps\PaymentService\Common\OcbcCreditCardSwitch\OcbcCreditCardSwitchFunction;
use Iapps\PaymentService\Common\OcbcCreditCardSwitch\OcbcCreditCardSwitchResponse;
use Iapps\PaymentService\Common\OcbcCreditCardSwitch\OcbcCreditCardSwitchClientFactory;
use Iapps\PaymentService\Common\OcbcCreditCardSwitch\OcbcCreditCardSwitchClient;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\Payment\PaymentServiceFactory;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeCode;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;
use Iapps\PaymentService\PaymentRequestValidator\OcbcCreditCardPaymentRequestValidator;
use Iapps\PaymentService\PaymentRequestValidator\PaymentRequestValidatorFactory;
use Iapps\PaymentService\PaymentRequest\PaymentRequestResponse;
use Illuminate\Support\Facades\Log;

class OcbcCreditCardPaymentRequestService extends PaymentRequestService
{

    protected $gateway_response;

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);
        $this->payment_code = PaymentModeType::OCBC_CREDIT_CARD;
        $this->gateway_response = '';
    }

    public function request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, array $option)
    {
        if( !$this->_checkDuplicateTransactionID($module_code, $transaction_id) )
            return false;

        if(!$this->_validateCollectionInfo($this->getPaymentCode(), $option)){
            $this->setResponseCode(MessageCode::CODE_PAYMENT_ATTRIBUTE_VALUE_VALIDATE_FAIL);
            return false;
        }

        $request = new PaymentRequest();
        $request->setId(GuidGenerator::generate());
        $request->setUserProfileId($user_profile_id);
        $request->setModuleCode($module_code);
        $request->setTransactionID($transaction_id);
        $request->setPaymentCode($this->getPaymentCode());
        $request->setStatus(PaymentRequestStatus::PENDING);
        $request->setCountryCurrencyCode($country_currency_code);
        $request->setAmount($amount);
        $request->setCreatedBy($this->getUpdatedBy());
        $request->getOption()->setArray($option);
        $request->setChannelId(PaymentRequestStaticChannel::$channelID);

        if( $response = $this->_requestAction($request) )
        {
            $v = PaymentRequestValidatorFactory::build($this->getPaymentCode(), $request);
            if( !$v->fails() )
            {
                //save request
                if( $this->_savePaymentRequest($request) )
                {
                    $this->_publishQueue($request);

                    $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_SUCCESS);
                    return $response; //$request->getSelectedField(array('id'));
                }
            }
            else
            {
                $this->setResponseCode($v->getErrorCode());
            }
        }

        if( $this->getResponseCode() == NULL )
            $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_FAIL);

        return false;
    }

    public function _requestAction(PaymentRequest $request)
    {
        try{
            $ocbc_switch_client = OcbcCreditCardSwitchClientFactory::build();
        }
        catch(\Exception $e)
        {//this is internal error, should not happen
            $this->setResponseCode(MessageCode::CODE_INVALID_SWITCH_SETTING);
            return false;
        }

        $ocbc_switch_client->setTransactionID($request->getTransactionID());
        $ocbc_switch_client->setUserProfileID($request->getUserProfileId());
        
        if( $transaction_currency = $request->getOption()->getValue('transaction_currency') )
            $ocbc_switch_client->setTransactionCurrency($transaction_currency);

        if( $transaction_description = $request->getOption()->getValue('transaction_description') )
        {
            $ocbc_switch_client->setTransactionDescription($transaction_description);
        }
        else if ( $transaction_description = $request->getOption()->getValue('transaction_type') )
        {
            $ocbc_switch_client->setTransactionDescription($transaction_description);
        }

        $ocbc_switch_client->setTransactionAmount(1*$request->getAmount());

        $option_array = json_decode($ocbc_switch_client->getOption(), true);
        //set user type
        if( $user_type = $request->getOption()->getValue('user_type')) {
            $option_array['user_type'] = $user_type;
        }
        
        $request->getOption()->setArray($option_array);

        //this validation in main class
        $v = OcbcCreditCardPaymentRequestValidator::make($request);
        if ( !$v->fails() )
        {
            if ( $response = $ocbc_switch_client->paymentSales() )
            {
                $request->setStatus(PaymentRequestStatus::PENDING);
                $response['id'] = $request->getId();

                $_r = new PaymentRequestResponse();
                $_r->setArray($response);
                $request->setResponse($_r);

                return json_encode($response);
            }else{
                $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_FAIL);
                return false;
                
            }    
        }

        $this->setResponseCode(MessageCode::CODE_PAYMENT_INVALID_INFO);
        return false;
    }

    public function complete($user_profile_id, $request_id, $payment_code, array $response = array())
    {
        $this->gateway_response = $response;

        // check first response from gateway at the UI front
        $first_ocbc_response = new OcbcCreditCardSwitchResponse($response,"api");

        if ($first_ocbc_response->isSuccess())
        {
            try{
                $ocbc_switch_client = OcbcCreditCardSwitchClientFactory::build(array(),$response);
            }
            catch(\Exception $e)
            {//this is internal error, should not happen
                $this->setResponseCode(MessageCode::CODE_INVALID_SWITCH_SETTING);
                return false;
            }

            // hash checking with gateway response
            if( $_request = $this->getRepository()->findById($request_id) )
            {
                if( $_request instanceof PaymentRequest )
                {
                    $ocbc_switch_client->setTransactionAmount($_request->getAmount());
                    // gateway checking on transaction status before calling parent class complete()
                    if ( $ocbc_switch_client->checkResponseTransactionHash($ocbc_switch_client->getBankTransactionSignature()) )
                    {
                        if ($this->gateway_response = $ocbc_switch_client->paymentStatusQuery())
                        {
                            if ($this->gateway_response->isSuccess())
                            {
                                if ( $response =  parent::complete($user_profile_id, $request_id, $payment_code, $response) )
                                {
                                    if ( $this->_request instanceof PaymentRequest )
                                    {
                                        $response['additional_info'] = $this->_request->getResponseFields(array('TRANSACTION_ID', 'TXN_STATUS', 'TRAN_DATE', 'SALES_DATE', 'RESPONSE_CODE'));
                                    }

                                    return $response;
                                }
                            }

                            $this->setResponseCode(MessageCode::CODE_PAYMENT_GATEWAY_TRANSACTION_REQUEST_FAILED);
                            return false;
                        }
                    }

                    $this->setResponseCode(MessageCode::CODE_INVALID_GATEWAY_HASH_CHECKING);
                    return false;
                }
            }
        }
        else
        {
            if (!$first_ocbc_response->isPending())
            {
                // if OCBC status is not PENDING, set the payment request to failed
                if( $_request = $this->getRepository()->findById($request_id) )
                {
                    if( $_request instanceof PaymentRequest )
                    {
                        $ori_request = clone($_request);
                        $_request->getResponse()->add('first_response', $first_ocbc_response->getFormattedResponse());
                        $_request->setFail();

                        $result = $this->_updatePaymentRequestStatus($_request,$ori_request);
                    }
                }

                if ($first_ocbc_response->isCancelByUser())
                {
                    $this->setResponseCode($first_ocbc_response->getResponseCode());
                    $this->setResponseMessage($first_ocbc_response->getResponseDesc());
                    return false;
                }
                elseif ($first_ocbc_response->isBankRejected())
                {
                    $this->setResponseCode($first_ocbc_response->getResponseCode());
                    $this->setResponseMessage($first_ocbc_response->getResponseDesc());
                    return false;
                }
                elseif ($first_ocbc_response->isError())
                {
                    $this->setResponseCode($first_ocbc_response->getResponseCode());
                    $this->setResponseMessage($first_ocbc_response->getResponseDesc());
                    return false;
                }
            }
        }

        return false;
    }

    public function _completeAction(PaymentRequest $request)
    {
        if (!empty($request->getReferenceID())){
            $request->setPending();
            //Processed already
            Logger::debug('Ocbc Credit Card Processed');
            return false;
        }

        $response = $this->gateway_response;

        if ( $response instanceof PaymentRequestResponseInterface )
        {
            $result = $this->_checkResponse($request, $response);
            
            $request->getResponse()->add('ocbc_response', $response->getFormattedResponse());
            $request->setReferenceID($response->getTransactionID());

            if ( $result ) {
                $request->setReferenceID($response->getBankTransactionID());
                return parent::_completeAction($request);
            }else{
                if ($request->getStatus()==PaymentRequestStatus::FAIL){
                    $this->setResponseMessage($response->getDescription());
                    Logger::debug('OcbcCreditCard Failed - ' . $request->getStatus() . ': ' . $response->getResponse());
                }
            }
        }

        return false;
    }

    public function cancel($user_profile_id, $request_id, $payment_code)
    {
        if( $request = $this->getRepository()->findById($request_id) )
        {
            if( $request instanceof PaymentRequest )
            {
                $this->gateway_response = (json_decode($request->getResponse()->toArray()['ocbc_response'], true)) ? json_decode($request->getResponse()->toArray()['ocbc_response'], true) : array();

                try{
                    $ocbc_switch_client = OcbcCreditCardSwitchClientFactory::build(array(),$this->gateway_response);
                }
                catch(\Exception $e)
                {//this is internal error, should not happen
                    $this->setResponseCode(MessageCode::CODE_INVALID_SWITCH_SETTING);
                    return false;
                }

                $ocbc_switch_client->setTransactionAmount($request->getAmount());

                if ($this->gateway_response = $ocbc_switch_client->paymentStatusQuery())
                {
                    if ($this->gateway_response->isSuccess())
                    {
                        if ($this->gateway_response = $ocbc_switch_client->paymentVoid())
                        {
                            if ($this->gateway_response->isSuccess())
                            {
                                if ($result = parent::void($user_profile_id, $request->getModuleCode(), $request->getTransactionID()))
                                {
                                    $ori_request = clone($request);
                                    $request->getResponse()->add('void_response', $this->gateway_response->getFormattedResponse());
                                    
                                    $result = $this->_updatePaymentRequestStatus($request,$ori_request);
                                    
                                    return $this->gateway_response;
                                }
                            }

                            $this->setResponseCode(MessageCode::OCBC_GATEWAY_TRANSACTION_VOID_STATUS_FAILED);
                            return false;
                        }
                    }

                    $this->setResponseCode(MessageCode::CODE_OCBC_GATEWAY_QUERY_STATUS_FAILED);
                    return false;
                }
            }
        }

        if( $this->getResponseCode() == NULL )
            $this->setResponseCode(MessageCode::CODE_REQUEST_NOT_FOUND);
        return false;
    }

    protected function _cancelAction(PaymentRequest $request)
    {
        $response = $this->gateway_response;

        if ( $response instanceof PaymentRequestResponseInterface )
        {
            $result = $this->_checkResponse($request, $response);
            
            $request->getResponse()->add('ocbc_void_response', $response->getFormattedResponse());

            if ( $result ) {
                return parent::_cancelAction($request);
            }else{
                if ($request->getStatus()==PaymentRequestStatus::FAIL){
                    $this->setResponseMessage($response->getDescription());
                    Logger::debug('OcbcCreditCard Failed - ' . $request->getStatus() . ': ' . $response->getResponse());
                }
            }
        }
        
        return false;
    }

    public function findPendingRequest()
    {
        $payment_request = new PaymentRequest();
        $payment_request->setPending();
        $payment_request->setPaymentCode($this->getPaymentCode());
        $requests = $this->getRepository()->findBySearchFilter($payment_request, null, null, null);

        return $requests;
    }

    public function updateRequest(PaymentRequest $request)
    {
        if ($this->getRepository()->update($request)){
            return true;
        }
        return false;
    }

    protected function _generateDetail1(PaymentRequest $request)
    {
        if ($request->getOption() != NULL) {
            $desc = new PaymentDescription();

            $attrServ = PaymentModeAttributeServiceFactory::build();

            $option_array = $request->getOption()->toArray();
            if ($option_array != NULL) {
                if (array_key_exists('reference_no', $option_array)) {
                    $desc->add('Transaction Ref No.', $option_array['reference_no']);
                }
                if (array_key_exists('trans_date', $option_array)) {
                    $desc->add('Date of Transaction', $option_array['trans_date']);
                }
            }

            $request->setDetail1($desc);
        }

        return true;
    }

}