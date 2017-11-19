<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IappsDateTime;
use Iapps\Common\CommunicationService\CommunicationServiceProducer;
use Iapps\PaymentService\Payment\Payment;
use Iapps\PaymentService\Payment\PaymentServiceFactory;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeService;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;
use Iapps\PaymentService\PaymentRequestValidator\PaymentRequestValidatorFactory;
use Iapps\PaymentService\Common\SystemCodeServiceFactory;
use Iapps\PaymentService\Common\Logger;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeCode;
use Iapps\PaymentService\PaymentRequest\PaymentRequestStaticChannel;

abstract class PaymentRequestService extends IappsBaseService{

    protected $payment_code = NULL;
    protected $admin_accesstoken = NULL;
    protected $payment = NULL;
    protected $_request = NULL;
    private $_payment_request_client = NULL;
    protected $channelID;

    public function setPaymentCode($code)
    {
        $this->payment_code = $code;
        return $this;
    }

    public function getPaymentCode()
    {
        return $this->payment_code;
    }

    public function setAdminAccessToken($token)
    {
        $this->admin_accesstoken = $token;
        return $this;
    }

    public function getAdminAccessToken()
    {
        return $this->admin_accesstoken;
    }

    public function setPaymentRequestClient($payment_request_client)
    {
        $this->_payment_request_client = $payment_request_client;
        return $this;
    }

    public function getPaymentRequestClient()
    {
        return $this->_payment_request_client;
    }
  
    public function setChannelID($channelID)
    {
        $this->channelID = $channelID;
        return $this;
    }
    
    public function getChannelID()
    {
        return $this->channelID;
    }
    
    /*
     * request is a two-step processed payment flow, follow by complete
     */
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
        if( $this->_requestAction($request) )
        {
            $v = PaymentRequestValidatorFactory::build($this->getPaymentCode(), $request);
            if( !$v->fails() )
            {
                //save request
                if( $this->_savePaymentRequest($request) )
                {
                    $this->_publishQueue($request);

                    $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_SUCCESS);
                    return $request->getSelectedField(array('id'));
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

    public function complete($user_profile_id, $request_id, $payment_code, array $response)
    {
        if( $this->_request = $this->getRepository()->findById($request_id) )
        {
            if( $this->_request instanceof PaymentRequest )
            {
                if( $this->_request->getStatus() != PaymentRequestStatus::PENDING )
                {
                    $this->setResponseCode(MessageCode::CODE_REQUEST_IS_ALREADY_PROCESSED);
                    return false;
                }

                $ori_request = clone($this->_request);
                if( $this->_request->getUserProfileId() == $user_profile_id AND
                    $this->_request->getPaymentCode() == $payment_code )
                {
                    if( $this->_request->setSuccess() )
                    {
                        $this->getRepository()->startDBTransaction();
                        if( $this->_completeAction($this->_request) )
                        {
                            if( $response )
                                $this->_request->getResponse()->add('external_response', json_encode($response));

                            if( $this->_updatePaymentRequestStatus($this->_request, $ori_request))
                            {
                                $this->getRepository()->completeDBTransaction();
                                $this->setResponseCode(MessageCode::CODE_REQUEST_COMPLETED);
                                return array(
                                    'payment_info' => $this->payment->getSelectedField(array('id', 'module_code', 'transactionID','payment_code', 'country_currency_code', 'amount', 'status', 'description1', 'description2')),
                                    'additional_info' => NULL
                                );
                            }
                            else
                            {
                                $this->getRepository()->rollbackDBTransaction();
                                $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_FAIL);
                                return false;
                            }
                        }
                        else
                        {
                            //failed or still processing
                            $returnResult = false;
                            if($this->_request->getStatus()==PaymentRequestStatus::PENDING){
                                $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_PENDING);
                                $paymentInfoFields = array('id', 'module_code', 'transactionID','payment_code', 'country_currency_code', 'amount', 'status', 'description1', 'description2');
                                $payment_info = array();
                                foreach($paymentInfoFields as $field){
                                    $payment_info[$field] = null;
                                }
                                $returnResult = array(
                                    'payment_info' => $payment_info,
                                    'additional_info' => 'Processing'
                                );
                            }else{
                                $this->_request->setFail();
                            }

                            $this->getRepository()->updateResponse($this->_request);
                            $this->getRepository()->completeDBTransaction();

                            if( $this->getResponseCode() == NULL )
                                $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_FAIL);



                            return $returnResult;
                        }
                    }
                }
            }
        }

        if( $this->getResponseCode() == NULL )
            $this->setResponseCode(MessageCode::CODE_REQUEST_NOT_FOUND);
        return false;
    }

    public function cancel($user_profile_id, $request_id, $payment_code)
    {
        if( $request = $this->getRepository()->findById($request_id) )
        {
            if( $request instanceof PaymentRequest )
            {
                if( $request->getStatus() != PaymentRequestStatus::PENDING )
                {
                    $this->setResponseCode(MessageCode::CODE_REQUEST_IS_ALREADY_PROCESSED);
                    return false;
                }

                $ori_request = clone($request);
                if( $request->getUserProfileId() == $user_profile_id AND
                    $request->getPaymentCode() == $payment_code )
                {
                    if( $request->setCancelled() )
                    {
                        if( $this->_cancelAction($request) )
                        {
                            if( $this->_updatePaymentRequestStatus($request, $ori_request))
                            {
                                $this->setResponseCode(MessageCode::CODE_REQUEST_CANCELED);
                                return true;
                            }
                            else
                            {
                                $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_FAIL);
                                return false;
                            }
                        }
                    }
                }
            }
        }

        if( $this->getResponseCode() == NULL )
            $this->setResponseCode(MessageCode::CODE_REQUEST_NOT_FOUND);
        return false;
    }

    public function void($user_profile_id, $module_code, $transactionID)
    {
        $paymentServ = PaymentServiceFactory::build();
        $paymentServ->setIpAddress($this->getIpAddress());
        $paymentServ->setUpdatedBy($this->getUpdatedBy());
        $result = $paymentServ->void($module_code, $transactionID, $user_profile_id);
        $this->setResponseCode($paymentServ->getResponseCode());
        return $result;
    }

    /*
     * make is a single-step processed flow
     * By Default, this method is not supported, return false
     */
    public function make($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, array $option)
    {
        $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_FAIL);
        return false;
    }

    /*
     * nothing extra to be done on request
     */
    protected function _requestAction(PaymentRequest $request)
    {
        return true;
    }

    /*
     * save payment record on complete
     */
    protected function _completeAction(PaymentRequest $request)
    {
        $this->_generateDetail1($request);
        $this->_generateDetail2($request);

        $payment_serv = PaymentServiceFactory::build();
        $payment_serv->setUpdatedBy($this->getUpdatedBy());
        $payment_serv->setIpAddress($this->getIpAddress());
        if( $this->payment = $payment_serv->createPaymentFromRequest($request) )
        {
            return true;
        }

        return false;
    }

    protected function _cancelAction(PaymentRequest $request)
    {
        return true;
    }

    protected function _savePaymentRequest(PaymentRequest $request)
    {
        $request->setCreatedBy($this->getUpdatedBy());
        if( $this->getRepository()->insert($request) )
        {
            //fire log
            $this->fireLogEvent('iafb_payment.payment_request', AuditLogAction::CREATE, $request->getId() );

            return $request;
        }

        return false;
    }

    protected function _updatePaymentRequestStatus(PaymentRequest $request, PaymentRequest $ori_request)
    {
        $request->setUpdatedBy($this->getUpdatedBy());
        if( $this->getRepository()->updateResponse($request) )
        {
            //fire log
            $this->fireLogEvent('iafb_payment.payment_request', AuditLogAction::UPDATE, $request->getId(), $ori_request);

            return $request;
        }

        return false;
    }

    protected function _checkDuplicateTransaction($module_code, $transactionID)
    {
        if($this->getRepository()->findByTransactionID($module_code, $transactionID) !== false)
        {
            $this->setResponseCode(MessageCode::CODE_TRANSACTIONID_EXISTS);
            return false;
        }

        return true;
    }

    protected function _checkResponse(PaymentRequest $request, PaymentRequestResponseInterface $response)
    {
        if( $response->isSuccess() )
        {
            $request->setSuccess();
            return true;
        }else if ($response->isPending()){
            $request->setPending();
            return false;
        }
        else
        {
            $request->setFail();
            return false;
        }
    }


    protected function _checkDuplicateTransactionID($module_code, $transactionID)
    {
        if($transactions = $this->getRepository()->findByTransactionID($module_code, $transactionID))
        {
            foreach ($transactions->result as $transaction) {
                if( !$transaction->allowedNextRequest() )
                {
                    $this->setResponseCode(MessageCode::CODE_TRANSACTIONID_EXISTS);
                    return false;
                }
            }
        }

        return true;
    }

    protected function _generateDetail1(PaymentRequest $request)
    {
        return true;
    }

    protected function _generateDetail2(PaymentRequest $request)
    {
        return true;
    }

    protected function _updatePaymentModeType(PaymentRequest $request)
    {
        return true;
    }

    protected function _publishQueue(PaymentRequest $request)
    {
        return true;
    }

    protected function _validateCollectionInfo($payment_code, $collection_info){
        $attr_serv = PaymentModeAttributeServiceFactory::build();
        if($result = $attr_serv->validateCollectionInfo($payment_code, $collection_info)){
            return true;
        }

        return false;
    }


  
    public function checkAccount($bank_code , $account_number,$acc_holder_name){

         if( $result = $this->_checkAccount($bank_code ,$account_number,$acc_holder_name) )
         {
           return $result;
         }
        $this->setResponseCode(MessageCode::CODE_CHECK_BANK_ACCOUNT_FAILED);
        return false;
    }

}
