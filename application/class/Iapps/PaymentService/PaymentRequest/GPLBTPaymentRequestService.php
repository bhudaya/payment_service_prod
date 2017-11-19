<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\Microservice\RemittanceService\RemittanceTransactionServiceFactory;
use Iapps\PaymentService\Common\GPLSwitch\GPLSwitchClientFactory;
use Iapps\PaymentService\Common\GPLSwitch\GPLTransactionType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Common\BDOSwitch\BDOSwitchClientFactory;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeCode;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;
use Iapps\PaymentService\PaymentRequestValidator\BDOPaymentRequestValidator;
use Iapps\PaymentService\Common\Logger;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Core\IappsDateTime;

class GPLBTPaymentRequestService extends PaymentRequestService{

    protected $gpl_transaction_type;
    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::BANK_TRANSFER_GPL;
        $this->gpl_transaction_type = GPLTransactionType::BANK_TRANSFER;
    }

    /*
     * GPL only call to switch upon complete
     */
    public function _requestAction(PaymentRequest $request)
    {
        try{
            $gpl_switch_client = GPLSwitchClientFactory::buildFromRequest($request);
            $gpl_switch_client->getReceiver()->setTransactionType($this->gpl_transaction_type);
        }
        catch(\Exception $e)
        {//this is internal error, should not happen
            $this->setResponseCode(MessageCode::CODE_INVALID_SWITCH_SETTING);
            return false;
        }

        $option_array = json_decode($gpl_switch_client->getOption(), true);
        //set user type
        if( $user_type = $request->getOption()->getValue('user_type')) {
            $option_array['user_type'] = $user_type;
        }

        $request->getOption()->setArray($option_array);

        $request->setStatus(PaymentRequestStatus::PENDING);
        return true;
    }

    public function _completeAction(PaymentRequest $request)
    {
        //make request to switch
        try{
            $gpl_switch_client = GPLSwitchClientFactory::buildFromOption($request->getOption()->toArray());
        }
        catch(\Exception $e)
        {//this is internal error, should not happen
            $this->setResponseCode(MessageCode::CODE_INVALID_SWITCH_SETTING);
            return false;
        }

        if($response = $gpl_switch_client->bankTransfer() )
        {
            $result = $this->_checkResponse($request, $response);
            $request->getResponse()->setJson(json_encode(array("transfer"=> $response->getResponse())));
            $request->setReferenceID($response->getBillNo());

            if( $result ) {
                return parent::_completeAction($request);
            }else{
                if($request->getStatus()==PaymentRequestStatus::FAIL){
                    $this->setResponseMessage($response->getResponseMessage());
                    $request->setFail();
                    $this->getRepository()->updateResponse($request);
                    Logger::debug('GPL Failed - ' . $request->getStatus() . ': ' . $response->getResponse());
                }elseif($request->getStatus()==PaymentRequestStatus::PENDING){
                    $this->setResponseMessage($response->getResponseMessage());
                    $this->getRepository()->updateResponse($request);
                    Logger::debug('GPL Pending - ' . $request->getStatus() . ': ' . $response->getResponse());
                }
            }
        }

        return false;
    }

    public function findPendingRequest(){
        $payment_request = new PaymentRequest();
        $payment_request->setPending();
        $payment_request->setPaymentCode($this->getPaymentCode());
        $requests = $this->getRepository()->findBySearchFilter($payment_request, null, null, null);

        return $requests;
    }

    public function reprocessRequest(PaymentRequest $request){
        //make request to switch
        try{
            $gpl_switch_client = GPLSwitchClientFactory::buildFromOption($request->getOption()->toArray());
        }
        catch(\Exception $e)
        {//this is internal error, should not happen
            $this->setResponseCode(MessageCode::CODE_INVALID_SWITCH_SETTING);
            return false;
        }


        if($response = $gpl_switch_client->inquiry() ) {
            $ori_request = clone($request);

            $result = $this->_checkResponse($request, $response);
            $request->getResponse()->setJson(json_encode(array("inquiry"=>$response->getResponse())));
            $request->setReferenceID($response->getBillNo());

            $this->getRepository()->beginDBTransaction();
            if ($result) {
                if ($complete = parent::_completeAction($request))
                {
                    if (parent::_updatePaymentRequestStatus($request, $ori_request))
                    {
                        Logger::debug("GPL reprocess Request Success");
                        Logger::debug($request->getTransactionID());
                        if ($this->getRepository()->statusDBTransaction() === FALSE){
                            $this->getRepository()->rollbackDBTransaction();
                        }else {
                            $this->getRepository()->commitDBTransaction();
                        }
                        $this->setResponseCode(MessageCode::CODE_REQUEST_COMPLETED);
                        return true;
                    }
                    else
                    {
                        Logger::debug("GPL reprocess Request failed");
                        $this->getRepository()->rollbackDBTransaction();
                        $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_FAIL);
                        return false;
                    }
                }
            } else {
                if($request->getStatus() == PaymentRequestStatus::FAIL){
                    Logger::debug('GPL Reprocess Failed - ' . $request->getStatus() . ': ' . $response->getResponse());
                    $this->setResponseMessage($response->getResponseMessage());
                    $request->setFail();
                    $this->getRepository()->updateResponse($request);
                    if ($this->getRepository()->statusDBTransaction() === FALSE){
                        $this->getRepository()->rollbackDBTransaction();
                    }else {
                        $this->getRepository()->commitDBTransaction();
                    }
                    return true;
                }
                elseif($request->getStatus() == PaymentRequestStatus::PENDING)
                {//do nothing if its still pending
                    $this->getRepository()->rollbackDBTransaction();
                    $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_PENDING);
                    return false;
                }
            }
            $this->getRepository()->rollbackDBTransaction();
        }

        $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_FAIL);
        return false;
    }

    protected function _generateDetail1(PaymentRequest $request)
    {
        //get bank transfer detail
        if( $option = $request->getOption() )
        {
            $account_holder_name = NULL;
            $bank_code = NULL;
            $bank_acc = NULL;
            $bank_name = NULL;
            if( $receiver = $option->getValue('receiver') )
            {
                $account_holder_name = isset($receiver->receiver_name) ? $receiver->receiver_name : NULL;
                $bank_code = isset($receiver->bank_code) ? $receiver->bank_code : NULL;
                $bank_acc = isset($receiver->account_no) ? $receiver->account_no : NULL;

                if( $bank_code )
                {
                    $attrServ = PaymentModeAttributeServiceFactory::build();
                    if( $value = $bank_name = $attrServ->getValueByCode($this->payment_code, PaymentModeAttributeCode::BANK_CODE, $bank_code) )
                        $bank_name = $value->getValue();
                }
            }

            $desc = new PaymentDescription();
            $desc->add("Account Holder's Name", $account_holder_name);
            $desc->add('Bank', $bank_name . "(" . $bank_code . ")");
            $desc->add('Bank Account No.', $bank_acc);

            $request->setDetail1($desc);
        }

        return true;
    }
}
