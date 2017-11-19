<?php

namespace Iapps\PaymentService\Common\OcbcCreditCardSwitch;

use Iapps\Common\Helper\ResponseMessage;
use Iapps\PaymentService\PaymentRequest\PaymentRequestResponseInterface;
use Iapps\Common\Helper\StringMasker;
use Iapps\PaymentService\PaymentRequest\PaymentRequestStatus;

class OcbcCreditCardSwitchResponse implements PaymentRequestResponseInterface{
    protected $raw;
    protected $formatted_response;

    protected $response_status;
    protected $response_code;
    protected $response_desc;

    protected $bankTransactionID;
    protected $transactionSignature;
    protected $transactionSignature2;
    protected $transactionID;
    protected $transactionDate;
    protected $salesDate;
    protected $voidDate;
    protected $authorization_code;
    protected $user_profile_id;
    protected $eci;

    protected $fraud_level;
    protected $fraud_score;

    function __construct($response, $api_request)
    {
        $this->setRaw($response);
    }

    //set API response array to object
    protected function _extractResponse(array $fields)
    {

        $this->setFormattedResponse($fields);
        if(array_key_exists('TRANSACTION_ID', $fields))
        {
            foreach ($fields AS $field => $value) {
                if ($field == 'TRANSACTION_ID') {
                    $this->setBankTransactionID($value);
                }
                if ($field == 'TXN_STATUS') {
                    $this->setResponseStatus($value);
                }
                if ($field == 'TXN_SIGNATURE') {
                    $this->setTransactionSignature($value);
                }
                if ($field == 'TXN_SIGNATURE2') {
                    $this->setTransactionSignature2($value);
                }
                if ($field == 'AUTH_ID') {
                    $this->setAuthorizationCode($value);
                }
                if ($field == 'TRAN_DATE') {
                    $this->setTransactionDate($value);
                }
                if ($field == 'SALES_DATE') {
                    $this->setSalesDate($value);
                }
                if ($field == 'VOID_REV_DATE') {
                    $this->setVoidDate($value);
                }
                if ($field == 'ECI') {
                    $this->setECI($value);
                }
                if ($field == 'RESPONSE_CODE') {
                    $this->setResponseCode($value);
                }
                if ($field == 'RESPONSE_DESC') {
                    $this->setResponseDesc($value);
                }
                if ($field == 'MERCHANT_TRANID') {
                    $this->setTransactionID($value);
                }
                if ($field == 'CUSTOMER_ID') {
                    $this->setUserProfileID($value);
                }
                if ($field == 'FR_LEVEL') {
                    $this->setFraudLevel($value);
                }
                if ($field == 'FR_SCORE') {
                    $this->setFraudScore($value);
                }
            }
        } else{

            $this->setFormattedResponse(array('ERR'=>'timeout'));
            //ERROR but make it processing
            $this->setResponseCode('PRC');
            $this->setResponseDesc('Received timeout but pending confirmation from Ocbc Credit Card');
        }
    }

    public function setRaw($raw)
    {
        $this->raw = $raw;
        if (is_array($raw))
        {
            $this->_extractResponse($raw);
        }
        else
        {
            $key_pair = explode('<BR>', $raw);
            
            $response_array = array();
            foreach($key_pair as $idx => $this_key_pair)
            {
                if (!empty(trim($this_key_pair))) {
                    list($key,$value) = explode("=", $this_key_pair);
                    $response_array[trim($key)] = trim($value);
                }
            }
            
            $this->_extractResponse($response_array);
        }
        
        return $this;
    }

    public function getRaw()
    {
        return $this->raw;
    }

    public function setFormattedResponse($formatted_response)
    {
        $this->formatted_response = json_encode($formatted_response);
        return $this;
    }

    public function getFormattedResponse()
    {
        return $this->formatted_response;
    }

    public function getResponse()
    {
        return $this->getFormattedResponse();
    }

    public function isSuccess()
    {
        return (in_array($this->getResponseCode(), array(
                                                    OcbcCreditCardSwitchFunction::OCBC_APPROVED_OR_COMPLETED, 
                                                    OcbcCreditCardSwitchFunction::OCBC_REFUND_COMPLETED)) || 
                in_array($this->getResponseStatus(), array(
                                                    OcbcCreditCardSwitchFunction::OCBC_STATUS_AUTHORIZED, 
                                                    OcbcCreditCardSwitchFunction::OCBC_STATUS_CAPTURED, 
                                                    OcbcCreditCardSwitchFunction::OCBC_STATUS_SALES_COMPLETED, 
                                                    OcbcCreditCardSwitchFunction::OCBC_STATUS_VOID))
            );
    }

    public function isPending()
    {
        return (in_array($this->getResponseStatus(), array(OcbcCreditCardSwitchFunction::OCBC_STATUS_PENDING)));
    }

    public function isError()
    {
        return (!in_array($this->getResponseCode(), array(
                                                    OcbcCreditCardSwitchFunction::OCBC_APPROVED_OR_COMPLETED,
                                                    OcbcCreditCardSwitchFunction::OCBC_REFUND_COMPLETED,
                                                    OcbcCreditCardSwitchFunction::OCBC_CUSTOMER_CANCEL_PAYMENT,
                                                    OcbcCreditCardSwitchFunction::OCBC_BANK_REJECTED_PAYMENT))
            );
    }

    public function isCancelByUser()
    {
        return (in_array($this->getResponseCode(), array(OcbcCreditCardSwitchFunction::OCBC_CUSTOMER_CANCEL_PAYMENT)));
    }

    public function isBankRejected()
    {
        return (in_array($this->getResponseCode(), array(OcbcCreditCardSwitchFunction::OCBC_BANK_REJECTED_PAYMENT)));
    }

    public function getStatus()
    {
        $status = PaymentRequestStatus::FAIL;
        if($this->isSuccess())
        {
            $status = PaymentRequestStatus::SUCCESS;
        }elseif($this->isPending())
        {
            $status = PaymentRequestStatus::PENDING;
        }

        return $status;
    }

    public function setResponseCode($response_code)
    {
        $this->response_code = $response_code;
        return $this;
    }

    public function getResponseCode()
    {
        return $this->response_code;
    }
    
    public function setResponseStatus($response_status)
    {
        $this->response_status = $response_status;
        return $this;
    }

    public function getResponseStatus()
    {
        return $this->response_status;
    }

    public function setResponseDesc($response_desc)
    {
        $this->response_desc = $response_desc;
        return $this;
    }

    public function getResponseDesc()
    {
        return $this->response_desc;
    }
    
    public function getBankTransactionID()
    {
        return $this->banktTansactionID;
    }

    public function setBankTransactionID($transactionIDSwitcher)
    {
        $this->banktTansactionID = $transactionIDSwitcher;
        return $this;
    }

    public function getTransactionSignature()
    {
        return $this->transactionSignature;
    }

    public function setTransactionSignature($transactionSignature)
    {
        $this->transactionSignature = $transactionSignature;
        return $this;
    }

    public function getTransactionSignature2()
    {
        return $this->transactionSignature2;
    }

    public function setTransactionSignature2($transactionSignature)
    {
        $this->transactionSignature2 = $transactionSignature;
        return $this;
    }

    public function getAuthorizationCode()
    {
        return $this->authorization_code;
    }

    public function setAuthorizationCode($authorization_code)
    {
        $this->authorization_code = $authorization_code;
        return $this;
    }

    public function getTransactionDate()
    {
        return $this->transactionDate;
    }

    public function setTransactionDate($transaction_date)
    {
        $this->transactionDate = $transaction_date;
        return $this;
    }

    public function getSalesate()
    {
        return $this->salesDate;
    }

    public function setSalesDate($sales_date)
    {
        $this->salesDate = $sales_date;
        return $this;
    }

    public function getVoidDate()
    {
        return $this->voidDate;
    }

    public function setVoidDate($void_date)
    {
        $this->voidDate = $void_date;
        return $this;
    }

    public function getECI()
    {
        return $this->eci;
    }

    public function setECI($eci)
    {
        $this->eci = $eci;
        return $this;
    }

    public function getTransactionID()
    {
        return $this->transactionID;
    }

    public function setTransactionID($transactionID)
    {
        $this->transactionID = $transactionID;
        return $this;
    }
    
    public function getUserProfileID()
    {
        return $this->user_profile_id;
    }

    public function setUserProfileID($user_profile_id)
    {
        $this->user_profile_id = $user_profile_id;
        return $this;
    }

    public function getFraudLevel()
    {
        return $this->fraud_level;
    }

    public function setFraudLevel($fraud_level)
    {
        $this->fraud_level = $fraud_level;
        return $this;
    }

    public function getFraudScore()
    {
        return $this->fraud_score;
    }

    public function setFraudScore($fraud_score)
    {
        $this->fraud_score = $fraud_score;
        return $this;
    }

    public function getSelectedField(array $fields)
    {
        return ArrayExtractor::extract($this->jsonSerialize(), $fields);
    }
}