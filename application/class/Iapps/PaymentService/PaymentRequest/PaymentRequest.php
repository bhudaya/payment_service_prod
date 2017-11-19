<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Helper\ArrayExtractor;
use Iapps\Common\SystemCode\SystemCode;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Common\Rijndael256EncryptorFactory;
use Iapps\Common\Helper\EncryptedS3Url;
use Iapps\PaymentService\Common\ReceiptReferenceImageS3Uploader;

class PaymentRequest extends IappsBaseEntity{
    protected $module_code;
    protected $country_code;
    protected $user_profile_id;
    protected $transactionID;
    protected $reference_id;
    protected $payment_code;
    protected $option;
    protected $response;
    protected $status;
    protected $country_currency_code;
    protected $amount;

    protected $detail1;
    protected $detail2;
    protected $agentId;

    //first checker
    protected $first_check_by;
    protected $first_check_at;
    protected $first_check_remarks;
    protected $first_check_status;
    protected $payment_mode_request_type;
    protected $receipt_reference_image_url;

    protected $first_check_by_accountID;
    protected $first_check_by_name;

    protected $transaction_type_desc;
    protected $user_profile_accountID;
    protected $user_profile_name;
    protected $user_profile_full_name;
    protected $user_profile_mobile_no;

    protected $bank_name;
    protected $transfer_reference_number;
    protected $date_of_transfer;
    protected $to_bank_name;
    protected $transactionID_mmdd;
    protected $transactionID_last_6_digits;
    
    protected $channelID;
    
    function __construct()
    {
        parent::__construct();
        $this->option = new PaymentRequestOption();
        $this->response = new PaymentRequestResponse();

        $this->detail1 = new PaymentDescription();
        $this->detail2 = new PaymentDescription();

        $this->first_check_at = new IappsDateTime();
        $this->payment_mode_request_type = new SystemCode();
    }

    public function setCountryCode($code)
    {
        $this->country_code = $code;
        return $this;
    }

    public function getCountryCode()
    {
        return $this->country_code;
    }

    public function setUserProfileId($user_profile_id)
    {
        $this->user_profile_id = $user_profile_id;
        return $this;
    }

    public function getUserProfileId()
    {
        return $this->user_profile_id;
    }

    public function setModuleCode($code)
    {
        $this->module_code = $code;
        return $this;
    }

    public function getModuleCode()
    {
        return $this->module_code;
    }

    public function setTransactionID($ID)
    {
        $this->transactionID = $ID;
        return $this;
    }

    public function getTransactionID()
    {
        return $this->transactionID;
    }

    public function setReferenceID($ref_id)
    {
        $this->reference_id = $ref_id;
        return $this;
    }

    public function getReferenceID()
    {
        return $this->reference_id;
    }

    public function setPaymentCode($code)
    {
        $this->payment_code = $code;
        return $this;
    }

    public function getPaymentCode()
    {
        return $this->payment_code;
    }

    public function setOption(PaymentRequestOption $option)
    {
        $this->option = $option;
        return $this;
    }

    public function getOption()
    {
        return $this->option;
    }

    public function setResponse(PaymentRequestResponse $response)
    {
        $this->response = $response;
        return $this;
    }

    public function getResponse()
    {
        return $this->response;
    }

    public function setAgentId($agentId)
    {
        $this->agentId = $agentId;
        return $this;
    }

    public function getAgentId()
    {
        return $this->agentId;
    }

    public function getResponseFields(array $fiels)
    {
        if( $arr = $this->getResponse()->toArray() )
        {
            return ArrayExtractor::extract($arr, $fiels);
        }

        return false;
    }

    public function setStatus($status)
    {
        $this->status = $status;
        return $this;
    }

    public function getStatus()
    {
        return $this->status;
    }

    public function setCountryCurrencyCode($code)
    {
        $this->country_currency_code = $code;
        return $this;
    }

    public function getCountryCurrencyCode()
    {
        return $this->country_currency_code;
    }

    public function setAmount($amount)
    {
        $this->amount = $amount;
        return $this;
    }

    public function getAmount()
    {
        return $this->amount;
    }

    public function setFirstCheckBy($first_check_by)
    {
        $this->first_check_by = $first_check_by;
        return $this;
    }

    public function getFirstCheckBy()
    {
        return $this->first_check_by;
    }

    public function setFirstCheckAt(IappsDateTime $dt)
    {
        $this->first_check_at = $dt;
        return $this;
    }

    public function getFirstCheckAt()
    {
        return $this->first_check_at;
    }

    public function setFirstCheckRemarks($first_check_remarks)
    {
        $this->first_check_remarks = $first_check_remarks;
        return $this;
    }

    public function getFirstCheckRemarks()
    {
        return $this->first_check_remarks;
    }

    public function setFirstCheckStatus($first_check_status)
    {
        $this->first_check_status = $first_check_status;
        return $this;
    }

    public function getFirstCheckStatus()
    {
        return $this->first_check_status;
    }

    public function setPaymentModeRequestType(SystemCode $code)
    {
        $this->payment_mode_request_type = $code;
        return $this;
    }

    public function getPaymentModeRequestType()
    {
        return $this->payment_mode_request_type;
    }

    public function setReceiptReferenceImageUrl($url)
    {
        $s3 = new ReceiptReferenceImageS3Uploader($url);
        $encryptor = Rijndael256EncryptorFactory::build();
        $this->receipt_reference_image_url = new EncryptedS3Url($s3, $encryptor);
        $this->receipt_reference_image_url->setUrl($url);
        return $this;
    }

    public function getReceiptReferenceImageUrl()
    {
        return $this->receipt_reference_image_url;
    }

    public function setFirstCheckByAccountID($first_check_by_accountID)
    {
        $this->first_check_by_accountID = $first_check_by_accountID;
        return $this;
    }

    public function getFirstCheckByAccountID()
    {
        return $this->first_check_by_accountID;
    }

    public function setFirstCheckByName($first_check_by_name)
    {
        $this->first_check_by_name = $first_check_by_name;
        return $this;
    }

    public function getFirstCheckByName()
    {
        return $this->first_check_by_name;
    }

    public function setTransactionTypeDesc($transaction_type_desc)
    {
        $this->transaction_type_desc = $transaction_type_desc;
        return $this;
    }

    public function getTransactionTypeDesc()
    {
        return $this->transaction_type_desc;
    }

    public function setUserProfileAccountID($user_profile_accountID)
    {
        $this->user_profile_accountID = $user_profile_accountID;
        return $this;
    }

    public function getUserProfileAccountID()
    {
        return $this->user_profile_accountID;
    }

    public function setUserProfileName($user_profile_name)
    {
        $this->user_profile_name = $user_profile_name;
        return $this;
    }

    public function getUserProfileName()
    {
        return $this->user_profile_name;
    }

    public function setUserProfileFullName($user_profile_full_name)
    {
        $this->user_profile_full_name = $user_profile_full_name;
        return $this;
    }

    public function getUserProfileFullName()
    {
        return $this->user_profile_full_name;
    }

    public function setUserProfileMobileNo($user_profile_mobile_no)
    {
        $this->user_profile_mobile_no = $user_profile_mobile_no;
        return $this;
    }

    public function getUserProfileMobileNo()
    {
        return $this->user_profile_mobile_no;
    }

    public function setBankName($bank_name)
    {
        $this->bank_name = $bank_name;
        return $this;
    }

    public function getBankName()
    {
        return $this->bank_name;
    }

    public function setTransferReferenceNumber($transfer_reference_number)
    {
        $this->transfer_reference_number = $transfer_reference_number;
        return $this;
    }

    public function getTransferReferenceNumber()
    {
        return $this->transfer_reference_number;
    }

    public function setDateOfTransfer($date_of_transfer)
    {
        $this->date_of_transfer = $date_of_transfer;
        return $this;
    }

    public function getDateOfTransfer()
    {
        return $this->date_of_transfer;
    }

    public function setToBankName($to_bank_name)
    {
        $this->to_bank_name = $to_bank_name;
        return $this;
    }

    public function getToBankName()
    {
        return $this->to_bank_name;
    }

    public function getTransactionNo()
    {
        //$mid = $this->payment_mode_request_type->getCode() != NULL ? strtolower(substr($this->payment_mode_request_type->getCode(), 0, 2)) : "";
        //$transID_mmdd = strlen($this->transactionID) >= 6 ? substr($this->transactionID, 4, 4) : "";
        $mobile_no = strlen($this->user_profile_mobile_no) > 2 ? substr($this->user_profile_mobile_no, 2, $this->user_profile_mobile_no) : "";
        $name = strlen($this->user_profile_name) > 3 ? strtoupper(substr($this->user_profile_name, 0, 3)) : "";
        //$last_6digits = substr($this->transactionID, -6, strlen($this->transactionID));

        //return $mobile_no.$mid.$transID_mmdd.ltrim($last_6digits, '0');
        return $name . " " . $mobile_no;
    }

    public function setTransactionIDMMDD($transactionID_mmdd)
    {
        $this->transactionID_mmdd = $transactionID_mmdd;
        return $this;
    }

    public function getTransactionIDMMDD()
    {
        return $this->transactionID_mmdd;
    }

    public function setTransactionIDLast6Digits($transactionID_last_6_digits)
    {
        $this->transactionID_last_6_digits = $transactionID_last_6_digits;
        return $this;
    }

    public function getTransactionIDLast6Digits()
    {
        return $this->transactionID_last_6_digits;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['country_code'] = $this->getCountryCode();
        $json['user_profile_id'] = $this->getUserProfileId();
        $json['module_code'] = $this->getModuleCode();
        $json['transactionID'] = $this->getTransactionID();
        $json['reference_id'] = $this->getReferenceID();
        $json['payment_code'] = $this->getPaymentCode();
        $json['option'] = $this->getOption()->toJson();
        $json['response'] = $this->getResponse()->toJson();
        $json['status'] = $this->getStatus();
        $json['country_currency_code'] = $this->getCountryCurrencyCode();
        $json['amount'] = $this->getAmount();

        $json['first_check_by'] = $this->getFirstCheckBy();
        $json['first_check_at'] = $this->getFirstCheckAt()->getString();
        $json['first_check_status'] = $this->getFirstCheckStatus();
        $json['first_check_remarks'] = $this->getFirstCheckRemarks();
        $json['payment_mode_type_id'] = $this->getPaymentModeRequestType()->getId();
        $json['payment_mode_type_code'] = $this->getPaymentModeRequestType()->getCode();
        $json['payment_mode_type_name'] = $this->getPaymentModeRequestType()->getDisplayName();
        $json['receipt_reference_image_url'] = $this->getReceiptReferenceImageUrl();
        $json['first_check_by_accountID'] = $this->getFirstCheckByAccountID();
        $json['first_check_by_name'] = $this->getFirstCheckByName();

        $json['transaction_type_desc'] = $this->getTransactionTypeDesc();
        $json['user_profile_accountID'] = $this->getUserProfileAccountID();
        $json['user_profile_name'] = $this->getUserProfileName();
        $json['user_profile_full_name'] = $this->getUserProfileFullName();
        $json['user_profile_mobile_no'] = $this->getUserProfileMobileNo();

        $json['bank_name'] = $this->getBankName();
        $json['transfer_reference_no'] = $this->getTransferReferenceNumber();
        $json['date_of_transfer'] = $this->getDateOfTransfer();
        $json['to_bank_name'] = $this->getToBankName();
        $json['transaction_no'] = $this->getTransactionNo();
        $json['channelID'] = $this->getChannelID();

        return $json;
    }

    public function setSuccess()
    {
        $this->setStatus(PaymentRequestStatus::SUCCESS);
        return $this;
    }

    public function setPending()
    {
        $this->setStatus(PaymentRequestStatus::PENDING);
        return $this;
    }

    public function setFail()
    {
        $this->setStatus(PaymentRequestStatus::FAIL);
        return $this;
    }

    public function setCancelled()
    {
        $this->setStatus(PaymentRequestStatus::CANCELLED);
        return $this;
    }

    /*
     * Only Failed and Cancelled request allowed to request again
     */
    public function allowedNextRequest()
    {
        return ($this->getStatus() == PaymentRequestStatus::FAIL || $this->getStatus() == PaymentRequestStatus::CANCELLED);
    }

    public function setDetail1(PaymentDescription $detail)
    {
        $this->detail1 = $detail;
        return $this;
    }

    public function setDetail2(PaymentDescription $detail)
    {
        $this->detail2 = $detail;
        return $this;
    }

    public function getDetail1()
    {
        return $this->detail1;
    }

    public function getDetail2()
    {
        return $this->detail2;
    }
    
    public function setChannelID($channelID)
    {
        $this->channelID = $channelID;
    }
    
    public function getChannelID()
    {
        return $this->channelID;
    }
    

}