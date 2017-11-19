<?php

namespace Iapps\PaymentService\Payment;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\SystemCode\SystemCode;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Payment\PaymentUserType;
use Iapps\PaymentService\Common\Rijndael256EncryptorFactory;
use Iapps\Common\Helper\EncryptedS3Url;
use Iapps\PaymentService\Common\ReceiptReferenceImageS3Uploader;


class Payment extends IappsBaseEntity{
    protected $country_code;
    protected $module_code;
    protected $transactionID;
    protected $user_profile_id;
    protected $country_currency_code;
    protected $amount;
    protected $status;
    protected $payment_code;
    protected $ewallet_id;
    protected $receipt_url;
    protected $payment_request_id;
    protected $description1;
    protected $description2;
    protected $payment_mode_name;
    protected $agent_id;
    protected $requested_by;
    protected $date_from;
    protected $date_to;
    protected $user_type;
    protected $is_agent_id_null = -1;
    protected $channelID;
    protected $channelCode;

    function __construct()
    {
        parent::__construct();

        $this->status = new SystemCode();

        $this->description1 = new PaymentDescription();
        $this->description2 = new PaymentDescription();
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

    public function setModuleCode($code)
    {
        $this->module_code = $code;
        return $this;
    }

    public function getModuleCode()
    {
        return $this->module_code;
    }

    public function setTransactionID($trx_id)
    {
        $this->transactionID = $trx_id;
        return $this;
    }

    public function getTransactionID()
    {
        return $this->transactionID;
    }

    public function setUserProfileId($id)
    {
        $this->user_profile_id = $id;
        return $this;
    }

    public function getUserProfileId()
    {
        return $this->user_profile_id;
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

    public function setStatus(SystemCode $code)
    {
        $this->status = $code;
        return $this;
    }

    public function getStatus()
    {
        return $this->status;
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

    public function setEwalletId($id)
    {
        $this->ewallet_id = $id;
        return $this;
    }

    public function getEwalletId()
    {
        return $this->ewallet_id;
    }

    public function setReceiptUrl($url)
    {
        $this->receipt_url = $url;
        return $this;
    }

    public function getReceiptUrl()
    {
        return $this->receipt_url;
    }

    public function setPaymentRequestId($id)
    {
        $this->payment_request_id = $id;
        return $this;
    }

    public function getPaymentRequestId()
    {
        return $this->payment_request_id;
    }

    public function setDescription1( PaymentDescription $desc)
    {
        $this->description1 = $desc;
        return $this;
    }

    public function setDescription2( PaymentDescription $desc)
    {
        $this->description2 = $desc;
        return $this;
    }

    public function getDescription1()
    {
        return $this->description1;
    }

    public function getDescription2()
    {
        return $this->description2;
    }

    public function setPaymentModeName($payment_mode_name)
    {
        $this->payment_mode_name = $payment_mode_name;
        return $this;
    }

    public function getPaymentModeName()
    {
        return $this->payment_mode_name;
    }

    public function setAgentId($agent_id)
    {
        $this->agent_id = $agent_id;
        return $this;
    }

    public function getAgentId()
    {
        return $this->agent_id;
    }

    public function setRequestedBy($requested_by)
    {
        $this->requested_by = $requested_by;
        return $this;
    }

    public function getRequestedBy()
    {
        return $this->requested_by;
    }

    public function setDateFrom(IappsDateTime $date_from)
    {
        $this->date_from = $date_from;
        return $date_from;
    }

    public function getDateFrom()
    {
        return $this->date_from;
    }

    public function setDateTo(IappsDateTime $date_to)
    {
        $this->date_to = $date_to;
        return $date_to;
    }

    public function getDateTo()
    {
        return $this->date_to;
    }

    public function setUserType($user_type)
    {
        $this->user_type = $user_type;
        return $this;
    }

    public function getUserType()
    {
        return $this->user_type;
    }

    public function setIsAgentIdNull($is_agent_id_null)
    {
        $this->is_agent_id_null = $is_agent_id_null;
        return $this;
    }

    public function getIsAgentIdNull()
    {
        return $this->is_agent_id_null;
    }
    
    public function setChannelID($channelID)
    {
        $this->channelID = $channelID;
    }
    
    public function getChannelID()
    {
        return $this->channelID;
    }
    
    public function setChannelCode($channelCode)
    {
        $this->channelCode = $channelCode;
    }
    
    public function getChannelCode()
    {
        return $this->channelCode;
    }
    
    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['country_code'] = $this->getCountryCode();
        $json['module_code'] = $this->getModuleCode();
        $json['transactionID'] = $this->getTransactionID();
        $json['user_profile_id'] = $this->getUserProfileId();
        $json['country_currency_code'] = $this->getCountryCurrencyCode();
        $json['amount'] = $this->getAmount();
        $json['status'] = (null !== $this->getStatus()->getCode())?$this->getStatus()->getCode():$this->getPaymentRequestStatus();
        $json['payment_code'] = $this->getPaymentCode();
        $json['ewallet_id'] = $this->getEwalletId();
        $json['receipt_url'] = $this->getReceiptUrl();
        $json['payment_request_id'] = $this->getPaymentRequestId();
        $json['description1'] = $this->getDescription1()->toJson();
        $json['description2'] = $this->getDescription2()->toJson();
        $json['agent_id'] = $this->getAgentId();
        $json['requested_by'] = $this->getRequestedBy();
        $json['payment_mode_name'] = $this->getPaymentModeName();
        $json['user_type'] = $this->getUserType();
        $json['channelID'] = $this->getChannelID();

        return $json;
    }


    public static function createFromPaymentRequest(PaymentRequest $request)
    {
        $payment = new Payment();
        $payment->setId(GuidGenerator::generate());
        $payment->setCountryCode($request->getCountryCode());
        $payment->setUserProfileId($request->getUserProfileId());
        $payment->setModuleCode($request->getModuleCode());
        $payment->setTransactionID($request->getTransactionID());
        $payment->setCountryCurrencyCode($request->getCountryCurrencyCode());
        $payment->setAmount($request->getAmount());
        $payment->setPaymentCode($request->getPaymentCode());
        $payment->setPaymentRequestId($request->getId());

        $payment->setDescription1($request->getDetail1());
        $payment->setDescription2($request->getDetail2());
        $payment->setRequestedBy($request->getCreatedBy());
        $payment->setAgentId($request->getAgentId());
        $payment->setChannelID($request->getChannelID());

        //set payment user type for filtering purpose
        if($request->getOption())
        {
            $option = $request->getOption()->toArray();
            if (array_key_exists('user_type', $option)) {
                if(isset($option['user_type'])) {
                    if($option['user_type'] == PaymentUserType::USER || $option['user_type'] == PaymentUserType::AGENT ||
                        $option['user_type'] == PaymentUserType::ADMIN || $option['user_type'] == PaymentUserType::PARTNER) {
                        $payment->setUserType($option['user_type']);
                    }
                }
            }
        }

        return $payment;
    }

    public function complete()
    {
        $this->getStatus()->setCode(PaymentStatus::COMPLETE);
        return $this;
    }
}