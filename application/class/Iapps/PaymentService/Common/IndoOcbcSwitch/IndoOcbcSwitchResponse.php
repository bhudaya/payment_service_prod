<?php

namespace Iapps\PaymentService\Common\IndoOcbcSwitch;

use Iapps\Common\Helper\ResponseMessage;
use Iapps\PaymentService\PaymentRequest\PaymentRequestResponseInterface;
use Iapps\Common\Helper\StringMasker;

class IndoOcbcSwitchResponse implements PaymentRequestResponseInterface{

    protected $raw;

    protected $product_code;
    protected $merchant_code;
    protected $terminal_code;
    protected $dest_refnumber;
    protected $dest_bankcode;
    protected $dest_bankacc;
    protected $dest_amount;
    protected $timestamp;
    protected $dest_custname;
    protected $purpose;
    protected $relationship;
    protected $recipient_name;
    protected $recipient_address;
    protected $recipient_city;
    protected $recipient_country;
    protected $recipient_postcode;
    protected $recipient_telepon;
    protected $recipient_email;
    protected $sender_name;
    protected $sender_address;
    protected $sender_city;
    protected $sender_postcode;
    protected $sender_country;
    protected $sender_telepon;
    protected $sender_email;
    protected $sender_idcardcode;
    protected $sender_idcardnumber;
    protected $track_number;
    protected $action;
    protected $err_code;
    protected $trx_refferenceid;
    protected $err_description;

    function __construct(array $response)
    {
        $this->setRaw($response);
    }

    protected function _extractResponse(array $fields)
    {
        foreach($fields AS $field => $value )
        {
            if( $field == 'product_code' )
                $this->setProductCode($value);
            if( $field == 'merchant_code')
                $this->setMerchantCode($value);
            if( $field == 'terminal_code')
                $this->setTerminalCode($value);
            if( $field == 'dest_refnumber')
                $this->setDestRefNumber($value);
            if( $field == 'dest_bankcode')
                $this->setDestBankCode($value);
            if( $field == 'dest_bankacc')
                $this->setDestBankAcc($value);
            if( $field == 'dest_amount')
                $this->setDestAmount($value);
            if( $field == 'timestamp')
                $this->setTimeStamp($value);
            if( $field == 'dest_custname')
                $this->setDestCustName($value);
            if( $field == 'purpose')
                $this->setPurpose($value);
            if( $field == 'relationship')
                $this->setRelationship($value);
            if( $field == 'recipient_name')
                $this->setRecipientName($value);
            if( $field == 'recipient_address')
                $this->setRecipientAddress($value);
            if( $field == 'recipient_city')
                $this->setRecipientCity($value);
            if( $field == 'recipient_postcode')
                $this->setRecipientPostcode($value);
            if( $field == 'recipient_country')
                $this->setRecipientCountry($value);
            if( $field == 'recipient_telepon')
                $this->setRecipientTelepon($value);
            if( $field == 'recipient_email')
                $this->setRecipientEmail($value);
            if( $field == 'sender_name')
                $this->setSenderName($value);
            if( $field == 'sender_address')
                $this->setSenderAddress($value);
            if( $field == 'sender_city')
                $this->setSenderCity($value);
            if( $field == 'sender_postcode')
                $this->setSenderPostcode($value);
            if( $field == 'sender_country')
                $this->setSenderCountry($value);
            if( $field == 'sender_telepon')
                $this->setSenderTelepon($value);
            if( $field == 'sender_email')
                $this->setSenderEmail($value);
            if( $field == 'sender_idcardcode')
                $this->setSenderIdCardCode($value);
            if( $field == 'sender_idcardnumber')
                $this->setSenderIdCardNumber($value);
            if( $field == 'track_number')
                $this->setTrackNumber($value);
            if( $field == 'action')
                $this->setAction($value);
            if( $field == 'err_code')
                $this->setErrCode($value);
            if( $field == 'trx_refferenceid')
                $this->setTrxRefferenceId($value);
            if( $field == 'err_description')
                $this->setErrDescription($value);
        }
    }

    public function setRaw(array $raw)
    {
        $this->raw = $raw;
        $this->_extractResponse($raw);
        return $this;
    }

    public function getRaw()
    {
        return $this->raw;
    }


    public function setProductCode($code)
    {
        $this->product_code = $code;
        return $this;
    }

    public function getProductCode()
    {
        return $this->product_code;
    }

    public function setMerchantCode($code)
    {
        $this->merchant_code = $code;
        return $this;
    }

    public function getMerchantCode()
    {
        return $this->merchant_code;
    }

    public function setTerminalCode($code)
    {
        $this->terminal_code = $code;
        return $this;
    }

    public function getTerminalCode()
    {
        return $this->terminal_code;
    }

    public function setDestRefNumber($ref_number)
    {
        $this->dest_refnumber = $ref_number;
        return $this;
    }

    public function getDestRefNumber()
    {
        return $this->dest_refnumber;
    }

    public function setDestBankCode($code)
    {
        $this->dest_bankcode = $code;
        return $this;
    }

    public function getDestBankCode()
    {
        return $this->dest_bankcode;
    }

    public function setDestBankAcc($acc)
    {//mask the last 3 digits
        $this->dest_bankacc = $acc;
        return $this;
    }

    public function getDestBankAcc()
    {
        return $this->dest_bankacc;
    }

    public function setDestAmount($amount)
    {
        $this->dest_amount = $amount;
        return $this;
    }

    public function getDestAmount()
    {
        return $this->dest_amount;
    }

    public function setTimeStamp($timestamp)
    {
        $this->timestamp = $timestamp;
        return $this;
    }

    public function getTimeStamp()
    {
        return $this->timestamp;
    }

    public function setDestCustName($name)
    {
        $this->dest_custname = $name;
        return $this;
    }

    public function getDestCustName()
    {
        return $this->dest_custname;
    }

    public function setPurpose($purpose)
    {
        $this->purpose = $purpose;
        return $this;
    }

    public function getPurpose()
    {
        return $this->purpose;
    }

    public function setRelationship($relationship)
    {
        $this->relationship = $relationship;
        return $this;
    }

    public function getRelationship()
    {
        return $this->relationship;
    }

    public function setRecipientName($name)
    {
        $this->recipient_name = $name;
        return $this;
    }

    public function getRecipientName()
    {
        return $this->recipient_name;
    }

    public function setRecipientAddress($address)
    {
        $this->recipient_address = $address;
        return $this;
    }

    public function getRecipientAddress()
    {
        return $this->recipient_address;
    }

    public function setRecipientCity($city)
    {
        $this->recipient_city = $city;
        return $this;
    }

    public function getRecipientCity()
    {
        return $this->recipient_city;
    }

    public function setRecipientCountry($country)
    {
        $this->recipient_country = $country;
        return $this;
    }

    public function getRecipientCountry()
    {
        return $this->recipient_country;
    }

    public function setRecipientPostcode($postcode)
    {
        $this->recipient_postcode = $postcode;
        return $this;
    }

    public function getRecipientPostcode()
    {
        return $this->recipient_postcode;
    }

    public function setRecipientTelepon($telepon)
    {
        $this->recipient_telepon = $telepon;
        return $this;
    }

    public function getRecipientTelepon()
    {
        return $this->recipient_telepon;
    }

    public function setRecipientEmail($email)
    {
        $this->recipient_email = $email;
        return $this;
    }

    public function getRecipientEmail()
    {
        return $this->recipient_email;
    }

    public function setSenderName($name)
    {
        $this->sender_name = $name;
        return $this;
    }

    public function getSenderName()
    {
        return $this->sender_name;
    }

    public function setSenderAddress($addr)
    {
        $this->sender_address = $addr;
        return $this;
    }

    public function getSenderAddress()
    {
        return $this->sender_address;
    }

    public function setSenderCity($city)
    {
        $this->sender_city = $city;
        return $this;
    }

    public function getSenderCity()
    {
        return $this->sender_city;
    }

    public function setSenderPostcode($postcode)
    {
        $this->sender_postcode = $postcode;
        return $this;
    }

    public function getSenderPostcode()
    {
        return $this->sender_postcode;
    }

    public function setSenderCountry($country)
    {
        $this->sender_country = $country;
        return $this;
    }

    public function getSenderCountry()
    {
        return $this->sender_country;
    }

    public function setSenderTelepon($telepon)
    {
        $this->sender_telepon = $telepon;
        return $this;
    }

    public function getSenderTelepon()
    {
        return $this->sender_telepon;
    }

    public function setSenderEmail($email)
    {
        $this->sender_email = $email;
        return $this;
    }

    public function getSenderEmail()
    {
        return $this->sender_email;
    }

    public function setSenderIdCardCode($code)
    {
        $this->sender_idcardcode = $code;
        return $this;
    }

    public function getSenderIdCardCode()
    {
        return $this->sender_idcardcode;
    }

    public function setSenderIdCardNumber($nbr)
    {
        $this->sender_idcardnumber = $nbr;
        return $this;
    }

    public function getSenderIdCardNumber()
    {
        return $this->sender_idcardnumber;
    }

    public function setTrackNumber($nbr)
    {
        $this->track_number = $nbr;
        return $this;
    }

    public function getTrackNumber()
    {
        return $this->track_number;
    }

    public function setAction($action)
    {
        $this->action = $action;
        return $this;
    }

    public function getAction()
    {
        return $this->action;
    }

    public function setErrCode($code)
    {
        $this->err_code = $code;
        return $this;
    }

    public function getErrCode()
    {
        return $this->err_code;
    }

    public function setTrxRefferenceId($ref_id)
    {
        $this->trx_refferenceid = $ref_id;
        return $this;
    }

    public function getTrxRefferenceId()
    {
        return $this->trx_refferenceid;
    }

    public function setErrDescription($desc)
    {
        $this->err_description = $desc;
        return $this;
    }

    public function getErrDescription()
    {
        return $this->err_description;
    }

    public function getResponse()
    {
        $response = $this->getRaw();
        if( array_key_exists('dest_bankacc', $response) )
            $response['dest_bankacc'] = stringMasker::mask($response['dest_bankacc'], 3);
        return json_encode($response);
    }

    public function isSuccess()
    {
        return $this->getErrCode() == '00';
    }
}