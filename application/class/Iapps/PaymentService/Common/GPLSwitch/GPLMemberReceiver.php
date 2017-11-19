<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

class GPLMemberReceiver implements \JsonSerializable{
    protected $country_code;
    protected $receiver_name;
    protected $address;
    protected $KtpNo;
    protected $transaction_type;
    protected $bank_code;
    protected $account_no;
    protected $bank_branch;
    protected $bank_area;
    protected $contact_number;
    protected $relationship;
    protected $receiver_remark;

    public function setCountryCode($country_code)
    {
        $this->country_code = $country_code;
        return $this;
    }

    public function getCountryCode()
    {
        return $this->country_code;
    }

    public function setReceiverName($receiver_name)
    {
        $this->receiver_name = $receiver_name;
        return $this;
    }

    public function getReceiverName()
    {
        return $this->receiver_name;
    }

    public function setAddress($address)
    {
        $this->address = $address;
        return $this;
    }

    public function getAddress()
    {
        return $this->address;
    }

    public function setTransactionType($transaction_type)
    {
        $this->transaction_type = $transaction_type;
        return $this;
    }

    public function getTransactionType()
    {
        return $this->transaction_type;
    }

    public function setBankCode($bank_code)
    {
        $this->bank_code = $bank_code;
        return $this;
    }

    public function getBankCode()
    {
        return $this->bank_code;
    }

    public function setAccountNo($account_no)
    {
        $this->account_no = $account_no;
        return $this;
    }

    public function getAccountNo()
    {
        return $this->account_no;
    }

    public function setBankBranch($bank_branch)
    {
        $this->bank_branch = $bank_branch;
        return $this;
    }

    public function getBankBranch()
    {
        return $this->bank_branch;
    }

    public function setBankArea($bank_area)
    {
        $this->bank_area = $bank_area;
        return $this;
    }

    public function getBankArea()
    {
        return $this->bank_area;
    }

    public function setContactNumber($contact_number)
    {
        $this->contact_number = $contact_number;
        return $this;
    }

    public function getContactNumber()
    {
        return $this->contact_number;
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

    public function setReceiverRemark($receiver_remark)
    {
        $this->receiver_remark = $receiver_remark;
        return $this;
    }

    public function getReceiverRemark()
    {
        return $this->receiver_remark;
    }

    public function setKtpNo($ktpNo)
    {
        $this->KtpNo = $ktpNo;
        return $this;
    }

    public function getKtpNo()
    {
        return $this->KtpNo;
    }

    public function jsonSerialize()
    {
        return array(
            'country_code' => $this->getCountryCode(),
            'receiver_name' => $this->getReceiverName(),
            'address' => $this->getAddress(),
            'KtpNo' => $this->getKtpNo(),
            'transaction_type' => $this->getTransactionType(),
            'bank_code' => $this->getBankCode(),
            'account_no' => $this->getAccountNo(),
            'bank_branch' => $this->getBankBranch() ? $this->getBankBranch() : '-',
            'bank_area' => $this->getBankArea(),
            'contact_number' => $this->getContactNumber(),
            'relationship' => strtoupper($this->getRelationship()),
            'receiver_remark' => $this->getReceiverRemark()
        );
    }

    public static function fromOption(array $option)
    {
        $receiver = new self();

        if( array_key_exists('country_code', $option) )
            $receiver->setCountryCode($option['country_code']);

        if( array_key_exists('receiver_name', $option) )
            $receiver->setReceiverName($option['receiver_name']);

        if( array_key_exists('address', $option) )
            $receiver->setAddress($option['address']);

        if( array_key_exists('KtpNo', $option) )
            $receiver->setKtpNo($option['KtpNo']);

        if( array_key_exists('transaction_type', $option) )
            $receiver->setTransactionType($option['transaction_type']);

        if( array_key_exists('bank_code', $option) )
            $receiver->setBankCode($option['bank_code']);

        if( array_key_exists('account_no', $option) )
            $receiver->setAccountNo($option['account_no']);

        if( array_key_exists('bank_branch', $option) )
            $receiver->setBankBranch($option['bank_branch']);

        if( array_key_exists('bank_area', $option) )
            $receiver->setBankArea($option['bank_area']);

        if( array_key_exists('contact_number', $option) )
            $receiver->setContactNumber($option['contact_number']);

        if( array_key_exists('relationship', $option) )
            $receiver->setRelationship($option['relationship']);

        if( array_key_exists('receiver_remark', $option) )
            $receiver->setReceiverRemark($option['receiver_remark']);

        return $receiver;
    }
}
