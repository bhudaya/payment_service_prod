<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

class GPLCompany implements \JsonSerializable{

    protected $corporate_id;
    protected $branch_code;
    protected $user_name;
    protected $password;


    public function setCorporateId($corporate_id)
    {
        $this->corporate_id = $corporate_id;
        return $this;
    }

    public function getCorporateId()
    {
        return $this->corporate_id;
    }

    public function setBranchCode($branch_code)
    {
        $this->branch_code = $branch_code;
        return $this;
    }

    public function getBranchCode()
    {
        return $this->branch_code;
    }

    public function setUserName($user_name)
    {
        $this->user_name = $user_name;
        return $this;
    }

    public function getUserName()
    {
        return $this->user_name;
    }

    public function setPassword($password)
    {
        $this->password = $password;
        return $this;
    }

    public function getPassword()
    {
        return $this->password;
    }

    public function jsonSerialize()
    {
        return array(
            'corporate_id' => $this->getCorporateId(),
            'branch_code' => $this->getBranchCode(),
            'user_name' => $this->getUserName(),
            'password' => $this->getPassword()
        );
    }

    public static function fromOption(array $option)
    {
        $company = new self();

        if( array_key_exists('corporate_id', $option) )
            $company->setCorporateId($option['corporate_id']);

        if( array_key_exists('branch_code', $option) )
            $company->setBranchCode($option['branch_code']);

        if( array_key_exists('user_name', $option) )
            $company->setUserName($option['user_name']);

        if( array_key_exists('password', $option) )
            $company->setPassword($option['password']);

        return $company;
    }
}