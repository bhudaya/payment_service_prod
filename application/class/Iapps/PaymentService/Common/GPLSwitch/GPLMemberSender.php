<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

use Iapps\Common\Core\IappsDateTime;

class GPLMemberSender implements \JsonSerializable{

    protected $full_name;
    protected $gender;
    protected $nationality_country_code;
    protected $identity_card_type;
    protected $identity_card_number;
    protected $identity_card_expiry;
    protected $identity_card_no_expiry = 1;
    protected $date_of_birth;
    protected $occupation;
    protected $income_source;
    protected $address;
    protected $contact_number;
    protected $postal_code;
    protected $member_number;

    function __construct()
    {
        $this->identity_card_expiry = new IappsDateTime();
        $this->date_of_birth = new IappsDateTime();
    }

    public function setFullName($full_name)
    {
        $this->full_name = $full_name;
        return $this;
    }

    public function getFullName()
    {
        return $this->full_name;
    }

    public function setGender($gender)
    {
        $this->gender = $gender;
        return $this;
    }

    public function getGender()
    {
        return $this->gender;
    }

    public function setNationalityCountryCode($nationality_country_code)
    {
        $this->nationality_country_code = $nationality_country_code;
        return $this;
    }

    public function getNationalityCountryCode()
    {
        return $this->nationality_country_code;
    }

    public function setIdentityCardType($identity_card_type)
    {
        $this->identity_card_type = $identity_card_type;
        return $this;
    }

    public function getIdentityCardType()
    {
        return $this->identity_card_type;
    }

    public function setIdentityCardNumber($identity_card_number)
    {
        $this->identity_card_number = $identity_card_number;
        return $this;
    }

    public function getIdentityCardNumber()
    {
        return $this->identity_card_number;
    }

    public function setIdentityCardExpiry(IappsDateTime $identity_card_expiry)
    {
        $this->identity_card_expiry = $identity_card_expiry;

        $this->setIdentityCardNoExpiry(0);
        return $this;
    }

    public function getIdentityCardExpiry()
    {
        return $this->identity_card_expiry;
    }

    public function setIdentityCardNoExpiry($identity_card_no_expiry)
    {
        $this->identity_card_no_expiry = $identity_card_no_expiry;
        return $this;
    }

    public function getIdentityCardNoExpiry()
    {
        return $this->identity_card_no_expiry;
    }

    public function setDateOfBirth(IappsDateTime $date_of_birth)
    {
        $this->date_of_birth = $date_of_birth;
        return $this;
    }

    public function getDateOfBirth()
    {
        return $this->date_of_birth;
    }

    public function setOccupation($occupation)
    {
        $this->occupation = $occupation;
        return $this;
    }

    public function getOccupation()
    {
        return $this->occupation;
    }

    public function setIncomeSource($income_source)
    {
        $this->income_source = $income_source;
        return $this;
    }

    public function getIncomeSource()
    {
        return $this->income_source;
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

    public function setContactNumber($contact_number)
    {
        $this->contact_number = $contact_number;
        return $this;
    }

    public function getContactNumber()
    {
        return $this->contact_number;
    }

    public function setPostalCode($postal_code)
    {
        $this->postal_code = $postal_code;
        return $this;
    }

    public function getPostalCode()
    {
        return $this->postal_code;
    }

    public function setMemberNumber($member_number)
    {
        $this->member_number = $member_number;
        return $this;
    }

    public function getMemberNumber()
    {
        return $this->member_number;
    }

    public function jsonSerialize()
    {
        return array(
            'member_number' => $this->getMemberNumber(),
            'full_name' => $this->getFullName(),
            'gender' => $this->getGender(),
            'nationality_country_code' => $this->getNationalityCountryCode(),
            'identity_card_type' => $this->getIdentityCardType(),
            'identity_card_number' => $this->getIdentityCardNumber(),
            'identity_card_expiry' => !$this->getIdentityCardExpiry()->isNull() ? $this->getIdentityCardExpiry()->getFormat('d/m/Y') : NULL,
            'identity_card_no_expiry' => $this->getIdentityCardNoExpiry(),
            'date_of_birth' => !$this->getDateOfBirth()->isNull() ? $this->getDateOfBirth()->getFormat('d/m/Y') : NULL,
            'occupation' => strtoupper($this->getOccupation()),
            'income_source' => strtoupper($this->getIncomeSource()),
            'address' => $this->getAddress(),
            'contact_number' => $this->getContactNumber(),
            'postal_code' => $this->getPostalCode()
        );
    }

    public static function fromOption(array $option)
    {
        $sender = new self();

        if( array_key_exists('member_number', $option) )
            $sender->setMemberNumber($option['member_number']);

        if( array_key_exists('full_name', $option) )
            $sender->setFullName($option['full_name']);

        if( array_key_exists('gender', $option) )
            $sender->setGender($option['gender']);

        if( array_key_exists('nationality_country_code', $option) )
            $sender->setNationalityCountryCode($option['nationality_country_code']);

        if( array_key_exists('identity_card_type', $option) )
            $sender->setIdentityCardType($option['identity_card_type']);

        if( array_key_exists('identity_card_number', $option) )
            $sender->setIdentityCardNumber($option['identity_card_number']);

        if( array_key_exists('identity_card_expiry', $option) )
            $sender->setIdentityCardExpiry(IappsDateTime::fromString(implode("-", array_reverse(explode("/", $option['identity_card_expiry'])))));

        if( array_key_exists('identity_card_no_expiry', $option) )
            $sender->setIdentityCardNoExpiry($option['identity_card_no_expiry']);

        if( array_key_exists('date_of_birth', $option) )
            $sender->setDateOfBirth(IappsDateTime::fromString(implode("-", array_reverse(explode("/", $option['date_of_birth'])))));

        if( array_key_exists('occupation', $option) )
            $sender->setOccupation($option['occupation']);

        if( array_key_exists('income_source', $option) )
            $sender->setIncomeSource($option['income_source']);

        if( array_key_exists('address', $option) )
            $sender->setAddress($option['address']);

        if( array_key_exists('contact_number', $option) )
            $sender->setContactNumber($option['contact_number']);

        if( array_key_exists('postal_code', $option) )
            $sender->setPostalCode($option['postal_code']);

        return $sender;
    }
}