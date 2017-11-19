<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Core\IappsDateTime;

class PaymentModeLocation extends IappsBaseEntity{

    protected $payment_code;
    protected $address;
    protected $postal_code;
    protected $latitude;
    protected $longitude;
    protected $operating_hours;

    function __construct()
    {
        parent::__construct();
    }

    public function setPaymentCode($code)
    {
        $this->payment_code = strtoupper($code);
        return $this;
    }

    public function getPaymentCode()
    {
        return $this->payment_code;
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

    public function setPostalCode($postal_code)
    {
        $this->postal_code = $postal_code;
        return $this;
    }

    public function getPostalCode()
    {
        return $this->postal_code;
    }

    public function setLatitude($latitude)
    {
        $this->latitude = $latitude;
        return $this;
    }

    public function getLatitude()
    {
        return $this->latitude;
    }

    public function setLongitude($longitude)
    {
        $this->longitude = $longitude;
        return $this;
    }

    public function getLongitude()
    {
        return $this->longitude;
    }

    public function setOperatingHours($operating_hours)
    {
        $this->operating_hours = $operating_hours;
        return $this;
    }

    public function getOperatingHours()
    {
        return $this->operating_hours;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['payment_code'] = $this->getPaymentCode();
        $json['address'] = $this->getAddress();
        $json['postal_code'] = $this->getPostalCode();
        $json['latitude'] = $this->getLatitude();
        $json['longitude'] = $this->getLongitude();
        $json['operating_hours'] = $this->getOperatingHours();
        
        return $json;
    }
}