<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\PaymentService\Attribute\AttributeValue;

class PaymentModeAttributeValue extends IappsBaseEntity{

    protected $payment_mode_attribute;
    protected $attribute_value;

    function __construct()
    {
        parent::__construct();

        $this->payment_mode_attribute = new PaymentModeAttribute();
        $this->attribute_value = new AttributeValue();
    }

    public function setPaymentModeAttributeId($payment_mode_attribute_id)
    {
        $this->payment_mode_attribute->setId($payment_mode_attribute_id);
        return $this;
    }

    public function getPaymentModeAttributeId()
    {
        return $this->payment_mode_attribute->getId();
    }

    public function setPaymentModeAttribute(PaymentModeAttribute $attribute)
    {
        $this->payment_mode_attribute = $attribute;
        return $this;
    }

    public function getPaymentModeAttribute()
    {
        return $this->payment_mode_attribute;
    }

    public function setAttributeValue(AttributeValue $attributeValue)
    {
        $this->attribute_value = $attributeValue;
        return $this;
    }

    public function getAttributeValue()
    {
        return $this->attribute_value;
    }

    public function setCountryCode($country_code)
    {
        $this->getAttributeValue()->setCountryCode($country_code);
        return $this;
    }

    public function getCountryCode()
    {
        return $this->getAttributeValue()->getCountryCode();
    }

    public function setCode($code)
    {
        $this->getAttributeValue()->setCode($code);
        return $this;
    }

    public function getCode()
    {
        return $this->getAttributeValue()->getCode();
    }

    public function setValue($value)
    {
        $this->getAttributeValue()->setValue($value);
        return $this;
    }

    public function getValue()
    {
        return $this->getAttributeValue()->getValue();
    }

    public function setOption($option)
    {
        $this->getAttributeValue()->setOption($option);
        return $this;
    }

    public function getOption()
    {
        return $this->getAttributeValue()->getOption();
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['payment_mode_attribute_id'] = $this->getPaymentModeAttributeId();
        $json['country_code'] = $this->getCountryCode();
        $json['code'] = $this->getCode();
        $json['code'] = $this->getCode();
        $json['value'] = $this->getValue();
        $json['option'] = $this->getOption();
        $json['image_url'] = $this->getAttributeValue()->getImageUrl();

        return $json;
    }
}