<?php

namespace Iapps\PaymentService\PaymentModeAttribute;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\PaymentService\Attribute\Attribute;
use Iapps\PaymentService\PaymentMode\PaymentMode;

class PaymentModeAttribute extends IappsBaseEntity{

    protected $attribute;
    protected $payment_mode;
    protected $values;

    public function __construct()
    {
        parent::__construct();

        $this->values = new PaymentModeAttributeValueCollection();
        $this->attribute = new Attribute();
        $this->payment_mode = new PaymentMode();
    }

    public function setAttribute(Attribute $attribute)
    {
        $this->attribute = $attribute;
        return $this;
    }

    public function getAttribute()
    {
        return $this->attribute;
    }

    public function setName($name)
    {
        $this->getAttribute()->setName($name);
        return $this;
    }

    public function getName()
    {
        return $this->getAttribute()->getName();
    }

    public function setPaymentMode(PaymentMode $paymentMode)
    {
        $this->payment_mode = $paymentMode;
        return $this;
    }

    public function getPaymentMode()
    {
        return $this->payment_mode;
    }

    public function setPaymentCode($payment_code)
    {
        $this->payment_mode->setCode($payment_code);
        return $this;
    }

    public function getPaymentCode()
    {
        return $this->payment_mode->getCode();
    }

    public function setValue(PaymentModeAttributeValueCollection $value)
    {
        $this->values = $value;
        return $this;
    }

    /**
     * 
     * @return PaymentModeAttributeValueCollection
     */
    public function getValue()
    {
        return $this->values;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['payment_code'] = $this->getPaymentCode();
        $json['attribute'] = $this->getAttribute()->getCode();
        $json['name'] = $this->getAttribute()->getName();
        $json['selection_only'] = $this->getAttribute()->getSelectionOnly();
        $json['value'] = $this->getValue();

        return $json;
    }

    public function getSelectedField(array $fields)
    {
        $array = parent::getSelectedField($fields);
        if( array_key_exists('value', $fields) )
        {
            if( is_array($fields['value']) )
                $array['value'] = $this->getValue()->getSelectedField($fields['value']);
        }

        return $array;
    }
}