<?php

namespace Iapps\PaymentService\Payment;

use Iapps\PaymentService\ValueObject\EncryptedFieldFactory;

class PaymentDescription{

    protected $data = array();
    protected $value;

    function __construct()
    {
        $this->value = EncryptedFieldFactory::build();
    }

    public function add($title, $value)
    {
        $field['title'] = $title;
        $field['value'] = $value;

        $this->data[] = $field;
        return $this;
    }

    public function setArray(array $option)
    {
        $this->data = $option;
    }

    public function setJson($option)
    {
        $this->data = json_decode($option, true);
    }

    public function toArray()
    {
        return $this->data;
    }

    public function toJson()
    {
        return json_encode($this->data);
    }

    public function setEncryptedValue($encryptedValue)
    {
        $value = EncryptedFieldFactory::build()->setEncryptedValue($encryptedValue)
                                               ->getValue();
        $this->setJson($value);
        return $this;
    }

    public function getEncryptedValue()
    {
        return EncryptedFieldFactory::build()->setValue($this->toJson())
            ->getEncodedValue();
    }
}