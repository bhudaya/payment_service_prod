<?php

namespace Iapps\PaymentService\PaymentRequest;

class PaymentRequestOption{

    protected $option;

    function __construct()
    {
        $this->option = array();
    }

    public function setArray(array $option)
    {
        $this->option = $option;
    }

    public function setJson($option)
    {
        $this->option = json_decode($option, true);
    }

    public function add($key, $value)
    {
        $this->option[$key] = $value;
        return $this;
    }

    public function remove($key)
    {
        if( array_key_exists($key, $this->option) )
            unset($this->option[$key]);

        return $this;
    }

    public function getValue($key)
    {
        if( array_key_exists($key, $this->option) )
            return $this->option[$key];

        return false;
    }

    public function toArray()
    {
        return $this->option;
    }

    public function toJson()
    {
        return json_encode($this->option);
    }
}