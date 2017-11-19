<?php

namespace Iapps\PaymentService\CodeMapper;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\SystemCode\SystemCode;

class CodeMapper extends IappsBaseEntity{

    protected $type;
    protected $reference_value;
    protected $mapped_value;

    function __construct()
    {
        parent::__construct();

        $this->type = new SystemCode();
    }

    public function setType(SystemCode $type)
    {
        $this->type = $type;
        return $this;
    }

    public function getType()
    {
        return $this->type;
    }

    public function setReferenceValue($reference_value)
    {
        $this->reference_value = $reference_value;
        return $this;
    }

    public function getReferenceValue()
    {
        return $this->reference_value;
    }

    public function setMappedValue($mapped_value)
    {
        $this->mapped_value = $mapped_value;
        return $this;
    }

    public function getMappedValue()
    {
        return $this->mapped_value;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['type'] = $this->getType();
        $json['reference_value'] = $this->getReferenceValue();
        $json['mapped_value'] = $this->getMappedValue();

        return $json;
    }
}