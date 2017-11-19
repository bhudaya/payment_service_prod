<?php

namespace Iapps\PaymentService\Currency;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Core\IappsDateTime;

class Currency extends IappsBaseEntity{

    private $code;
    private $name;
    private $symbol;
    private $denomination;
    private $effective_at;


    public function setCode($code)
    {
        $this->code = strtoupper($code);
        return true;
    }

    public function setName($name)
    {
        $this->name = $name;
        return true;
    }

    public function setSymbol($symbol)
    {
        $this->symbol = $symbol;
        return true;
    }

    public function setDenomination($denomination)
    {
        $this->denomination = $denomination;
        return true;
    }

    public function setEffectiveAt($effective_at)
    {
        $this->effective_at = $effective_at;
        return true;
    }

    public function getCode()
    {
        return $this->code;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getSymbol()
    {
        return $this->symbol;
    }

    public function getDenomination()
    {
        return $this->denomination;
    }

    public function getEffectiveAt()
    {
        return $this->effective_at;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['code'] = $this->getCode();
        $json['name'] = $this->getName();
        $json['symbol'] = $this->getSymbol();
        $json['denomination'] = $this->getDenomination();
        $json['effective_at'] = $this->getEffectiveAt() ? $this->getEffectiveAt()->getString() : "";

        return $json;
    }
}