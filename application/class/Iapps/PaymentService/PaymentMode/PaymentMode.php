<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Core\IappsDateTime;
use Iapps\Common\SystemCode\SystemCode;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeCollection;

class PaymentMode extends IappsBaseEntity{

    protected $code;
    protected $name;
    protected $payment_mode_group;
    protected $self_service;
    protected $need_approval;
    protected $for_refund;
    protected $is_payment_mode;
    protected $is_collection_mode;
    protected $delivery_time;

    protected $attributes;

    function __construct()
    {
        parent::__construct();

        $this->payment_mode_group = new SystemCode();
        $this->delivery_time = new SystemCode();
        $this->attributes = new PaymentModeAttributeCollection();
    }

    public function setCode($code)
    {
        $this->code = strtoupper($code);
        return $this;
    }

    public function setName($name)
    {
        $this->name = $name;
        return $this;
    }

    public function getCode()
    {
        return $this->code;
    }

    public function getName()
    {
        return $this->name;
    }

    public function setPaymentModeGroup(SystemCode $payment_mode_group)
    {
        $this->payment_mode_group = $payment_mode_group;
        return $this;
    }

    public function getPaymentModeGroup()
    {
        return $this->payment_mode_group;
    }

    public function setSelfService($self_service)
    {
        $this->self_service = $self_service;
        return $this;
    }

    public function getSelfService()
    {
        return $this->self_service;
    }

    public function setNeedApproval($need_approval)
    {
        $this->need_approval = $need_approval;
        return $this;
    }

    public function getNeedApproval()
    {
        return $this->need_approval;
    }

    public function setForRefund($for_refund)
    {
        $this->for_refund = $for_refund;
        return $this;
    }

    public function getForRefund()
    {
        return $this->for_refund;
    }

    public function setIsPaymentMode($is_payment_mode)
    {
        $this->is_payment_mode = $is_payment_mode;
        return $this;
    }

    public function getIsPaymentMode()
    {
        return $this->is_payment_mode;
    }

    public function setIsCollectionMode($is_collection_mode)
    {
        $this->is_collection_mode = $is_collection_mode;
        return $this;
    }

    public function getIsCollectionMode()
    {
        return $this->is_collection_mode;
    }

    public function setDeliveryTime(SystemCode $delivery_time)
    {
        $this->delivery_time = $delivery_time;
        return $this;
    }

    public function getDeliveryTime()
    {
        return $this->delivery_time;
    }

    public function setAttributes(PaymentModeAttributeCollection $attributeCollection)
    {
        $this->attributes = $attributeCollection;
        return $this;
    }

    public function getAttributes()
    {
        return $this->attributes;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['code'] = $this->getCode();
        $json['name'] = $this->getName();
        $json['payment_mode_group'] = $this->getPaymentModeGroup()->getCode();
        $json['self_service'] = (bool)$this->getSelfService();
        $json['need_approval'] = (bool)$this->getNeedApproval();
        $json['for_refund'] = (bool)$this->getForRefund();
        $json['is_payment_mode'] = (bool)$this->getIsPaymentMode();
        $json['is_collection_mode'] = (bool)$this->getIsCollectionMode();
        $json['delivery_time'] = $this->getDeliveryTime()->getCode();

        return $json;
    }
}