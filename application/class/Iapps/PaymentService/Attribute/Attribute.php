<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\Common\Core\IappsBaseEntity;

class Attribute extends IappsBaseEntity{

    protected $selection_only;
    protected $code;
    protected $name;
    protected $description;
    protected $display_order;

    protected $attributeValues;

    function __construct()
    {
        parent::__construct();

        $this->attributeValues = new AttributeValueCollection();
    }

    public function setSelectionOnly($flag)
    {
        $this->selection_only = $flag;
        return $this;
    }

    public function getSelectionOnly()
    {
        return $this->selection_only;
    }

    public function setCode($code)
    {
        $this->code = $code;
        return $this;
    }

    public function getCode()
    {
        return $this->code;
    }

    public function setName($name)
    {
        $this->name = $name;
        return $this;
    }

    public function getName()
    {
        return $this->name;
    }

    public function setDescription($desc)
    {
        $this->description = $desc;
        return $this;
    }

    public function getDescription()
    {
        return $this->description;
    }

    public function setAttributeValues(AttributeValueCollection $attributeValueCollection)
    {
        $this->attributeValues = $attributeValueCollection;
        return $this;
    }

    public function getAttributeValues()
    {
        return $this->attributeValues;
    }

    public function setDisplayOrder($display_order)
    {
        $this->display_order = $display_order;
        return $this;
    }

    public function getDisplayOrder()
    {
        return $this->display_order;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['code'] = $this->getCode();
        $json['name'] = $this->getName();
        $json['selection_only'] = $this->getSelectionOnly();
        $json['description'] = $this->getDescription();
        $json['display_order'] = $this->getDisplayOrder();

        return $json;
    }

    public function isSelectionOnly()
    {   
        return ($this->getSelectionOnly() == '1');
    }

    public function equals(Attribute $attribute)
    {
        return ($attribute->getCode() == $this->getCode());
    }
}

