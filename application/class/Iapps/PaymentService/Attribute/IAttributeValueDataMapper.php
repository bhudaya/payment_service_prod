<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\Common\Core\IappsBaseDataMapper;

interface IAttributeValueDataMapper extends IappsBaseDataMapper{
    public function findByIds(array $ids);
    public function findByAttributeId($attribute_id);
    public function findByAttributeIds(array $attribute_ids);
    public function findByFilters(AttributeValueCollection $filters);
    public function findAll();
    public function insert(AttributeValue $attribute);
    public function update(AttributeValue $attribute);
}