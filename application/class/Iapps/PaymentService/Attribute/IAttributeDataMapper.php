<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\Common\Core\IappsBaseDataMapper;

interface IAttributeDataMapper extends IappsBaseDataMapper{
    public function findAll();
    public function findByIds(array $ids);
    public function findByCode($code);
    public function findByFilters(AttributeCollection $filters);
    public function insert(Attribute $attribute);
    public function update(Attribute $attribute);
}