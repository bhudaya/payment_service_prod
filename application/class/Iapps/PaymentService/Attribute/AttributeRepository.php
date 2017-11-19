<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\Common\Core\IappsBaseRepository;

class AttributeRepository extends IappsBaseRepository{

    public function findByIds(array $ids)
    {
        return $this->getDataMapper()->findByIds($ids);
    }

    public function findAll()
    {
        return $this->getDataMapper()->findAll();
    }

    public function findByCode($code)
    {
        return $this->getDataMapper()->findByCode($code);
    }

    public function findByFilters(AttributeCollection $filters)
    {
        return $this->getDataMapper()->findByFilters($filters);
    }

    public function insert(Attribute $attribute)
    {
        return $this->getDataMapper()->insert($attribute);
    }

    public function update(Attribute $attribute)
    {
        return $this->getDataMapper()->update($attribute);
    }
}