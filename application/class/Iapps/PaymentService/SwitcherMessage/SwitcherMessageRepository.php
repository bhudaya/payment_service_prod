<?php

namespace Iapps\PaymentService\SwitcherMessage;

use Iapps\Common\Core\Exception\DataMapperException;
use Iapps\Common\Core\IappsBaseDataMapper;
use Iapps\Common\Core\IappsBaseRepository;
use Iapps\Common\Core\Language;

class SwitcherMessageRepository extends IappsBaseRepository
{
    function __construct(IappsBaseDataMapper $dm)
    {
        if( !($dm instanceof ISwitcherMessageMapper) )
        {
            Throw new DataMapperException();
        }

        parent::__construct($dm);
    }

    public function findByParam(SwitcherMessage $obj)
    {
        return $this->getDataMapper()->findByParam($obj);
    }

    public function findListByParam(SwitcherMessage $obj)
    {
        return $this->getDataMapper()->findListByParam($obj);
    }

    public function findMessageByCodeArr(Array $codeArr, SwitcherMessage $obj)
    {
        return $this->getDataMapper()->findMessageByCodeArr($codeArr, $obj);
    }


}