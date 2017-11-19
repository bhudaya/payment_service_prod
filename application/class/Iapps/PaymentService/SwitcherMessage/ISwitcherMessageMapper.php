<?php

namespace Iapps\PaymentService\SwitcherMessage;

use Iapps\Common\Core\IappsBaseDataMapper;

interface ISwitcherMessageMapper extends IappsBaseDataMapper
{
    public function findByParam(SwitcherMessage $obj);
    public function findListByParam(SwitcherMessage $obj);
    public function findMessageByCodeArr(Array $codeArr, SwitcherMessage $obj);
}