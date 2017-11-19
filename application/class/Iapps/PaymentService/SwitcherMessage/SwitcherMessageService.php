<?php

namespace Iapps\PaymentService\SwitcherMessage;

use Iapps\Common\Core\Exception\DataRepositoryException;
use Iapps\Common\Core\IappsBaseRepository;
use Iapps\Common\Core\IappsBaseService;

class SwitcherMessageService extends IappsBaseService{

    function __construct(IappsBaseRepository $rp)
    {
        if( !($rp instanceof SwitcherMessageRepository) )
        {
            Throw new DataRepositoryException();
        }

        parent::__construct($rp);
    }

    public function getMessage($code, $lang ,$switcher_code)
    {
        $Switcher_message = new SwitcherMessage();
        $Switcher_message->setCode((string)$code);
        $Switcher_message->setLang($lang);        
        $Switcher_message->setSwitcherCode($switcher_code);

        if( $data = $this->getRepository()->findByParam($Switcher_message) )
        {
            return $data->getMessage();
        }

        return false;
    }

    public function getAllConfigByCode($code, $likeSide = NULL)
    {
        if( $data = $this->getRepository()->getAllConfigByCode($code, $likeSide) )
        {
            return $data;
        }

        return false;
    }

}