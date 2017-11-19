<?php

namespace Iapps\PaymentService\SwitcherMessage;

use Iapps\Common\Core\IappsBaseEntity;

class SwitcherMessage extends IappsBaseEntity{

    protected $lang = NULL;
    protected $code = NULL;
    protected $message = NULL;
    protected $switcher_code = NULL;

     
    public function getSwitcherCode()
    {
        return $this->switcher_code;
    }    
    public function setSwitcherCode($switcher_code)
    {
        $this->switcher_code = $switcher_code;
    }

    public function setLang($lang)
    {
        $this->lang = $lang;
        return true;
    }   

    public function getLang()
    {
        return $this->lang;
    }

    public function setCode($code)
    {
        $this->code = $code;
        return true;
    }

    public function getCode()
    {
        return $this->code;
    }

    public function setMessage($message)
    {
        $this->message = $message;
        return true;
    }

    public function getMessage()
    {
        return $this->message;
    }
}