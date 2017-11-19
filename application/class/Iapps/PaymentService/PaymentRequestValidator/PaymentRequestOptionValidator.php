<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

use Iapps\Common\Validator\IappsValidator;
use Iapps\PaymentService\PaymentRequest\PaymentRequestOption;

class PaymentRequestOptionValidator extends IappsValidator{

    protected $option;
    protected $fields;

    public static function make(PaymentRequestOption $option, array $fields)
    {
        $v = new static();
        $v->option = $option;
        $v->fields = $fields;
        $v->validate();

        return $v;
    }

    public function validate()
    {
        $this->isFailed = false;
        foreach($this->fields AS $field)
        {
            if(!$this->option->getValue($field))
                $this->isFailed = true;
        }
    }
}