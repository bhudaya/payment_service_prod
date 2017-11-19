<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\RemittanceService\Common\CountryCodeValidator;
use Iapps\Common\Validator\IappsValidator;

class AttributeValueValidator extends IappsValidator{

    protected $attribute_value;
    public static function make(AttributeValue $attribute_value)
    {
        $v = new AttributeValueValidator();
        $v->attribute_value = $attribute_value;
        $v->validate();

        return $v;
    }

    public function validate()
    {
        $this->isFailed = true;

        if( $this->_validateValue() AND
            $this->_validateCountryCode() )
        {
            $this->isFailed = false;
        }
    }

    protected function _validateValue()
    {
        if( $value = $this->attribute_value->getValue() )
        {
            $input_type = $this->attribute_value->getAttribute()->getInputType();

            switch($input_type)
            {
                case AttributeInputType::NUMBER:
                    return is_numeric($value);
                    break;
                case AttributeInputType::TEXT:
                    return $value != NULL;
                    break;
                default:
                    return false;
                    break;
            }
        }

        return false;
    }

    protected function _validateCountryCode()
    {
        if( $code = $this->attribute_value->getCountryCode() )
        {
            $v = CountryCodeValidator::make($code);
            return !$v->fails();
        }

        //code can be null
        return true;
    }
}
