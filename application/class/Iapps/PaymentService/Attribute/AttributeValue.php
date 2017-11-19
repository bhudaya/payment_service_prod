<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\Common\Core\IappsBaseEntity;
use Iapps\Common\Core\S3FileUrl;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\PaymentService\Common\Logger;

class AttributeValue extends IappsBaseEntity{

    protected $country_code;
    protected $attribute;
    protected $code;
    protected $value;
    protected $option;
    protected $imageUrl;    
                
    function __construct()
    {
        parent::__construct();

        $this->attribute = new Attribute();
        $this->imageUrl = new S3FileUrl(NULL);
    }

    public function setCountryCode($country_code)
    {
        $this->country_code = $country_code;
        return $this;
    }

    public function getCountryCode()
    {
        return $this->country_code;
    }

    public function setAttribute(Attribute $attribute)
    {
        $this->attribute = $attribute;
        return $this;
    }

    public function getAttribute()
    {
        return $this->attribute;
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

    public function setValue($value)
    {
        $this->value = $value;
        return $this;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function setOption($option)
    {
        $this->option = $option;
        return $this;
    }

    public function getOption()
    {
        return $this->option;
    }

    public function setImageUrl($url)
    {
        $this->imageUrl->setUrl($url);
        return $this;
    }

    public function getImageUrl()
    {
        if( $url = $this->imageUrl->getUrl() )
        {
            $s3 = AttributeValueImageUploaderFactory::build($url);
            $this->imageUrl->setUrl($url, $s3); //update s3 url
        }
        return $this->imageUrl;        
    }

    public function checkOption(array $collectionInfo)
    {
        if($option = json_decode($this->getOption(),true) AND isset($option['validation']))
        {
            foreach($option['validation'] as $field=> $v){
                foreach($v as $vField => $vValue){
                    if( isset($collectionInfo[$field]) )
                    {
                        $checkValue = $collectionInfo[$field];
                        if(key($v[$vField]) == 'length'){
                            $len = strlen($collectionInfo[$field]);
                            $vValue = $v[$vField]['length'];
                            $vValueArr = explode(",", $vValue);
                            if(!in_array($len, $vValueArr)){
                                Logger::debug('payment_mode.validate: '. $field . '(' . $checkValue .') length('.$len.
                                    ' != '. $vValue .') incorrect');
                                return false;
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    public function jsonSerialize()
    {
        $json = parent::jsonSerialize();

        $json['country_code'] = $this->getCountryCode();
        $json['attribute_id'] = $this->getAttribute()->getId();
        $json['code'] = $this->getCode();
        $json['value'] = $this->getValue();
        $json['option'] = $this->getOption();
        $json['image_url'] = $this->getImageUrl();

        return $json;
    }

    public static function createNew(Attribute $attribute, $value, $country_code)
    {
        $val = new AttributeValue();
        $val->setId(GuidGenerator::generate());
        $val->setAttribute($attribute);
        $val->setValue($value);
        $val->setCountryCode($country_code);

        return $val;
    }
}