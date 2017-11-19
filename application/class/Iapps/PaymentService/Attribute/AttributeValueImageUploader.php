<?php

namespace Iapps\PaymentService\Attribute;

use Iapps\Common\Helper\FileUploader\S3ImageFileUploader;
use Iapps\Common\Helper\S3Helper\AwsS3HelperFactory;
use Aws\Common\Enum\Region;

/*
 * This will upload the picture publicly!
 */
class AttributeValueImageUploader extends S3ImageFileUploader{

    function __construct($key)
    {
        parent::__construct();

        $this->setS3Folder('payment_attribute_value/');
        $this->setMaxUploadSize(1000000);
        $this->setFileName($key);

        $this->getS3()->setValidPeriod(NULL);
    }

    protected function _uploadOriginaltoS3()
    {
        return $this->getS3()->createPublicObject($this->_getOriginalPath() . $this->getFileName(),
            $this->_getOriginalKey());
    }

    protected function _uploadSmalltoS3()
    {
        return $this->getS3()->createPublicObject($this->_getSmallPath() . $this->getFileName(),
            $this->_getSmallKey());
    }

    protected function _uploadMediumtoS3()
    {
        return $this->getS3()->createPublicObject($this->_getMediumPath() . $this->getFileName(),
            $this->_getMediumKey());
    }

    protected function _uploadLargetoS3()
    {
        return $this->getS3()->createPublicObject($this->_getLargePath() . $this->getFileName(),
            $this->_getLargeKey());
    }
}