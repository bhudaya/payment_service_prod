<?php

namespace Iapps\PaymentService\Common;

use Iapps\Common\Helper\FileUploader\S3ImageFileUploader;
use Iapps\Common\Helper\S3Helper\AwsS3HelperFactory;
use Aws\Common\Enum\Region;


class ReceiptReferenceImageS3Uploader extends S3ImageFileUploader{

    function __construct($key)
    {
        if( ENVIRONMENT == 'testing' )
        {
            $aws = AwsS3HelperFactory::build(Region::SINGAPORE, NULL,
                'AKIAJFZS4GMLHQNKU6PA',
                'lR4szDL5ax6oDn7JU0ijtpcJcpSa675ONfCFJdob');
            parent::__construct($aws);
        }
        else
            parent::__construct();

        $this->setS3Folder('receipt_reference/');
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