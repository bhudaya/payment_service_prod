<?php

namespace Iapps\PaymentService\PaymentRequest;

/*
 * The purpose is to initialize the 
 * channelID from the base controller.
 * so that we can call the static channelID
 * via service level anywhere. to cater
 * for the new channelID column in 
 * payment and payment_request table
 */
class PaymentRequestStaticChannel {
    
    public static $channelID = NULL;
    public static $channelCode = NULL;

    public static function build($channelID,$channelCode)
    {
        if( self::$channelID == NULL )
        {
            self::$channelID = $channelID;
        }
        
        if(self::$channelCode == NULL)
        {
            self::$channelCode = $channelCode;
        }

        return self::$channelID;
    }
    
}
