<?php

namespace  Iapps\PaymentService\PaymentBatch;

use Iapps\Common\ChatService\ChatServiceProducer;
use Iapps\Common\ChatService\NotificationChannel;
use Iapps\Common\ChatService\NotificationTag;
use Iapps\Common\CommunicationService\CommunicationServiceProducer;
use Iapps\Common\Helper\MessageBroker\BroadcastEventConsumer;

abstract class NotificationService extends BroadcastEventConsumer{

    protected function _sendEmail()
    {
        if ($email = $this->_getRecipientEmail() AND
            $subject = $this->_getEmailSubject() AND
            $body = $this->_getEmailBody()
        ) {
            $communication = new CommunicationServiceProducer();
            return $communication->sendEmail(getenv("ICS_PROJECT_ID"), $subject, $body, $body, array($email));
        }

        return false;
    }

    abstract protected function _getRecipientEmail();
    abstract protected function _getEmailSubject();
    abstract protected function _getEmailBody();
}