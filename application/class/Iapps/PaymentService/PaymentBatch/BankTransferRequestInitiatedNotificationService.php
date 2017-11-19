<?php

namespace  Iapps\PaymentService\PaymentBatch;

use Iapps\PaymentService\Common\CoreConfigDataServiceFactory;
use Iapps\PaymentService\Common\CoreConfigType;
use Iapps\Common\Helper\MessageBroker\BroadcastEventConsumer;
use Iapps\PaymentService\PaymentRequest\ListPaymentRequestServiceFactory;
use Iapps\PaymentService\Common\PaymentEventType;

class BankTransferRequestInitiatedNotificationService extends NotificationService{

    protected $payment_request;
    protected $country_code;

    public function doTask($msg)
    {
        $data = json_decode($msg->body);

        try
        {
            if( isset($data->payment_request_id) )
            {
                $this->_notifyAdmin($data->payment_request_id);
            }
            return true;
        }
        catch(\Exception $e)
        {
            return false;
        }
    }

    public function listenEvent()
    {
        $this->listen(PaymentEventType::PAYMENT_REQUEST_INITIATED, 'BT2', 'payment.queue.notifyNewBankTransferRequest');
    }

    protected function _notifyAdmin($payment_request_id)
    {
        if($payment_request_service = ListPaymentRequestServiceFactory::build()) {

            if($this->payment_request = $payment_request_service->getPaymentRequestInfo($payment_request_id)) {

                $this->country_code = $this->payment_request->getCountryCode();
                $this->_sendEmail();

            }

        }
        return false;
    }

    protected function _getRecipientEmail()
    {
        $code = CoreConfigType::NEW_BANK_TRANSFER_REQUEST_RECIPIENT_EMAIL_SG;
        if($this->country_code == 'ID') {
            $code = CoreConfigType::NEW_BANK_TRANSFER_REQUEST_RECIPIENT_EMAIL_ID;
        }

        $coreconfig = CoreConfigDataServiceFactory::build();
        return $coreconfig->getConfig($code);
    }

    protected function _getEmailSubject()
    {
        $coreconfig = CoreConfigDataServiceFactory::build();
        $subject = $coreconfig->getConfig(CoreConfigType::NEW_BANK_TRANSFER_REQUEST_EMAIL_SUBJECT);

        $subject = str_replace("[TransferType]", $this->payment_request->getPaymentModeRequestType()->getDisplayName(), $subject);

        return $subject;
    }

    protected function _getEmailBody()
    {
        $coreconfig = CoreConfigDataServiceFactory::build();
        $body = $coreconfig->getConfig(CoreConfigType::NEW_BANK_TRANSFER_REQUEST_EMAIL_BODY);

        /*<p></p><p>New bank transfer request:</p>
        <p>[LS]Transaction ID[LE]: [TransactionID]</p>
        <p>[LS]Amount[LE]: [Amount]</p>
        <p>[LS]Transfer Type[LE] : [TransferType]</p>
        <p>[LS]From Bank[LE]: [FromBank]</p>
        <p>[LS]SLIDE Transfer Number[LE]: [TransactionNo]</p>
        <p>[LS]Transfer Ref. No[LE]: [TransferRefNo]</p>
        <p>[LS]Date of Transfer[LE]: [DateOfTransfer]</p>
        <p>[LS]To SLIDE Bank Account[LE]: [ToBank]</p>
        <p></p>
        <p>Please proceed to SLIDE Admin Panel to verify bank transfer request with bank statement account.</p><p></p>*/
        $body = str_replace("[LS]", "<div style='width:25%; font-weight: bold; float:left;margin-right:3px;margin-left:3px'>", $body);
        $body = str_replace("[LE]", "</div>", $body);
        $body = str_replace("[TransactionID]", $this->payment_request->getTransactionID(), $body);
        $body = str_replace("[Amount]", substr($this->payment_request->getCountryCurrencyCode(),3,3)." ".$this->payment_request->getAmount(), $body);
        $body = str_replace("[TransferType]", $this->payment_request->getPaymentModeRequestType()->getDisplayName(), $body);
        $body = str_replace("[FromBank]", $this->payment_request->getBankName(), $body);
        $body = str_replace("[TransactionNo]", $this->payment_request->getTransactionNo(), $body);
        $body = str_replace("[TransferRefNo]", $this->payment_request->getTransferReferenceNumber() ? $this->payment_request->getTransferReferenceNumber() : "-", $body);
        $body = str_replace("[DateOfTransfer]", $this->payment_request->getDateOfTransfer() ? $this->payment_request->getDateOfTransfer() : "-", $body);
        $body = str_replace("[ToBank]", $this->payment_request->getToBankName(), $body);

        return $body;
    }
}