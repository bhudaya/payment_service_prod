<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\PaymentAccess\PaymentAccessCheckerFactory;
use Iapps\PaymentService\PaymentRequest\PaymentModeRequestType;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;

class ManualBankTransferPaymentRequestValidator extends PaymentRequestValidator
{
    public function validate()
    {
        parent::validate();

        if( !$this->fails() )
        {
            if( !$this->_validateAccess() OR
                !$this->_validateSwitchParameter() )
                $this->isFailed = true;
        }
    }

    protected function _validateAccess()
    {
        $access_checker = PaymentAccessCheckerFactory::build($this->request->getPaymentCode());

        if( $this->request->getAmount() < 0 )
            $result = $access_checker->checkDirectionOut(NULL);
        else
            $result = $access_checker->checkDirectionIn(NULL);

        if( $result )
            return true;

        $this->setErrorCode(MessageCode::CODE_PAYMENT_NOT_ACCESSIBLE);
        return false;
    }

    protected function _validateSwitchParameter()
    {
        $validation_array =  array('payment_mode_request_type', 'bank_code','bank_name', 'to_bank_code', 'to_bank_name');
        //{"payment_code":"BT2", "country_currency_code":"SG-SGD", "amount":5, "option":{"bank_code":"001","bank_name":"BCA","transfer_reference_number":"123450001","date_of_transfer":"2016-07-25","to_bank_code":"014","to_bank_name":"BCA - SLIDE 5270112345","payment_mode_request_type":"atm/ibanking", "receipt_reference_image_name":"<image_name.png>"}}
        $option = $this->request->getOption()->toArray();
        if (array_key_exists('payment_mode_request_type', $option)) {
            if(isset($option['payment_mode_request_type'])) {
                if($option['payment_mode_request_type'] == PaymentModeRequestType::ATM) {
                    $validation_array_add = array ('receipt_reference_image_name', 'date_of_transfer');
                    $validation_array = array_merge($validation_array, $validation_array_add);
                }
            }
        }

        $v = PaymentRequestOptionValidator::make($this->request->getOption(), $validation_array);
        return !$v->fails();
    }
}