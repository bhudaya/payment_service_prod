<?php

namespace Iapps\PaymentService\PaymentRequestValidator;

use Iapps\Common\Helper\RequestHeader;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Validator\IappsValidator;
use Iapps\PaymentService\CountryCurrency\CountryCurrencyServiceFactory;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\PaymentAccess\PaymentAccessCheckerFactory;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;

class PaymentRequestValidator extends IappsValidator{

    protected $request;
    public static function make(PaymentRequest $request)
    {
        $v = new static();
        $v->request = $request;
        $v->validate();

        return $v;
    }

    public function validate()
    {
        $this->isFailed = false;

        //validate country currency
        if( !$this->_validateCountryCurrency() )
            $this->isFailed = true;

        if( !$this->_validateTransactionID() )
            $this->isFailed = true;

        if( !$this->_validateAmount() )
            $this->isFailed = true;

        if( !$this->_validateAccess() )
            $this->isFailed = true;

    }

    /*
     * validate if country currency code is valid
     */
    protected function _validateCountryCurrency()
    {
        $country_cur_serv = CountryCurrencyServiceFactory::build();
        if( $info = $country_cur_serv->getCountryCurrencyInfo($this->request->getCountryCurrencyCode()) )
        {
            $this->request->setCountryCode($info['country_code']);
            return $info;
        }

        $this->setErrorCode(MessageCode::CODE_COUNTRY_CURRENCY_INVALID_CURRENCY_CODE);
        return false;
    }

    /*
     * validate if there is only one active transaction ID
     */
    protected function _validateTransactionID()
    {
        return ($this->request->getModuleCode() !== NULL AND $this->request->getTransactionID() !== NULL );
    }

    protected function _validateAmount()
    {
        return ($this->request->getAmount() <> 0.0);
    }

    protected function _validateAccess()
    {
        $access_checker = PaymentAccessCheckerFactory::build($this->request->getPaymentCode());

        $headers = RequestHeader::get();
        $token = NULL;
        if( array_key_exists(ResponseHeader::FIELD_X_AUTHORIZATION, $headers) )
            $token = $headers[ResponseHeader::FIELD_X_AUTHORIZATION];

        if( $this->request->getAmount() < 0 )
            $result = $access_checker->checkDirectionOut($token);
        else
            $result = $access_checker->checkDirectionIn($token);

        if( $result )
            return true;

        $this->setErrorCode(MessageCode::CODE_PAYMENT_NOT_ACCESSIBLE);
        return false;
    }
}