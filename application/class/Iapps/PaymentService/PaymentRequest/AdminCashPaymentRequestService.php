<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Helper\ArrayExtractor;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\Helper\RequestHeader;
use Iapps\Common\Helper\ResponseHeader;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\PaymentService\Payment\PaymentDescription;
use Iapps\PaymentService\PaymentMode\PaymentModeType;

class AdminCashPaymentRequestService extends PaymentRequestService{

    function __construct(PaymentRequestRepository $rp, $ipAddress = '127.0.0.1', $updatedBy = NULL)
    {
        parent::__construct($rp, $ipAddress, $updatedBy);

        $this->payment_code = PaymentModeType::ADMIN_CASH;
    }

    public function request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, array $option)
    {
        //add admin access token as option
        $headers = RequestHeader::get();
        $option['token'] = NULL;
        if( array_key_exists(ResponseHeader::FIELD_X_AUTHORIZATION, $headers) )
            $option['token'] = $headers[ResponseHeader::FIELD_X_AUTHORIZATION];

        return parent::request($user_profile_id, $module_code, $transaction_id, $country_currency_code, $amount, $option);
    }

    protected function _requestAction(PaymentRequest $request)
    {
        $option_array = $request->getOption()->toArray();
        if(array_key_exists('reference_no', $option_array)) {
            $request->setReferenceID($option_array['reference_no']);
        }
        return true;
    }

    protected function _generateDetail1(PaymentRequest $request)
    {
        //get agent detail
        $acc_serv = AccountServiceFactory::build();
        if( $agent = $acc_serv->getUser(NULL, $this->getUpdatedBy()) )
        {
            $desc = new PaymentDescription();
            $desc->add('', 'You were served by ' . $agent->getName());

            $request->setDetail1($desc);
        }

        return true;
    }
}