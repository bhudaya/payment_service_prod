<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;

class SearchPaymentRequestService extends IappsBaseService{

    public function setFromCreatedAt(IappsDateTime $from)
    {
        $this->getRepository()->setFromCreatedAt($from);
    }

    public function setToCreatedAt(IappsDateTime $to)
    {
        $this->getRepository()->setToCreatedAt($to);
    }

    public function getPaymentRequestByParam(PaymentRequest $request, array $user_profile_id_arr = NULL, $limit=null, $page=null){
        if( $object = $this->getRepository()->findBySearchFilter($request, $user_profile_id_arr, $limit, $page) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_REQUEST_LIST_SUCCESS);
            return $object;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_REQUEST_LIST_FAILED);
        return false;

    }

    public function getPaymentBySearchFilter(PaymentRequest $paymentRequest, $limit, $page)
    {
        if( $collection = $this->getRepository()->trxListFindBySearchFilter($paymentRequest, $limit, $page) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_SUCCESS);
            return $collection;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_FAILED);
        return false;
    }

    public function getPaymentByPaymentRequestID($id)
    {
        if( $paymentRequestInfos = $this->getRepository()->findById($id) )
        {
            $attrServ = PaymentModeAttributeServiceFactory::build();
            $bank_name = null;

            if( $value = $bank_name = $attrServ->getValueByCode($paymentRequestInfos->getPaymentCode(), PaymentModeAttributeCode::BANK_CODE, $paymentRequestInfos->getOption()->getValue('dest_bankcode')) )
            {
                $bank_name = $value->getValue();
                $paymentRequestInfos->setBankName($bank_name);
            }

            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_SUCCESS);
            return $paymentRequestInfos;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_FAILED);
        return false;
    }
}