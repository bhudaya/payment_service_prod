<?php

namespace Iapps\PaymentService\Payment;

use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Core\PaginatedResult;
use Iapps\PaymentService\Payment\PaymentCollection;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Common\SystemCodeServiceFactory;
use Iapps\PaymentService\CountryCurrency\CountryCurrencyServiceFactory;
use Iapps\PaymentService\PaymentAccess\PaymentAccessCheckerFactory;
use Iapps\PaymentService\PaymentRequest\BTIndoOCBCPaymentRequestService;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;
use Iapps\PaymentService\PaymentRequest\PaymentRequestCollection;
use Iapps\PaymentService\PaymentRequest\PaymentRequestServiceFactory;
use Iapps\Common\Core\IappsBaseRepository;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\PaymentMode\PaymentModeServiceFactory;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\PaymentRequest\PaymentRequestStatus;
use Iapps\PaymentService\PaymentRequest\PaymentRequestUserConversionService;
use Iapps\PaymentService\PaymentRequest\PaymentRequestUserConversionServiceFactory;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeCode;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;
use Iapps\Common\Microservice\CountryService\CountryServiceFactory;
use Iapps\PaymentService\PaymentRequest\SearchPaymentRequestServiceFactory;

class PaymentService extends IappsBaseService {

    protected $_paymentCode = NULL;
    protected $channelCode;

    public function setPaymentCode($code)
    {
        $this->_paymentCode = $code;
        return true;
    }

    public function createPaymentFromRequest(PaymentRequest $request)
    {
        $payment = Payment::createFromPaymentRequest($request);
        $this->_completePayment($payment);
        $payment->setCreatedBy($this->getUpdatedBy());

        //save payment record
        if( $this->_savePayment($payment) )
        {
            return $payment;
        }

        return false;
    }

    public function updateUserProfileId($module_code, $transactionID, $user_id)
    {
        //get payment with transactionID, module code
        if( $payment = $this->getByTransactionID($module_code, $transactionID) )
        {
            if( $payment->getUserProfileId() == NULL )
            {//only proceed if user profile id is null
                $payment->setUserProfileId($user_id);
                $payment->setUpdatedBy($this->getUpdatedBy());

                $this->getRepository()->startDBTransaction();
                //set user id
                if( $this->getRepository()->update($payment) )
                {
                    //update payment request
                    $requestServ = PaymentRequestUserConversionServiceFactory::build();
                    $requestServ->setUpdatedBy($this->getUpdatedBy());
                    $requestServ->setIpAddress($this->getIpAddress());
                    if( $requestServ->convert($payment->getPaymentRequestId(), $user_id) )
                    {
                        $this->getRepository()->completeDBTransaction();
                        $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_CHECK_UPDATE_SUCCESS);
                        return $payment;
                    }
                }
                $this->getRepository()->rollbackDBTransaction();
            }
        }

        $this->setResponseCode(MessageCode::CODE_PAYMENT_REQUEST_CHECK_UPDATE_FAIL);
        return false;
    }


    public function getByTransactionID($module_code, $transactionID)
    {

        if( $paymentModeInfo = $this->getRepository()->findByTransactionID($module_code,$transactionID) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_SUCCESS);
            //return $paymentModeInfo->getSelectedField(array('id','code','name'));
            return $paymentModeInfo;

        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_FAILED);
        return false;
    }

    public function getByTransactionIDArr($module_code, $transactionIDArr)
    {
        if( $collection = $this->getRepository()->findByTransactionIDArr($module_code,$transactionIDArr) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_SUCCESS);
            return $collection;

        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_FAILED);
        return false;
    }

    public function void($module_code, $transactionID, $user_profile_id)
    {
        if( $payment = $this->getByTransactionID($module_code, $transactionID) )
        {
            if( $payment instanceof Payment
                AND $payment->getUserProfileId() == $user_profile_id
                AND $payment->getStatus()->getCode() == PaymentStatus::COMPLETE )   //only completed payment can be voided
            {
                $payment->getStatus()->setCode(PaymentStatus::VOID);
                if( $this->_updateStatusCode($payment) )
                {//update payment request
                    if( $this->getRepository()->update($payment) )
                    {
                        $this->setResponseCode(MessageCode::CODE_PAYMENT_VOIDED_SUCCESS);
                        return $payment;
                    }
                }

                $this->setResponseCode(MessageCode::CODE_PAYMENT_VOIDED_FAILED);
                return false;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_FAILED);
        return false;
    }

    protected function _completePayment(Payment $payment)
    {
        $payment->complete();
        $this->_updateStatusCode($payment);
    }

    protected function _savePayment(Payment $payment)
    {
        if( $this->getRepository()->insert($payment) )
        {
            //fire log
            $this->fireLogEvent('iafb_payment.payment', AuditLogAction::CREATE, $payment->getId() );

            return true;
        }

        return false;
    }

    protected function _checkDuplicateTransactionID($module_code, $transactionID)
    {
        if($this->getRepository()->findByTransactionID($module_code, $transactionID) !== false)
        {
            $this->setResponseCode(MessageCode::CODE_TRANSACTIONID_EXISTS);
            return false;
        }

        return true;
    }

    protected function _updateStatusCode(Payment $payment)
    {
        $systemcode_serv = SystemCodeServiceFactory::build();
        if( $code = $systemcode_serv->getByCode($payment->getStatus()->getCode(), PaymentStatus::getSystemGroupCode()) )
        {
            $payment->setStatus($code);
            return true;
        }


        return false;
    }

    protected function _getCountryCurrencyInfo($code)
    {
        $country_cur_serv = CountryCurrencyServiceFactory::build();
        if( $info = $country_cur_serv->getCountryCurrencyInfo($code) )
            return $info;

        $this->setResponseCode(MessageCode::CODE_COUNTRY_CURRENCY_INVALID_CURRENCY_CODE);
        return false;
    }

    protected function _getPaymentRequestService()
    {
        $service = PaymentRequestServiceFactory::build($this->_paymentCode);
        $service->setIpAddress($this->getIpAddress());
        $service->setUpdatedBy($this->getUpdatedBy());
        return $service;
    }

    protected function _getAdditionalInfo(PaymentRequest $request)
    {
        return NULL;
    }

    protected function _checkPaymentAccessible($amount)
    {
        if( $this->_paymentCode == NULL or
            $this->admin_accesstoken == NULL )
        {
            $this->setResponseCode(MessageCode::CODE_PAYMENT_INVALID_INFO);
            return false;
        }

        $access_checker = PaymentAccessCheckerFactory::build($this->_paymentCode);
        if( $amount < 0 )
            $result = $access_checker->checkDirectionOut($this->admin_accesstoken);
        else
            $result = $access_checker->checkDirectionIn($this->admin_accesstoken);

        if( !$result )
        {
            $this->setResponseCode(MessageCode::CODE_PAYMENT_NOT_ACCESSIBLE);
            return false;
        }

        return true;
    }

    protected function _returnResponse(Payment $payment, array $additionalInfo = NULL)
    {
        return array(
            'payment_info' => $payment->getSelectedField(array('id', 'module_code', 'transactionID','payment_code', 'country_currency_code', 'amount', 'status')),
            'additional_info' => $additionalInfo
        );
    }

    //--------
    public function getPaymentByParam(Payment $config , $limit , $page, $include_cancelled = false)
    {
        $payment_mode_serv = PaymentModeServiceFactory::build();
        if( !$paymentModeInfo = $payment_mode_serv->getPaymentModeList(MAX_VALUE,1) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_FAILED);
            return false;
        }

        $result = new PaginatedResult();
        $paymentColl = new PaymentCollection();
        $total = 0;
        if( $collection = $this->getRepository()->findByParam($config, MAX_VALUE , 1) )
        {
            $total = $collection->total;
            foreach ($collection->result as $paymentEach) {
                foreach ($paymentModeInfo->result as $paymentModeEach) {
                    if ($paymentEach->getPaymentCode() == $paymentModeEach->getCode()) {
                        $paymentEach->setPaymentModeName($paymentModeEach->getName());
                        $paymentColl->addData($paymentEach);
                    }
                }
            }
        }

        if( $include_cancelled )
        {//get from payment request service, and map to payment object as if its cancelled payment
            $paymentRequestServ = SearchPaymentRequestServiceFactory::build();
            if($config->getDateFrom())
                $paymentRequestServ->setFromCreatedAt($config->getDateFrom());
            if($config->getDateTo())
                $paymentRequestServ->setToCreatedAt($config->getDateTo());

            $requestFilter = new PaymentRequest();
            $requestFilter->setStatus(PaymentRequestStatus::CANCELLED);
            $requestFilter->setUserProfileId($config->getUserProfileId());
            $requestFilter->setModuleCode($config->getModuleCode());
            $requestFilter->setPaymentCode($config->getPaymentCode());
            $requestFilter->setTransactionID($config->getTransactionID());

            if( $cancelledRequests = $paymentRequestServ->getPaymentBySearchFilter($requestFilter, MAX_VALUE, 1) )
            {
                $total = $total + $cancelledRequests->total;
                foreach($cancelledRequests->result AS $cancelledRequest)
                {
                    if( $cancelledRequest instanceof PaymentRequest )
                    {
                        $cancelledPayment = Payment::createFromPaymentRequest($cancelledRequest);
                        $cancelledPayment->getStatus()->setCode($cancelledRequest->getStatus());
                        $cancelledPayment->setCreatedAt($cancelledRequest->getCreatedAt());
                        $cancelledPayment->setCreatedBy($cancelledRequest->getCreatedBy());
                        $cancelledPayment->setId(NULL); //no id

                        foreach ($paymentModeInfo->result as $paymentModeEach) {
                            if ($cancelledPayment->getPaymentCode() == $paymentModeEach->getCode()) {
                                $cancelledPayment->setPaymentModeName($paymentModeEach->getName());
                            }
                        }

                        $paymentColl->addData($cancelledPayment);
                    }
                }
            }
        }

        if( count($paymentColl) > 0 )
        {
            $paymentColl = $paymentColl->sortByCreatedAt();
            $result = $paymentColl->pagination($limit, $page);
            $result->setTotal($total);

            if( count($result->getResult()) > 0 )
            {
                $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_SUCCESS);
                return $result;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_FAILED);
        return false;
    }
    
    public function setChannelCode($channelCode)
    {
        $this->channelCode = $channelCode;
        return $this;
    }

    public function getChannelCode()
    {
        return $this->channelCode;
    }

    public function getPaymentCreatorAndSearchFilter(Payment $payment, $created_by_arr, $limit, $page, IappsDateTime $date_from = NULL, IappsDateTime $date_to = NULL)
    {
        if( $collection = $this->getRepository()->findByCreatorAndParam($payment, $created_by_arr, $limit, $page, $date_from, $date_to) )
        {
            $paymentColl = new PaymentCollection();
            $payment_mode_serv = PaymentModeServiceFactory::build();
            if($paymentModeColl = $payment_mode_serv->getPaymentModeList(100,1)) {
                foreach ($collection->result as $paymentEach) {
                    foreach ($paymentModeColl->result as $paymentModeEach) {
                        if ($paymentEach->getPaymentCode() == $paymentModeEach->getCode()) {
                            $paymentEach->setPaymentModeName($paymentModeEach->getName());
                            $paymentColl->addData($paymentEach);
                        }
                    }
                }
            }

            $collection->result = $paymentColl;
            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_SUCCESS);
            return $collection;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_LIST_FAILED);
        return false;
    }

    public function reportFindByParam(Payment $payment, $date_from, $date_to)
    {
        if ($paymentInfos = $this->getRepository()->reportFindByParam($payment, $date_from, $date_to)) {

            $this->setResponseCode(MessageCode::CODE_GET_AGUNG_TRANSACTION_REPORT_SUCCESS);
            return $paymentInfos;
        }

        $this->setResponseCode(MessageCode::CODE_GET_AGUNG_TRANSACTION_REPORT_FAIL);
        return false;
    }
}

