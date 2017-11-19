<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\Core\IappsBaseService;
use Iapps\Common\Helper\GuidGenerator;
use Iapps\Common\SystemCode\SystemCode;
use Iapps\PaymentService\Attribute\Attribute;
use Iapps\PaymentService\Attribute\AttributeCollection;
use Iapps\PaymentService\Common\SystemCodeServiceFactory;
use Iapps\PaymentService\PaymentMode\PaymentMode;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Common\FunctionCode;
use Iapps\PaymentService\Common\PaymentDirection;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;

class PaymentModeService extends IappsBaseService{

    public function getPaymentModeList($limit, $page,
                                       $is_collection = NULL,
                                       $is_payment = NULL,
                                       AttributeCollection $attributes = NULL,
                                       array $delivery_codes = NULL,
                                       array $group_codes = NULL,
                                       $is_array = false)
    {
        $paymentModeCollection = NULL;
        if( $is_collection != NULL OR
            $is_payment != NULL OR
            $group_codes != NULL OR
            $delivery_codes != NULL OR
            $attributes != NULL )
        {//get by filter

            //setup filter
            $filters = new PaymentModeCollection();

            if( !is_null($is_collection))
            {
                $filter = (new PaymentMode())->setIsCollectionMode($is_collection);
                $filters->addData($filter);
            }

            if( !is_null($is_payment))
            {;
                $filter = (new PaymentMode())->setIsPaymentMode($is_payment);
                $filters->addData($filter);
            }

            if ($group_codes) {
                if ($group_ids = $this->_getPaymentCodeGroupIds($group_codes)) {
                    foreach ($group_ids AS $group_id) {
                        $filter = new PaymentMode();
                        $filter->getPaymentModeGroup()->setId($group_id);
                        $filters->addData($filter);
                    }
                } else {
                    $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_FAILED);
                    return false;
                }
            }

            if ($delivery_codes) {
                if ($delivery_ids = $this->_getDeliveryTimeIds($delivery_codes)) {
                    foreach ($delivery_ids AS $delivery_id) {
                        $filter = new PaymentMode();
                        $filter->getDeliveryTime()->setId($delivery_id);
                        $filters->addData($filter);
                    }
                } else {
                    $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_FAILED);
                    return false;
                }
            }

            if( $attributes )
            {
                $pmAttrServ = PaymentModeAttributeServiceFactory::build();
                if( !$pmAttrs = $pmAttrServ->getByAttributeValue($attributes) )
                {
                    $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_FAILED);
                    return false;
                }

                foreach( $pmAttrs AS $pmAttr)
                {
                    $filter = new PaymentMode();
                    $filter->setCode($pmAttr->getPaymentCode());
                    $filters->addData($filter);
                }
            }

            if( $info = $this->getRepository()->findByFilters($filters) )
            {
                $paymentModeCollection = $info->result;
            }
        }
        else
        {
            if( $info = $this->getRepository()->findAll($limit, $page) )
            {
                $paymentModeCollection = $info->result;
            }
        }

        if( $paymentModeCollection instanceof PaymentModeCollection )
        {
            //get required attributes for each payment mode
            $pmAttrServ = PaymentModeAttributeServiceFactory::build();
            foreach($paymentModeCollection AS $paymentMode)
            {
                if( $pmAttr = $pmAttrServ->getAttributesByPaymentCode($paymentMode->getCode(), NULL, false))
                {
                    $paymentMode->setAttributes($pmAttr);
                }
            }

            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_SUCCESS);
            if( !$is_array )
                return $paymentModeCollection->pagination($limit, $page);
            else
            {
                $paginatedResult = $paymentModeCollection->pagination($limit, $page);

                $result = new \stdClass();
                $result->result = array();
                $result->total = $paginatedResult->getTotal();

                foreach($paginatedResult->getResult() AS $paymentMode)
                {
                    $temp = $paymentMode->jsonSerialize();
                    $temp['attribute'] = $paymentMode->getAttributes()->getSelectedField(array('attribute', 'name', 'selection_only'));

                    $result->result[] = $temp;
                }

                return $result;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_FAILED);
        return false;

    }

    protected function _getPaymentCodeGroupIds(array $codes)
    {
        $syscodeServ = SystemCodeServiceFactory::build();
        if( $info = $syscodeServ->getBySystemCodeGroup(PaymentModeGroup::getSystemGroupCode()) )
        {
            $pmGroups = $info->result;
            $group_ids = array();
            foreach($codes AS $groupCode)
            {
                if( $pmGroup = $pmGroups->getByCode($groupCode) )
                    $group_ids[] = $pmGroup->getId();
                else
                    return false;
            }

            if( count($group_ids) > 0 )
                return $group_ids;
        }

        return false;
    }

    protected function _getDeliveryTimeIds(array $codes)
    {
        $syscodeServ = SystemCodeServiceFactory::build();
        if( $info = $syscodeServ->getBySystemCodeGroup(DeliveryTime::getSystemGroupCode()) )
        {
            $pmGroups = $info->result;
            $group_ids = array();
            foreach($codes AS $groupCode)
            {
                if( $pmGroup = $pmGroups->getByCode($groupCode) )
                    $group_ids[] = $pmGroup->getId();
                else
                    return false;
            }

            if( count($group_ids) > 0 )
                return $group_ids;
        }

        return false;
    }

    public function getPaymentModeInfo($code)
    {
        if( $paymentModeInfo = $this->getRepository()->findByCode($code) )
        {
            $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_SUCCESS);

            $result = $paymentModeInfo->getSelectedField(array('id','code','name', 'payment_mode_group', 'self_service', 'need_approval', 'for_refund'));
            $result['delivery_time'] = $paymentModeInfo->getDeliveryTime()->getSelectedField(array('id', 'code', 'display_name', 'description'));
            return $result;
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_FAILED);
        return false;
    }

    public function getPaymentModeByParam(PaymentMode $paymentMode, $limit = 1000, $page = 1)
    {
        if( $object = $this->getRepository()->findByParam($paymentMode, $limit, $page) )
        {
            if( $object->result instanceof PaymentModeCollection )
            {
                $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_SUCCESS);
                return $object;
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_FAILED);
        return false;
    }


    public function getSupportedPaymentModeByFunction($access_token, $direction, $access_type = NULL)
    {
        $payment_mode_arr = array();

        $account_serv = AccountServiceFactory::build();

        if ($direction == PaymentDirection::IN) {
            if ($account_serv->checkAccess($access_token, FunctionCode::COUNTER_CASHIN, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::STORE_CASH, PaymentModeType::EWALLET);
            } else if ($account_serv->checkAccess($access_token, FunctionCode::MOBILE_CASHIN, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::MOBILE_AGENT_CASH, PaymentModeType::EWALLET);
            } else if ($account_serv->checkAccess($access_token, FunctionCode::ADMIN_PAYMENT_IN, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::ADMIN_CASH);
            } else if ($account_serv->checkAccess($access_token, FunctionCode::PARTNER_PAYMENT_IN, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::PARTNER_CASH);
            } else if ($account_serv->checkAccess($access_token, FunctionCode::FRANCHISE_CASHIN, $access_type)) {
                $payment_mode_arr[] = PaymentModeType::FRANCHISE_CASH;
            }
        } else if ($direction == PaymentDirection::OUT) {
            if ($account_serv->checkAccess($access_token, FunctionCode::COUNTER_CASHOUT, $access_type)) {
                $payment_mode_arr[] = PaymentModeType::STORE_CASH;
            } else if ($account_serv->checkAccess($access_token, FunctionCode::MOBILE_CASHOUT, $access_type)) {
                $payment_mode_arr[] = PaymentModeType::MOBILE_AGENT_CASH;
            } else if ($account_serv->checkAccess($access_token, FunctionCode::ADMIN_PAYMENT_OUT, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::ADMIN_CASH);
            } else if ($account_serv->checkAccess($access_token, FunctionCode::PARTNER_PAYMENT_OUT, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::PARTNER_CASH);
            } else if ($account_serv->checkAccess($access_token, FunctionCode::FRANCHISE_CASHOUT, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::FRANCHISE_CASH);
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_SUCCESS);
        return $payment_mode_arr;
    }

    public function getSupportedPaymentModeByUserId($user_profile_id, $direction, $access_type = NULL)
    {
        $payment_mode_arr = array();

        $account_serv = AccountServiceFactory::build();

        if ($direction == PaymentDirection::IN) {
            if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::COUNTER_CASHIN, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::STORE_CASH, PaymentModeType::EWALLET);
            } else if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::MOBILE_CASHIN, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::MOBILE_AGENT_CASH, PaymentModeType::EWALLET);
            } else if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::ADMIN_PAYMENT_IN, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::ADMIN_CASH);
            } else if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::PARTNER_PAYMENT_IN, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::PARTNER_CASH);
            } else if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::FRANCHISE_CASHIN, $access_type)) {
                $payment_mode_arr[] = PaymentModeType::FRANCHISE_CASH;
            }
        } else if ($direction == PaymentDirection::OUT) {
            if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::COUNTER_CASHOUT, $access_type)) {
                $payment_mode_arr[] = PaymentModeType::STORE_CASH;
            } else if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::MOBILE_CASHOUT, $access_type)) {
                $payment_mode_arr[] = PaymentModeType::MOBILE_AGENT_CASH;
            } else if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::ADMIN_PAYMENT_OUT, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::ADMIN_CASH);
            } else if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::PARTNER_PAYMENT_OUT, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::PARTNER_CASH);
            } else if ($account_serv->checkAccessByUserProfileId($user_profile_id, FunctionCode::FRANCHISE_CASHOUT, $access_type)) {
                $payment_mode_arr = array(PaymentModeType::FRANCHISE_CASH);
            }
        }

        $this->setResponseCode(MessageCode::CODE_GET_PAYMENT_MODE_SUCCESS);
        return $payment_mode_arr;
    }
}