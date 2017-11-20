<?php

namespace Iapps\PaymentService\PaymentOptionValidator;

use Iapps\PaymentService\Common\MessageCode;
use Iapps\PaymentService\Common\TMoneySwitch\TMoneySwitchClientFactory;
use Iapps\PaymentService\Attribute\AttributeCode;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\Common\Logger;
use Iapps\PaymentService\Common\TransferToSwitch\TransferToSwitchClientFactory;

class IndoBankCollectionInfoValidator extends CollectionInfoValidator{

    public function validate($payment_code, $country_code, array $option = array())    
    {
        if( $result = parent::validate($payment_code, $country_code,  $option) )
        {         

            //to call T Money for more validation
            if( isset($option[AttributeCode::BANK_CODE]) AND isset($option[AttributeCode::BANK_ACCOUNT]) )
            {//and only for bank account
                $bank_code = $option[AttributeCode::BANK_CODE];
                $bank_account = $option[AttributeCode::BANK_ACCOUNT];
                if( isset($option[AttributeCode::ACCOUNT_HOLDER_NAME]))
                    $accountHolderName = $option[AttributeCode::ACCOUNT_HOLDER_NAME];
                else
                    $accountHolderName = NULL;


                //transferto check account
                //if($payment_code == PaymentModeType::BANK_TRANSFER_TRANSFERTO){

                if($support = $this->_isBankSupportedByPaymentMode(PaymentModeType::BANK_TRANSFER_TRANSFERTO,$bank_code)){


                    //return true;
                    Logger::debug('Transfer-to Indo Bank Validation: ' . $bank_code);


                    $client = TransferToSwitchClientFactory::build();
                    if( !$response = $client->checkAccount($bank_code, $bank_account) )
                    {
                        $this->setResponseCode(MessageCode::CODE_CHECK_BANK_ACCOUNT_FAILED);
                        return false;
                    }

                    if( $response->isSuccess() )
                    {
                        if( !is_null($accountHolderName) )
                        {
                            if(strtoupper($accountHolderName) == strtoupper($response->getDestAccHolder()) )
                            {//it's ok
                                return $result;
                            }
                            else
                            {//no the name is not correct
                                $this->setResponseCode(MessageCode::CODE_CHECK_ACCOUNT_HOLDER_NAME_FAILED);
                                $this->setResponseMessage("Account holder name is invalid. Correct Name: '" . $response->getDestAccHolder() . "'");
                                return false;
                            }
                        }
                        else //it's valid
                            return $result;
                    }
                    $this->setResponseCode(MessageCode::CODE_CHECK_BANK_ACCOUNT_FAILED);
                    return false;
                }

                //check if bank code is covered by T Money
                if( $this->_isBankSupported($bank_code) )
                {
                    

                    Logger::debug('Indo Bank Validation: ' . $bank_code);
                    $client = TMoneySwitchClientFactory::build();
                    if( !$response = $client->checkAccount($bank_code, $bank_account) )
                    {
                        $this->setResponseCode(MessageCode::CODE_CHECK_BANK_ACCOUNT_FAILED);                    
                        return false;
                    }
                    
                    if( $response->isSuccess() )
                    {
                        if( !is_null($accountHolderName) )
                        {
                            if(strtoupper($accountHolderName) == strtoupper($response->getDestAccHolder()) )
                            {//it's ok
                                return $result;
                            }
                            else
                            {//no the name is not correct
                                $this->setResponseCode(MessageCode::CODE_CHECK_ACCOUNT_HOLDER_NAME_FAILED);
                                $this->setResponseMessage("Account holder name is invalid. Correct Name: '" . $response->getDestAccHolder() . "'");                                
                                return false;
                            }
                        }
                        else //it's valid
                            return $result;                        
                    }

                    $this->setResponseCode(MessageCode::CODE_CHECK_BANK_ACCOUNT_FAILED);                    
                    return false;
                }
            }
        }

        return $result;
    }
    
    protected function _isBankSupported($bankCode)
    {
        //check if bank code is covered by T Money
        $pmAttServ = PaymentModeAttributeServiceFactory::build();                    
        if( $pmAttr = $pmAttServ->getAttributesByPaymentCode(PaymentModeType::BANK_TRANSFER_TMONEY, 'ID', false) )
        {
            if( $attr = $pmAttr->getByAttributeCode(AttributeCode::BANK_CODE) )
            {
                return $attr->getValue()->getByCode($bankCode); 
            }
                
        }
        
        return false;
    }

    protected function _isBankSupportedByPaymentMode($payment_mode,$bankCode)
    {
        //check if bank code is covered by payment mode
        $pmAttServ = PaymentModeAttributeServiceFactory::build();
        if( $pmAttr = $pmAttServ->getAttributesByPaymentCode($payment_mode, 'ID', false) )
        {
            if( $attr = $pmAttr->getByAttributeCode(AttributeCode::BANK_CODE) )
            {
                return $attr->getValue()->getByCode($bankCode);
            }

        }

        return false;
    }

    /*
     * if($response = $tmoney_switch_client->checkAccount($bank_code,$account_number) )
        {

            $result = array(
                //'responseCode'=>$response->getResponseCode(),
                'bankAccount'=>$response->getDestBankacc(),
                'CorrectAccountHolderName'=>$response->getDestAccHolder(),
                'description'=>$response->getDescription()
                //'formatResponse'=>$response->getFormattedResponse()
            );

            if ($response->getResponseCode() == "00" || $response->getResponseCode() == "0") {
                $this->setResponseCode(MessageCode::CODE_CHECK_BANK_ACCOUNT_SUCCESS);
                if(strtoupper($acc_holder_name) == strtoupper($response->getDestAccHolder()) ){
                    $this->setResponseCode(MessageCode::CODE_CHECK_ACCOUNT_HOLDER_NAME_SUCCESS);
                    $result["description"] = "Success";
                }else{
                    //$result["responseCode"] = "01";
                    $this->setResponseCode(MessageCode::CODE_CHECK_ACCOUNT_HOLDER_NAME_FAILED);
                    $result["description"] = "Invalid Account Holder Name";
                }

            }else{
                $this->setResponseCode(MessageCode::CODE_CHECK_BANK_ACCOUNT_FAILED);
            }
            //$this->setResponseMessage("Check Bank Account Failed");
            return $result ;
        }
     */
}