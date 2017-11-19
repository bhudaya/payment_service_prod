<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

use Iapps\Common\Validator\IappsValidator;

class GPLSwitchClientValidator extends IappsValidator{

    protected $_client;
    public static function make(GPLSwitchClient $client)
    {
        $v = new GPLSwitchClientValidator();
        $v->_client = $client;
        $v->validate();

        return $v;
    }

    public function validate()
    {
        $this->isFailed = true;

        if( $this->_validateCustomerRefId() AND
            $this->_validateCheckSum() AND
            $this->_validateCompany() AND
            $this->_validateSender() AND
            $this->_validateReceiver() AND
            $this->_validateTrx() )
        {
            $this->isFailed = false;
        }
    }

    protected function _validateCustomerRefId()
    {
        return $this->_client->getCustomerRefNo() != NULL;
    }

    protected function _validateCheckSum()
    {
        return $this->_client->getCheckSum() != NULL;
    }

    protected function _validateCompany()
    {
        $company = $this->_client->getCompany();
        if( $company instanceof GPLCompany)
        {
            return
            (
                $company->getCorporateId() != NULL AND
                $company->getBranchCode() != NULL AND
                $company->getUserName() != NULL AND
                $company->getPassword() != NULL
            );
        }

        return false;
    }

    protected function _validateSender()
    {
        $sender = $this->_client->getSender();
        if( $sender instanceof GPLMemberSender )
        {
            if( $sender->getFullName() == NULL OR
                $sender->getIdentityCardType() == NULL OR
                $sender->getIdentityCardNumber() == NULL OR
                $sender->getDateOfBirth()->isNull() OR
                $sender->getOccupation() == NULL OR
                $sender->getIncomeSource() == NULL OR
                $sender->getAddress() == NULL OR
                $sender->getContactNumber() == NULL
                 )
                return false;

            if( !($sender->getGender() == 'F' OR $sender->getGender() == 'M') )
                return false;

            if( strlen($sender->getNationalityCountryCode()) != 2 )
                return false;

            if( $sender->getIdentityCardType() == NULL OR $sender->getIdentityCardNumber() == NULL)
                return false;

            if( $sender->getIdentityCardNoExpiry() == false AND $sender->getIdentityCardExpiry()->isNull() )
                return false;

            return true;
        }

        return false;
    }

    protected function _validateReceiver()
    {
        $receiver = $this->_client->getReceiver();
        if( $receiver instanceof GPLMemberReceiver )
        {
            if( $receiver->getReceiverName() == NULL OR
                $receiver->getAddress() == NULL OR
                $receiver->getContactNumber() == NULL OR
                $receiver->getRelationship() == NULL )
                return false;

            if( !($receiver->getTransactionType() == 'BANK' OR $receiver->getTransactionType() == 'CASH') )
                return false;

            if( strlen($receiver->getCountryCode()) != 2 )
                return false;

            if( $receiver->getTransactionType() == 'BANK' )
            {
                if( $receiver->getBankCode() == NULL OR
                    $receiver->getAccountNo() == NULL )
                    return false;
            }

            return true;
        }

        return false;
    }

    protected function _validateTrx()
    {
        $transaction = $this->_client->getTrx();
        if( $transaction instanceof GPLTransaction )
        {
            if( $transaction->getTransactionAmount() == NULL OR
                $transaction->getTransactionDate()->isNull() OR
                $transaction->getPurpose() == NULL OR
                $transaction->getFundSource() == NULL OR
                $transaction->getConversionDirection() == NULL OR
                is_null($transaction->getRoundDecimal()))
                return false;

            if( strlen($transaction->getReceiveCurrencyCode()) != 3 )
                return false;

            if( strlen($transaction->getSendAmountCurrency()) != 3 )
                return false;

            return true;
        }

        return false;
    }
}

