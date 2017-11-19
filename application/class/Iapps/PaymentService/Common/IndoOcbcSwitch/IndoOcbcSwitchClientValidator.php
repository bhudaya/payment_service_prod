<?php

namespace Iapps\PaymentService\Common\IndoOcbcSwitch;

use Iapps\Common\Validator\IappsValidator;

class IndoOcbcSwitchClientValidator extends IappsValidator{

    protected $_client;

    public static function make(IndoOcbcSwitchClient $client)
    {
        $v = new IndoOcbcSwitchClientValidator();
        $v->_client = $client;
        $v->validate();

        return $v;
    }

    public function validate()
    {
        $this->isFailed = true;

        if( $this->_validateProductCode() AND
            $this->_validateMerchantCode() AND
            $this->_validateTerminalCode() AND
            $this->_validateDestRefNumber() AND
            $this->_validateDestBankCode() AND
            $this->_validateDestBankAccount() AND
            $this->_validateDestAmount() )
        {
            $this->isFailed = false;
        }


    }

    protected function _validateProductCode()
    {
        log_message('debug', 'product code check: ' . ($this->_client->getProductCode() != NULL));
        return ($this->_client->getProductCode() != NULL);
    }

    protected function _validateMerchantCode()
    {
        log_message('debug', 'merchant code check: ' . ($this->_client->getMerchantCode() != NULL ));
        return ($this->_client->getMerchantCode() != NULL );
    }

    protected function _validateTerminalCode()
    {
        log_message('debug', 'terminal code check: ' . ($this->_client->getTerminalCode() != NULL ));
        return ($this->_client->getTerminalCode() != NULL );
    }

    protected function _validateDestRefNumber()
    {
        log_message('debug', 'ref number check: ' . ($this->_client->getDestRefNumber() != NULL ));
        return ($this->_client->getDestRefNumber() != NULL );
    }

    protected function _validateDestBankCode()
    {
        log_message('debug', 'bank code check: ' . ($this->_client->getDestBankCode() != NULL ));
        return ($this->_client->getDestBankCode() != NULL );
    }

    protected function _validateDestBankAccount()
    {
        log_message('debug', 'bank account check: ' . ($this->_client->getDestBankAccount() != NULL));
        return ($this->_client->getDestBankAccount() != NULL);
    }

    protected function _validateDestAmount()
    {
        if( is_numeric($this->_client->getDestAmount()) )
        {
            log_message('debug', 'amount check: ' . ($this->_client->getDestAmount() > 0.0));
            return ($this->_client->getDestAmount() > 0.0);
        }

        log_message('debug', 'amount check: ' . 0);
        return false;
    }
}