<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

use Iapps\Common\Core\IappsDateTime;

class GPLTransaction implements \JsonSerializable{

    protected $send_amount_currency_code;
    protected $receive_currency_code;
    protected $send_amount;
    protected $transaction_amount;
    protected $transaction_date;
    protected $description;
    protected $purpose;
    protected $fund_source;
    protected $home_collection;
    protected $rate;
    protected $service_charge;
    protected $payment_method;
    protected $payment_description;
    protected $conversion_direction;
    protected $round_decimal;

    function __construct()
    {
        $this->transaction_date = new IappsDateTime();
    }

    public function setSendAmountCurrency($send_amount_currency_code)
    {
        $this->send_amount_currency_code = $send_amount_currency_code;
        return $this;
    }

    public function getSendAmountCurrency()
    {
        return $this->send_amount_currency_code;
    }

    public function setReceiveCurrencyCode($receive_currency_code)
    {
        $this->receive_currency_code = $receive_currency_code;
        return $this;
    }

    public function getReceiveCurrencyCode()
    {
        return $this->receive_currency_code;
    }

    public function setSendAmount($send_amount)
    {
        $this->send_amount = $send_amount;
        return $this;
    }

    public function getSendAmount()
    {
        return $this->send_amount;
    }

    public function setTransactionAmount($transaction_amount)
    {
        $this->transaction_amount = $transaction_amount;
        return $this;
    }

    public function getTransactionAmount()
    {
        return abs($this->transaction_amount);
    }

    public function setTransactionDate(IappsDateTime $transaction_date)
    {
        $this->transaction_date = $transaction_date;
        return $this;
    }

    public function getTransactionDate()
    {
        return $this->transaction_date;
    }

    public function setDescription($description)
    {
        $this->description = $description;
        return $this;
    }

    public function getDescription()
    {
        return $this->description;
    }

    public function setPurpose($purpose)
    {
        $this->purpose = $purpose;
        return $this;
    }

    public function getPurpose()
    {
        return $this->purpose;
    }

    public function setFundSource($fund_source)
    {
        $this->fund_source = $fund_source;
        return $this;
    }

    public function getFundSource()
    {
        return $this->fund_source;
    }

    public function setHomeCollection($home_collection)
    {
        $this->home_collection = $home_collection;
        return $this;
    }

    public function getHomeCollection()
    {
        return $this->home_collection;
    }

    public function setRate($rate)
    {
        $this->rate = $rate;
        return $this;
    }

    public function getRate()
    {
        return $this->rate;
    }

    public function setServiceCharge($service_charge)
    {
        $this->service_charge = $service_charge;
        return $this;
    }

    public function getServiceCharge()
    {
        return $this->service_charge;
    }

    public function setPaymentMethod($payment_method)
    {
        $this->payment_method = $payment_method;
        return $this;
    }

    public function getPaymentMethod()
    {
        return $this->payment_method;
    }

    public function setPaymentDescription($payment_description)
    {
        $this->payment_description = $payment_description;
        return $this;
    }

    public function getPaymentDescription()
    {
        return $this->payment_description;
    }

    public function setConversionDirection($conversion_direction)
    {
        $this->conversion_direction = $conversion_direction;
        return $this;
    }

    public function getConversionDirection()
    {
        return $this->conversion_direction;
    }

    public function setRoundDecimal($round_decimal)
    {
        $this->round_decimal = $round_decimal;
        return $this;
    }

    public function getRoundDecimal()
    {
        return $this->round_decimal;
    }

    public function jsonSerialize()
    {
        return array(
            'send_amount_currency' => $this->getSendAmountCurrency(),
            'receive_currency_code' => $this->getReceiveCurrencyCode(),
            'Send_amount' => $this->getSendAmount(),
            'transaction_amount' => $this->getTransactionAmount(),
            'transaction_date' => $this->getTransactionDate()->getFormat('Y-m-d'),
            'Description' => $this->getDescription(),
            'purpose' => strtoupper($this->getPurpose()),
            'fund_source' => strtoupper($this->getFundSource()),
            'home_collection' => $this->getHomeCollection(),
            'rate' => $this->getRate(),
            'service_charge' => $this->getServiceCharge() ? $this->getServiceCharge() : 0,
            'payment_method' => $this->getPaymentMethod(),
            'payment_description' => $this->getPaymentDescription(),
            'conversion_direction' => $this->getConversionDirection(),
            'round_decimal' => $this->getRoundDecimal() ? $this->getRoundDecimal() : 0
        );
    }

    public static function fromOption(array $option)
    {
        $trx = new self();

        if( array_key_exists('send_amount_currency', $option) )
            $trx->setSendAmountCurrency($option['send_amount_currency']);

        if( array_key_exists('receive_currency_code', $option) )
            $trx->setReceiveCurrencyCode($option['receive_currency_code']);

        if( array_key_exists('Send_amount', $option) )
            $trx->setSendAmount($option['Send_amount']);

        if( array_key_exists('transaction_amount', $option) )
            $trx->setTransactionAmount($option['transaction_amount']);

        if( array_key_exists('transaction_date', $option) )
            $trx->setTransactionDate(IappsDateTime::fromString($option['transaction_date']));

        if( array_key_exists('Description', $option) )
            $trx->setDescription($option['Description']);

        if( array_key_exists('purpose', $option) )
            $trx->setPurpose($option['purpose']);

        if( array_key_exists('fund_source', $option) )
            $trx->setFundSource($option['fund_source']);

        if( array_key_exists('home_collection', $option) )
            $trx->setHomeCollection($option['home_collection']);

        if( array_key_exists('rate', $option) )
            $trx->setRate($option['rate']);

        if( array_key_exists('service_charge', $option) )
            $trx->setServiceCharge($option['service_charge']);

        if( array_key_exists('payment_method', $option) )
            $trx->setPaymentMethod($option['payment_method']);

        if( array_key_exists('payment_description', $option) )
            $trx->setPaymentDescription($option['payment_description']);

        if( array_key_exists('conversion_direction', $option) )
            $trx->setConversionDirection($option['conversion_direction']);

        if( array_key_exists('round_decimal', $option) )
            $trx->setRoundDecimal($option['round_decimal']);

        return $trx;
    }
}