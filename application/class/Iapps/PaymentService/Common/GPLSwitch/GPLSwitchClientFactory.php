<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\PaymentMode\PaymentModeService;
use Iapps\PaymentService\PaymentMode\PaymentModeServiceFactory;
use Iapps\PaymentService\PaymentRequest\PaymentRequest;
use Iapps\PaymentService\Common\Logger;

class GPLSwitchClientFactory{
    protected static $_client;

    public static function build()
    {
        if( self::$_client == NULL )
        {
            if( !$url = getenv('GPL_SWITCH_URL') )
                throw new \Exception('GPL Switch URL Is Not Defined');

            $gplCompany = GPLCompanyFactory::build();
            self::$_client = new GPLSwitchClient(array(
                "url" => $url
            ));
            self::$_client->setCompany($gplCompany);
        }

        return self::$_client;
    }

    public static function buildFromRequest(PaymentRequest $request)
    {
        $gpl_switch_client = self::build();

        $gpl_switch_client->setCustomerRefNo($request->getTransactionID());
        //trx

        $paymentModeServ = PaymentModeServiceFactory::build();
        if ($payment_info = $paymentModeServ->getPaymentModeInfo($request->getPaymentCode())) {
            $gpl_switch_client->getReceiver()->setTransactionType(strtoupper($payment_info['payment_mode_group']));
        }

        if ($payment_info = $paymentModeServ->getPaymentModeInfo($request->getOption()->getValue('payment_method'))) {
            $gpl_switch_client->getTrx()->setPaymentMethod($payment_info['payment_mode_group']);
        }

        $gpl_switch_client->getTrx()->setReceiveCurrencyCode(substr($request->getCountryCurrencyCode(), 3, 3));
        $gpl_switch_client->getTrx()->setTransactionAmount($request->getAmount());
        $gpl_switch_client->getTrx()->setTransactionDate(IappsDateTime::now());

        if ($customer_ref_no = $request->getOption()->getValue('customer_ref_no'))
            $gpl_switch_client->setCustomerRefNo($customer_ref_no);
        if ($send_amount = $request->getOption()->getValue('send_amount'))
            $gpl_switch_client->getTrx()->setSendAmount($send_amount);
        if ($send_amount_currency = $request->getOption()->getValue('send_amount_currency'))
            $gpl_switch_client->getTrx()->setSendAmountCurrency(substr($send_amount_currency, 3, 3));
        if ($calc_dir = $request->getOption()->getValue('conversion_direction'))
            $gpl_switch_client->getTrx()->setConversionDirection($calc_dir);
        if ($round_decimal = $request->getOption()->getValue('round_decimal'))
            $gpl_switch_client->getTrx()->setRoundDecimal($round_decimal);

        if( $purpose = $request->getOption()->getValue('purpose') )
            $gpl_switch_client->getTrx()->setPurpose($purpose);
        if( $fund_source = $request->getOption()->getValue('sender_income_source') )
            $gpl_switch_client->getTrx()->setFundSource($fund_source);
        if( $home_collection = $request->getOption()->getValue('home_collection') )
            $gpl_switch_client->getTrx()->setHomeCollection($home_collection);
        if( $rate = $request->getOption()->getValue('rate') )
            $gpl_switch_client->getTrx()->setRate($rate);
        if( $service_charge = $request->getOption()->getValue('service_charge') )
            $gpl_switch_client->getTrx()->setServiceCharge($service_charge);

        //sender
        if( $sender_member_number = $request->getOption()->getValue('sender_member_number') )
            $gpl_switch_client->getSender()->setMemberNumber($sender_member_number);
        if( $sender_fullname = $request->getOption()->getValue('sender_fullname') )
            $gpl_switch_client->getSender()->setFullName(strtoupper(self::_formatString($sender_fullname)));
        if( $sender_gender = $request->getOption()->getValue('sender_gender') )
            $gpl_switch_client->getSender()->setGender($sender_gender);
        if( $sender_nationality = $request->getOption()->getValue('sender_nationality') )
            $gpl_switch_client->getSender()->setNationalityCountryCode($sender_nationality);
        if( $sender_id_type = $request->getOption()->getValue('sender_id_type') )
            $gpl_switch_client->getSender()->setIdentityCardType($sender_id_type);
        if( $sender_id_number = $request->getOption()->getValue('sender_id_number') )
            $gpl_switch_client->getSender()->setIdentityCardNumber($sender_id_number);
        if( $sender_id_expiry = $request->getOption()->getValue('sender_id_expiry') )
            $gpl_switch_client->getSender()->setIdentityCardExpiry(IappsDateTime::fromString($sender_id_expiry));
        if( $sender_birth_date = $request->getOption()->getValue('sender_birth_date') )
            $gpl_switch_client->getSender()->setDateOfBirth(IappsDateTime::fromString($sender_birth_date));
        if( $sender_occupation = $request->getOption()->getValue('sender_occupation') )
            $gpl_switch_client->getSender()->setOccupation($sender_occupation);
        if( $sender_income_source = $request->getOption()->getValue('sender_income_source') )
            $gpl_switch_client->getSender()->setIncomeSource($sender_income_source);
        if( $sender_address = $request->getOption()->getValue('sender_address') )
            $gpl_switch_client->getSender()->setAddress(self::_formatString($sender_address));
        if( $sender_phone = $request->getOption()->getValue('sender_phone') )
            $gpl_switch_client->getSender()->setContactNumber($sender_phone);
        if( $sender_postal_code = $request->getOption()->getValue('sender_postal_code') )
            $gpl_switch_client->getSender()->setPostalCode($sender_postal_code);

        //receiver
        $gpl_switch_client->getReceiver()->setCountryCode(substr($request->getCountryCurrencyCode(),0,2));
        if( $receiver_name = $request->getOption()->getValue('receiver_name') )
            $gpl_switch_client->getReceiver()->setReceiverName(strtoupper(self::_formatString($receiver_name)));
        if( $receiver_address = $request->getOption()->getValue('receiver_address') )
            $gpl_switch_client->getReceiver()->setAddress(self::_formatString($receiver_address));
        if( $bank_code = $request->getOption()->getValue('bank_code') )
            $gpl_switch_client->getReceiver()->setBankCode($bank_code);
        if( $account = $request->getOption()->getValue('bank_account') )
            $gpl_switch_client->getReceiver()->setAccountNo($account);
        if( $bank_branch = $request->getOption()->getValue('bank_branch') )
            $gpl_switch_client->getReceiver()->setBankBranch($bank_branch);
        if( $receiver_mobile_phone = $request->getOption()->getValue('receiver_mobile_phone') )
            $gpl_switch_client->getReceiver()->setContactNumber($receiver_mobile_phone);
        if( $relationship = $request->getOption()->getValue('relationship') )
            $gpl_switch_client->getReceiver()->setRelationship($relationship);
        if( $ktpNo = $request->getOption()->getValue('KtpNo') )
            $gpl_switch_client->getReceiver()->setKtpNo($ktpNo);

        GPLSwitchSignature::generate($gpl_switch_client);
        GPLSwitchClientCodeMapper::map($gpl_switch_client);
        return $gpl_switch_client;
    }

    public static function buildFromOption(array $option)
    {
        $client = self::build();
        $client->setFromOption($option);

        return $client;
    }

    protected static function _formatString($string){
        return trim( str_replace( PHP_EOL, ' ', $string ) );
    }
}