<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

/*
* This class is responsible to map our own value to the code that recognised by GPL
*/
use Iapps\PaymentService\CodeMapper\CodeMapper;
use Iapps\PaymentService\CodeMapper\CodeMapperCollection;
use Iapps\PaymentService\CodeMapper\CodeMapperServiceFactory;
use Iapps\PaymentService\CodeMapper\CodeMapperType;

class GPLSwitchClientCodeMapper {

    public static function map(GPLSwitchClient $client)
    {
        //get code mapper
        $codeServ = CodeMapperServiceFactory::build();

        $collection = new CodeMapperCollection();

        $bankCode = $client->getReceiver()->getCountryCode() . "-" . $client->getReceiver()->getBankCode();
        $idtype = $client->getSender()->getIdentityCardType();
        $purpose = $client->getTrx()->getPurpose();
        $fundSource = $client->getTrx()->getFundSource();
        $nationality = $client->getSender()->getNationalityCountryCode();
        $payment_method = $client->getTrx()->getPaymentMethod();

        $bankcodeCode = new CodeMapper();
        $bankcodeCode->getType()->setCode(CodeMapperType::GPL_BANK_CODE);
        $bankcodeCode->setReferenceValue($bankCode);
        $collection->addData($bankcodeCode);
        $client->getReceiver()->setBankCode(NULL);

        //sender id type
        $idtypeCode = new CodeMapper();
        $idtypeCode->getType()->setCode(CodeMapperType::GPL_SENDER_IDENTITY_TYPE);
        $idtypeCode->setReferenceValue($idtype);
        $collection->addData($idtypeCode);
        $client->getSender()->setIdentityCardType(NULL);

        //remittance purpose
        $purposeCode = new CodeMapper();
        $purposeCode->getType()->setCode(CodeMapperType::GPL_REMITTANCE_PURPOSE);
        $purposeCode->setReferenceValue($purpose);
        $collection->addData($purposeCode);
        $client->getTrx()->setPurpose(NULL);

        //fund
        $fundCode = new CodeMapper();
        $fundCode->getType()->setCode(CodeMapperType::GPL_FUND_OF_SOURCE);
        $fundCode->setReferenceValue($fundSource);
        $collection->addData($fundCode);
        $client->getTrx()->setFundSource(NULL);
        $client->getSender()->setIncomeSource(NULL);

        //nationality
        $nationalityCode = new CodeMapper();
        $nationalityCode->getType()->setCode(CodeMapperType::GPL_NATIONALITY);
        $nationalityCode->setReferenceValue($nationality);
        $collection->addData($nationalityCode);
        $client->getSender()->setNationalityCountryCode(NULL);

        //payment method
        $paymentMethod = new CodeMapper();
        $paymentMethod->getType()->setCode(CodeMapperType::GPL_PAYMENT_METHOD);
        $paymentMethod->setReferenceValue($payment_method);
        $collection->addData($paymentMethod);
        $client->getTrx()->setPaymentMethod(NULL);

        //payment description
        $paymentDescription = new CodeMapper();
        $paymentDescription->getType()->setCode(CodeMapperType::GPL_PAYMENT_DESCRIPTION);
        $paymentDescription->setReferenceValue($payment_method);
        $collection->addData($paymentDescription);
        $client->getTrx()->setPaymentDescription(NULL);

        if( $collection = $codeServ->getByReferenceValues($collection) AND
            $collection->result instanceof CodeMapperCollection)
        {
            //map sender id
            if( $info = $collection->result->getByReferenceValue($idtype, CodeMapperType::GPL_SENDER_IDENTITY_TYPE) )
                $client->getSender()->setIdentityCardType($info->getMappedValue());

            if( $info = $collection->result->getByReferenceValue($purpose, CodeMapperType::GPL_REMITTANCE_PURPOSE) )
                $client->getTrx()->setPurpose($info->getMappedValue());

            if( $info = $collection->result->getByReferenceValue($fundSource, CodeMapperType::GPL_FUND_OF_SOURCE) )
            {
                $client->getTrx()->setFundSource($info->getMappedValue());
                $client->getSender()->setIncomeSource($info->getMappedValue());
            }

            if( $info = $collection->result->getByReferenceValue($nationality, CodeMapperType::GPL_NATIONALITY) )
                $client->getSender()->setNationalityCountryCode($info->getMappedValue());

            if( $info = $collection->result->getByReferenceValue($bankCode, CodeMapperType::GPL_BANK_CODE) )
                $client->getReceiver()->setBankCode($info->getMappedValue());

            //TRANSACTION
            if( $info = $collection->result->getByReferenceValue($payment_method, CodeMapperType::GPL_PAYMENT_METHOD) )
                $client->getTrx()->setPaymentMethod($info->getMappedValue());

            if( $info = $collection->result->getByReferenceValue($payment_method, CodeMapperType::GPL_PAYMENT_DESCRIPTION) )
                $client->getTrx()->setPaymentDescription($info->getMappedValue());
        }

        return $client;
    }
}
