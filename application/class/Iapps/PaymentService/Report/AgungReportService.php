<?php

namespace Iapps\PaymentService\Report;

use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\PaymentMode\PaymentModeType;
use Iapps\PaymentService\Common\MessageCode;
use Iapps\Common\Core\IappsBasicBaseService;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Microservice\CountryService\CountryServiceFactory;
use Iapps\PaymentService\Payment\Payment;
use Iapps\PaymentService\Payment\PaymentStatus;
use Iapps\PaymentService\Payment\PaymentServiceFactory;
use Iapps\PaymentService\Payment\PaymentCollection;
use Iapps\PaymentService\PaymentRequest\PaymentRequestServiceFactory;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeServiceFactory;
use Iapps\PaymentService\PaymentModeAttribute\PaymentModeAttributeCode;
use Iapps\PaymentService\PaymentRequest\SearchPaymentRequestServiceFactory;

class AgungReportService extends IappsBasicBaseService
{
    
    /*
    * agung transaction report
    */

    public function getAgungTransactionReport($admin_id, $date_from,$date_to)
    {

        $final_results = array();
        $final_results['header'] = NULL;
        $final_results['data']   = NULL;
        $final_results['timezone']   = NULL;

        $accountSer = AccountServiceFactory::build();

        if ($upline = $accountSer->getUplineStructure($admin_id)) {
            
            if($partner = $upline->first_upline->getUser()){

                $final_results['header'] = $partner;
            }
        }

        $timezone_format = NULL;
        if ($login_user_info = $accountSer->getUser(NULL,$admin_id)) {
            
            if (isset($login_user_info->getHostAddress()->country)) {
                
                $countryCode = $login_user_info->getHostAddress()->country;
                $country_serv = CountryServiceFactory::build();

                if($countryInfo = $country_serv->getCountryInfo($countryCode) )
                {
                    $timezone_format = $countryInfo->getTimezoneFormat();
                    $final_results['timezone'] = $timezone_format;
                }
            }
        }

        $payment = new Payment();
        $payment->setPaymentCode(PaymentModeType::BANK_TRANSFER_INDO_OCBC);
        $payment->getStatus()->setCode(PaymentStatus::COMPLETE);

        $paymentSer = PaymentServiceFactory::build();

        if ($paymentInfos = $paymentSer->reportFindByParam($payment, $date_from, $date_to)) {
            
            $paymentColl = new PaymentCollection();
            $paymentRequestSer = SearchPaymentRequestServiceFactory::build();
            $attrServ = PaymentModeAttributeServiceFactory::build();

            foreach ($paymentInfos->result as $eachColl) {
                
                $paymentRequestInfos = $paymentRequestSer->getPaymentByPaymentRequestID($eachColl->getPaymentRequestId());                
                
                if ($paymentRequestInfos) {
                  
                  $bank_name = null;
                  if( $value = $bank_name = $attrServ->getValueByCode($payment->getPaymentCode(), PaymentModeAttributeCode::BANK_CODE, $paymentRequestInfos->getOption()->getValue('dest_bankcode')) ) 

                  $bank_name = $value->getValue();
                  $paymentRequestInfos->setBankName($bank_name);
                  $paymentColl->addData($paymentRequestInfos);
                }
            }

            $paymentInfos->result = $paymentColl;
            $final_results['data'] = $paymentInfos->result;

            $this->setResponseCode(MessageCode::CODE_GET_AGUNG_TRANSACTION_REPORT_SUCCESS);
            return $final_results;
        }


        $this->setResponseCode(MessageCode::CODE_GET_AGUNG_TRANSACTION_REPORT_FAIL);
        return $final_results;
    }

    public function export_agung_transaction_csv($data,$date_from,$date_to,$report_lang)
    {
      
      $partner_account_id = NULL;
      $partner_name = NULL;

      if ($data['header']) {
          $partner_account_id   = $data['header']->getAccountID() ? $data['header']->getAccountID() : NULL;
          $partner_name = $data['header']->getFullName() ? $data['header']->getFullName() : $data['header']->getName();
      }

      ini_set('memory_limit', '-1');      
      ini_set('max_input_time', '-1');      
      ini_set('max_execution_time', '-1');

      header("Content-Type: text/csv");
      header("Content-Disposition: attachment; filename=Agung_transaction_report.csv");
      // Disable caching
      header("Cache-Control: no-cache, no-store, must-revalidate"); // HTTP 1.1
      header("Pragma: no-cache"); // HTTP 1.0
      header("Expires: 0"); // Proxies
      header( "1", true, 200);    

      $output = fopen("php://output", "w");

      fputs($output, "sep=,\n");

      $columns = array();

      $printed_date = IappsDateTime::now();

      $date_from = substr($date_from,0,10);
      $date_to = substr($date_to,0,10);

      if ($data['timezone']) {

          $printed_date->setTimeZoneFormat($data['timezone']);
          $temp_date = $printed_date->getLocalDateTimeStr('d-m-Y H:i:s');
          $printed_date->setDateTimeString($temp_date);
      }

      if ($report_lang == 'English') {

          $columns = array(
                        'Date' => '',
                        'Time' => '',
                        'Terminal ID' => '',
                        'Transaction Type' => '',
                        'Transaction Status' => '',
                        'Destination Reference No.' => '',
                        'OCBC Tektaya Reference No.' => '',
                        'Destination Bank' => '',
                        'Currency' => '',
                        'Transaction Amount' => '',
                        'Destination Bank Account No.' => '',
                        'Customer ID' => ''
                        );

          $row  = array('PRINTED DATE: '.$printed_date->getString().' PARTNER ID: '.$partner_account_id.' PARTNER NAME: '.$partner_name);
          fputcsv($output, array_values($row));   

          $row  = array('TRANSACTION DATE: FROM '.$date_from.' TO '.$date_to);
          fputcsv($output, array_values($row));  
      }

      if ($report_lang == 'Bahasa') {
        
          $columns = array(
                        'Tanggal Transaksi' => '',
                        'Waktu Transaksi' => '',
                        'Terminal ID' => '',
                        'Jenis Transaksi' => '',
                        'Status Transaksi' => '',
                        'No. Referensi' => '',
                        'No. Resi' => '',
                        'Tujuan Transaksi' => '',
                        'Mata uang' => '',
                        'Nominal Transaksi' => '',
                        'Rekening Tujuan' => '',
                        'ID Pelanggan' => ''
                        );

          $row  = array('TGL DICETAK: '.$printed_date->getString().' MERCHANT ID: '.$partner_account_id.' NAMA MERCHANT: '.$partner_name);
          fputcsv($output, array_values($row)); 

          $row  = array('TANGGAL TRANSAKSI '.$date_from.' KE '.$date_to);
          fputcsv($output, array_values($row));
      }
      
      $row  = array();
      fputcsv($output, array_values($row));  

      //write header 
      $headerRow = array();
      $headerRow['No.'] = 'No.';
      foreach ($columns as $k => $v) {
        $headerRow[] = $k;
      }

      fputcsv($output, array_values($headerRow));
        
      $no = 1;

      if (count($data['data']) >= 1) {
          foreach ($data['data'] as $eachData) {

          $row = array();
          $row['no'] = $no;

          foreach ($columns as $k => $v) {

            $option = $eachData->getOption()->toArray();
            $response = $eachData->getResponse()->toArray();

            if ($data['timezone']) {
                $response['timestamp'] = IappsDateTime::fromString($response['timestamp']);
                $response['timestamp']->setTimeZoneFormat($data['timezone']);
                $temp_date = $response['timestamp']->getLocalDateTimeStr('Ymd H:i:s');
                $response['timestamp']->setDateTimeString($temp_date);
            }else{
                $response['timestamp'] = IappsDateTime::fromString($response['timestamp']);
                $temp_date = $response['timestamp']->getLocalDateTimeStr('Ymd H:i:s');
                $response['timestamp']->setDateTimeString($temp_date);
            }

            if ($k == "Date" || $k == "Tanggal Transaksi") {

              $row[] = substr($response['timestamp']->getString(),0,8);

            }else if ($k == "Time" || $k == "Waktu Transaksi") {

              $row[] = substr($response['timestamp']->getString(),-8);

            }else if ($k == "Terminal ID") {

              if ( isset($option['terminal_code']) ) {
                
                  $row[] = $option['terminal_code'];
              }else{
                  $row[] = "";
              }

            }else if ($k == "Transaction Type" || $k == "Jenis Transaksi") {
              
              if ( isset($response['action']) ) {
                
                  $row[] = $response['action'];
              }else{
                  $row[] = "";
              }

            }else if ($k == "Transaction Status" || $k == "Status Transaksi") {
              
              if ( isset($response['err_description']) ) {
                
                  $row[] = $response['err_description'];
              }else{
                  $row[] = "";
              }

            }else if ($k == "Destination Reference No." || $k == "No. Referensi") {
              
              if ( isset($option['dest_refnumber']) ) {
                
                  $row[] = $option['dest_refnumber']."\t";
              }else{
                  $row[] = "";
              }

              
            }else if ($k == "OCBC Tektaya Reference No." || $k == "No. Resi") {
              
              if ( isset($response['trx_refferenceid']) ) {
                
                  $row[] = $response['trx_refferenceid']."\t";
              }else{
                  $row[] = "";
              }
              
            }else if ($k == "Destination Bank" || $k == "Tujuan Transaksi") {
              
              $row[] = $eachData->getBankName();

            }else if ($k == "Currency" || $k == "Mata uang") {
              
              $row[] = substr($eachData->getCountryCurrencyCode(),-3);

            }else if ($k == "Transaction Amount" || $k == "Nominal Transaksi") {
              
              $row[] = str_replace('-','',$eachData->getAmount());
              
            }else if ($k == "Destination Bank Account No." || $k == "Rekening Tujuan") {
              
              if ( isset($option['dest_bankacc']) ) {
                
                  $row[] = $option['dest_bankacc']."\t";
              }else{
                  $row[] = "";
              }

              
            }else if ($k == "Customer ID" || $k == "ID Pelanggan") {

              if ( isset($response['sender_idcardnumber']) ) {
                
                  $row[] = $response['sender_idcardnumber'];
              }else{
                  $row[] = "";
              }

            }

          }

          fputcsv($output, array_values($row));
          $no++;
        }
      }
      
      
      $row  = array();
      fputcsv($output, array_values($row));
      $row  = array();
      fputcsv($output, array_values($row));            
      
      fclose($output);
      exit();
    }

}