<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\AuditLog\AuditLogAction;
use Iapps\Common\CommunicationService\CommunicationServiceProducer;
use Iapps\Common\Core\IappsDateTime;
use Iapps\PaymentService\Common\MessageCode;

class PaymentRequestReconciliationService extends PaymentRequestService{

    public function reconciliationCompare($module_code, $date, $file_path)
    {
        try{

            //select data from database
            $start_time = $date . ' 00:00:00';
            $end_time = $date . ' 23:59:59';

            $start_timestamp = IappsDateTime::fromString($start_time)->getUnix();
            $end_timestamp = IappsDateTime::fromString($end_time)->getUnix();
            $orderBy = 'reference_id';
            $object = $this->getRepository()->findList($module_code, $start_timestamp, $end_timestamp, $orderBy);
            $dbData = $object->result->toArray();

//            //read data from csv file
//            $objPHPExcel = new \PHPExcel();
//            $objPHPExcel = \PHPExcel_IOFactory::load($file_path);
//            $fileData = $objPHPExcel->getActiveSheet()->toArray(null,true,true,true);

            $objPHPReader = new \PHPExcel_Reader_CSV();
            $objPHPReader->setInputEncoding('GBK');
            $objPHPReader->setDelimiter(';');

            $fileData = array();

            if($objPHPReader->canRead($file_path)){
                $objPHPExcel = $objPHPReader->load($file_path);
                $fileData = $objPHPExcel->getActiveSheet()->toArray(null,true,true,true);
            }

            unlink($file_path);

            $reference_ids = array();
            foreach ($fileData as $rowData) {
                $reference_ids[] = $rowData['A'];
            }
            array_multisort($reference_ids, SORT_ASC, $fileData);

            //1.in db and in file, and compare is true
            //2.in db and in file, and compare is false
            //3.in db, not in file
            //4.in file, not in db

            // create new phpExcel Object for write compare result to excel/html
            $objPHPExcel = new \PHPExcel();
            $objPHPExcel->setActiveSheetIndex(0);
            $sheet = $objPHPExcel->getActiveSheet();
            $sheet->setTitle('reconciliation_result');

            $columnName = array(
                '1' => 'S/N',
                '2' => "tag",

                '3' => "reference_id",
                '4' => "dest_refnumber",
                '5' => "product_code",
                '6' => "merchant_code",
                '7' => "terminal_code",
                '8' => "dest_bankcode",
                '9' => "dest_bankacc",
                '10' => "dest_custname",
                '11' => "dest_amount",
                '12' => "err_code",

                '13' => "reference_id",
                '14' => "dest_refnumber",
                '15' => "product_code",
                '16' => "merchant_code",
                '17' => "terminal_code",
                '18' => "dest_bankcode",
                '19' => "dest_bankacc",
                '20' => "dest_custname",
                '21' => "dest_amount",
                '22' => "err_code"
            );

            $rowNum = 1;
            $sheet->getComment("B2")->getText()->createTextRun('1.in db and in file, and compare is true
2.in db and in file, and compare is false
3.in db, not in file
4.in file, not in db');
            //        $sheet->getComment("B2")->setVisible(true);
            $sheet->getComment("B2")->setWidth("220pt");
            $sheet->mergeCells("B$rowNum:K$rowNum");
            $sheet->mergeCells("L$rowNum:U$rowNum");
            $sheet->setCellValue("C1","in database");
            $sheet->setCellValue("M1","in csv file");

            $rowNum = 2;
            $columnNum = 'A';
            foreach ($columnName as $key => $value) {
                $sheet->setCellValue("$columnNum$rowNum", $value);
                $columnNum++;
            };

            $rowNum = 3;
            $sn = 0;
            while(count($dbData) > 0 && count($fileData) > 0)
            {
                $sn++;
                $dbRow = reset($dbData);
                $fileRow = reset($fileData);

                $reference_id = $dbRow->getReferenceId();

                $compareResult = array();

                //1/2.in db and in file
                if($reference_id == $fileRow['A'])
                {
                    $dbRowOption = $dbRow->getOption();
                    $dbRowResponse = $dbRow->getResponse();
                    $dbRowOption = json_decode($dbRowOption);
                    $dbRowResponse = json_decode($dbRowResponse);

                    if($this->compareData($dbRowOption, $dbRowResponse, $fileRow, $compareResult) == true)
                    {
                        //1.in db and in file, and compare is true
                        $rowWrite = $this->generateRowData(1, $reference_id, $dbRowOption, $dbRowResponse, $fileRow);

                    }
                    else
                    {
                        //2.in db and in file, and compare is false
                        $rowWrite = $this->generateRowData(2, $reference_id, $dbRowOption, $dbRowResponse, $fileRow);

                    }
                    array_shift($dbData);
                    array_shift($fileData);
                }
                else if($reference_id < $fileRow['A'])
                {
                    $dbRowOption = $dbRow->getOption();
                    $dbRowResponse = $dbRow->getResponse();
                    $dbRowOption = json_decode($dbRowOption);
                    $dbRowResponse = json_decode($dbRowResponse);

                    //3.in db, not in file
                    $rowWrite = $this->generateRowData(3, $reference_id, $dbRowOption, $dbRowResponse, $fileRow);

                    array_shift($dbData);
                }
                else if($reference_id > $fileRow['A'])
                {
                    //4.in file, not in db
                    $rowWrite = $this->generateRowData(4, null, null, null, $fileRow);

                    array_shift($fileData);
                }

                // write to excel
                $columnNum = "B";
                $tag = false;

                $sheet->setCellValue("A$rowNum", $sn);

                foreach ($rowWrite as $key => $value) {
                    if($key == 'tag' && $value == 2)
                    {
                        $tag = true;
                    }
                    if($tag)
                    {
                        $key2 = ltrim($key,"f_");
                        if((array_key_exists($key, $compareResult) || array_key_exists($key2, $compareResult)) && $compareResult[$key2] == false)
                        {
                            $sheet->getStyle("$columnNum$rowNum")->getFont()->getColor()->setARGB('FFFF0000');
                        }
                    }
                    $sheet->setCellValue("$columnNum$rowNum", $value);
                    $columnNum++;
                }
                $rowNum++;
            }

            if(count($dbData) > 0)
            {
                //3.in db, not in file
                while(count($dbData) > 0)
                {
                    $sn++;
                    $dbRow = reset($dbData);
                    $reference_id = $dbRow->getReferenceId();
                    $dbRowOption = $dbRow->getOption();
                    $dbRowResponse = $dbRow->getResponse();
                    $dbRowOption = json_decode($dbRowOption);
                    $dbRowResponse = json_decode($dbRowResponse);

                    $rowWrite = $this->generateRowData(3, $reference_id, $dbRowOption, $dbRowResponse, $fileRow);

                    array_shift($dbData);

                    // write to excel
                    $columnNum = "B";
                    $sheet->setCellValue("A$rowNum", $sn);
                    foreach ($rowWrite as $key => $value) {
                        $sheet->setCellValue("$columnNum$rowNum", $value);
                        $columnNum++;
                    }
                    $rowNum++;
                }
            }
            if(count($fileData) > 0)
            {
                //4.in file, not in db
                while(count($fileData) > 0)
                {
                    $sn++;
                    $fileRow = reset($fileData);

                    $rowWrite = $this->generateRowData(4, null, null, null, $fileRow);

                    array_shift($fileData);

                    // write to excel
                    $columnNum = "B";
                    $sheet->setCellValue("A$rowNum", $sn);
                    foreach ($rowWrite as $key => $value) {
                        $sheet->setCellValue("$columnNum$rowNum", $value);
                        $columnNum++;
                    }
                    $rowNum++;
                }
            }

//            $extName = explode('.', $file_path);
//            $extName = end($extName);
            $save_path = "./uploads/export/reconciliation_compare_".IappsDateTime::now()->getUnix().".html";
            $objWriter = \PHPExcel_IOFactory::createWriter($objPHPExcel, 'HTML');
            $objWriter->save($save_path);

            $content = file_get_contents($save_path,false,null);

            //This file needs to delete ?
            //unlink($save_path);

            //send mail
            $_communicationService = new CommunicationServiceProducer();
            $sendResult = $_communicationService->sendEmail(null,"reconciliation_compare_result_".$date,$content,$content,"chao@iappsasia.com");
            var_dump($sendResult);
            if($sendResult)
            {

            }

            $this->setResponseCode(MessageCode::CODE_RECONCILIATION_SUCCESS);
            return true;
        }
        catch (\Exception $ex)
        {
            $this->setResponseCode(MessageCode::CODE_RECONCILIATION_FAILED);
            return false;
        }
    }

    private function generateRowData($tag, $reference_id, $dbRowOption, $dbRowResponse, $fileRow)
    {
        if($tag == 3)
        {
            //3.in db, not in file
            $array = array(
                "tag" => $tag,

                "reference_id" => $reference_id,
                "dest_refnumber" => $dbRowOption->dest_refnumber,
                "product_code" => $dbRowOption->product_code,
                "merchant_code" => $dbRowOption->merchant_code,
                "terminal_code" => $dbRowOption->terminal_code,
                "dest_bankcode" => $dbRowOption->dest_bankcode,
                "dest_bankacc" => $dbRowOption->dest_bankacc,
                "dest_custname" => $dbRowResponse->dest_custname,
                "dest_amount" => $dbRowResponse->dest_amount,
                "err_code" => $dbRowResponse->err_code,

                "f_reference_id" => NULL,
                "f_dest_refnumber" => NULL,
                "f_product_code" => NULL,
                "f_merchant_code" => NULL,
                "f_terminal_code" => NULL,
                "f_dest_bankcode" => NULL,
                "f_dest_bankacc" => NULL,
                "f_dest_custname" => NULL,
                "f_dest_amount" => NULL,
                "f_err_code" => NULL
            );
        }
        else if($tag == 4)
        {
            //4.in file, not in db
            $array = array(
                "tag" => $tag,

                "reference_id" => null,
                "dest_refnumber" => null,
                "product_code" => null,
                "merchant_code" => null,
                "terminal_code" => null,
                "dest_bankcode" => null,
                "dest_bankacc" => null,
                "dest_custname" => null,
                "dest_amount" => null,
                "err_code" => null,

                "f_reference_id" => $fileRow['A'],
                "f_dest_refnumber" => $fileRow['B'],
                "f_product_code" => $fileRow['C'],
                "f_merchant_code" => $fileRow['D'],
                "f_terminal_code" => $fileRow['E'],
                "f_dest_bankcode" => $fileRow['F'],
                "f_dest_bankacc" => $fileRow['G'],
                "f_dest_custname" => $fileRow['H'],
                "f_dest_amount" => $fileRow['I'],
                "f_err_code" => $fileRow['J']
            );
        }
        else
        {
            $array = array(
                "tag" => $tag,

                "reference_id" => $reference_id,
                "dest_refnumber" => $dbRowOption->dest_refnumber,
                "product_code" => $dbRowOption->product_code,
                "merchant_code" => $dbRowOption->merchant_code,
                "terminal_code" => $dbRowOption->terminal_code,
                "dest_bankcode" => $dbRowOption->dest_bankcode,
                "dest_bankacc" => $dbRowOption->dest_bankacc,
                "dest_custname" => $dbRowResponse->dest_custname,
                "dest_amount" => $dbRowResponse->dest_amount,
                "err_code" => $dbRowResponse->err_code,

                "f_reference_id" => $fileRow['A'],
                "f_dest_refnumber" => $fileRow['B'],
                "f_product_code" => $fileRow['C'],
                "f_merchant_code" => $fileRow['D'],
                "f_terminal_code" => $fileRow['E'],
                "f_dest_bankcode" => $fileRow['F'],
                "f_dest_bankacc" => $fileRow['G'],
                "f_dest_custname" => $fileRow['H'],
                "f_dest_amount" => $fileRow['I'],
                "f_err_code" => $fileRow['J']
            );
        }
        return $array;
    }

    private function compareData($dbRowOption, $dbRowResponse, $fileRow, &$result)
    {
        // {"product_code":"800","merchant_code":"6012","terminal_code":"a56a2aef-704c-4d6d-9bf4-352689f32d41","dest_refnumber":"20160316TR000041RMT","dest_bankcode":"097","dest_bankacc":"****898","dest_amount":"5550000","timestamp":"16-03-2016 09:48:59","dest_custname":"-","purpose":"","relationship":"","recipient_name":"","recipient_address":"","recipient_city":"","recipient_postcode":"","recipient_country":"","recipient_telepon":"","recipient_email":"","sender_name":"","sender_address":"","sender_city":"","sender_postcode":"","sender_country":"","sender_telepon":"","sender_email":"","sender_idcardcode":"","sender_idcardnumber":"","track_number":" ","action":"transfer_money","err_code":"00","trx_refferenceid":"094859000535","err_description":"success"}
        // A:reference_id | B:dest_refnumber | C:product | D:merchant_code |  E:terminal_code | F:dest_bankcode | G:dest_bankacc | H:dest_custname | I:dest_amount | J:err_code
        $compareResult = true;
        $result = array();

        if($dbRowOption->dest_refnumber != $fileRow['B'])
        {
            $result['dest_refnumber'] = false;
            $compareResult = false;
        }
        else
        {
            $result['dest_refnumber'] = true;
        }

        if($dbRowOption->product_code != $fileRow['C'])
        {
            $result['product_code'] = false;
            $compareResult = false;
        }
        else
        {
            $result['product_code'] = true;
        }

        if($dbRowOption->merchant_code != $fileRow['D'])
        {
            $result['merchant_code'] = false;
            $compareResult = false;
        }
        else
        {
            $result['merchant_code'] = true;
        }

        if($dbRowOption->terminal_code != $fileRow['E'])
        {
            $result['terminal_code'] = false;
            $compareResult = false;
        }
        else
        {
            $result['terminal_code'] = true;
        }

        if($dbRowOption->dest_bankcode != $fileRow['F'])
        {
            $result['dest_bankcode'] = false;
            $compareResult = false;
        }
        else
        {
            $result['dest_bankcode'] = true;
        }

//        if($dbRowOption->dest_bankacc != $fileRow['G'])
//        {
//            $result['dest_bankacc'] = false;
//            $compareResult = false;
//        }
//        else
//        {
        $result['dest_bankacc'] = true;
//        }

        if($dbRowResponse->dest_custname != $fileRow['H'])
//        if($dbData->username != $fileData['H'])
        {
            $result['dest_custname'] = false;
            $compareResult = false;
        }
        else
        {
            $result['dest_custname'] = true;
        }

        if($dbRowResponse->dest_amount != $fileRow['I'])
        {
            $result['dest_amount'] = false;
            $compareResult = false;
        }
        else
        {
            $result['dest_amount'] = true;
        }

        if($dbRowResponse->err_code != $fileRow['J'])
        {
            $result['err_code'] = false;
            $compareResult = false;
        }
        else
        {
            $result['err_code'] = true;
        }

        return $compareResult;
    }
}