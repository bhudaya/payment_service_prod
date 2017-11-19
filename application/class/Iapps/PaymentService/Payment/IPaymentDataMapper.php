<?php

namespace Iapps\PaymentService\Payment;

use Iapps\Common\Core\IappsBaseDataMapper;
use Iapps\Common\Core\IappsDateTime;

interface IPaymentDataMapper extends IappsBaseDataMapper{

    public function findByTransactionID($module_id, $transactionID);
    public function findByTransactionIDArr($module_id, $transactionIDArr);
    public function insert(Payment $payment );
    public function update(Payment $payment );
    public function findByParam(Payment $payment, $limit , $page );
    public function findByCreatorAndParam(Payment $payment, $created_by_arr, $limit, $page, IappsDateTime $date_from = NULL, IappsDateTime $date_to = NULL);
    public function reportFindByParam(Payment $payment, IappsDateTime $date_from, IappsDateTime $date_to);

}