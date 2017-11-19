<?php

namespace Iapps\PaymentService\Payment;

use Iapps\Common\Core\IappsBaseRepository;
use Iapps\Common\Core\IappsDateTime;

class PaymentRepository extends IappsBaseRepository{

    public function findByTransactionID($module_id, $transactionID)
    {
        return $this->getDataMapper()->findByTransactionID($module_id, $transactionID);
    }

    public function findByTransactionIDArr($module_id, $transactionIDArr)
    {
        return $this->getDataMapper()->findByTransactionIDArr($module_id, $transactionIDArr);
    }

    public function update(Payment $payment)
    {
        return $this->getDataMapper()->update($payment);
    }

    public function insert(Payment $payment)
    {
        return $this->getDataMapper()->insert($payment);
    }
        
    public function findByParam(Payment $payment, $limit , $page)
    {
        return $this->getDataMapper()->findByParam($payment, $limit , $page);
    }

    public function findByCreatorAndParam(Payment $payment, $created_by_arr, $limit, $page, IappsDateTime $date_from = NULL, IappsDateTime $date_to = NULL)
    {
        return $this->getDataMapper()->findByCreatorAndParam($payment,  $created_by_arr, $limit, $page, $date_from, $date_to);
    }

    public function reportFindByParam(Payment $payment, IappsDateTime $date_from, IappsDateTime $date_to)
    {
        return $this->getDataMapper()->reportFindByParam($payment, $date_from, $date_to);
    }

}