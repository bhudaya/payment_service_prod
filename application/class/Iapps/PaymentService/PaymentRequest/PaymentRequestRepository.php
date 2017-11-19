<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Core\IappsBaseRepository;

class PaymentRequestRepository extends IappsBaseRepository{

    public function findByTransactionID($module_code, $transactionID)
    {
        return $this->getDataMapper()->findByTransactionID($module_code, $transactionID);
    }

    public function updateResponse(PaymentRequest $request)
    {
        return $this->getDataMapper()->updateResponse($request);
    }

    public function updateStatus(PaymentRequest $request)
    {
        return $this->getDataMapper()->updateStatus($request);
    }

    public function update(PaymentRequest $request)
    {
        return $this->getDataMapper()->update($request);
    }

    public function insert(PaymentRequest $request)
    {
        return $this->getDataMapper()->insert($request);
    }
    
    public function findList($module_code = null, $start_timestamp = null, $end_timestamp = null, $orderBy = null)
    {
        return $this->getDataMapper()->findList($module_code, $start_timestamp, $end_timestamp, $orderBy);
    }

    public function findBySearchFilter(PaymentRequest $request, array $user_profile_id_arr = NULL, $limit, $page)
    {
        return $this->getDataMapper()->findBySearchFilter($request, $user_profile_id_arr, $limit, $page);
    }

    public function updateFirstCheck(PaymentRequest $request)
    {
        return $this->getDataMapper()->updateFirstCheck($request);
    }

    public function trxListFindBySearchFilter(PaymentRequest $request, $limit, $page)
    {
        return $this->getDataMapper()->trxListFindBySearchFilter($request, $limit, $page);
    }

    public function beginDBTransaction()
    {
        return $this->getDataMapper()->TransBegin();
    }

    public function commitDBTransaction()
    {
        return $this->getDataMapper()->TransCommit();
    }

    public function statusDBTransaction()
    {
        return $this->getDataMapper()->TransStatus();
    }
}