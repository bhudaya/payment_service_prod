<?php

namespace Iapps\PaymentService\PaymentRequest;

use Iapps\Common\Core\IappsBaseDataMapperV2;

interface IPaymentRequestDataMapper extends IappsBaseDataMapperV2{

    public function findByTransactionID($module_id, $transactionID);
    public function insert(PaymentRequest $request);
    public function updateResponse(PaymentRequest $request);
    public function updateStatus(PaymentRequest $request);
    public function update(PaymentRequest $request);
    public function findList($module_code = null, $start_timestamp = null, $end_timestamp = null, $orderBy = null);
    public function findBySearchFilter(PaymentRequest $request, array $user_profile_id_arr = NULL, $limit, $page);
    public function updateFirstCheck(PaymentRequest $request);
    public function trxListFindBySearchFilter(PaymentRequest $request, $limit, $page);
}