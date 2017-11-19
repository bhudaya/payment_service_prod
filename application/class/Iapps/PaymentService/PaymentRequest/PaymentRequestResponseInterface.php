<?php

namespace Iapps\PaymentService\PaymentRequest;

interface PaymentRequestResponseInterface{
    public function isSuccess();
    public function getResponse();
}