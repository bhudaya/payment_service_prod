<?php

namespace Iapps\PaymentService\Common\EwalletClient;

use Iapps\Common\Helper\ResponseMessage;
use Iapps\PaymentService\PaymentRequest\PaymentRequestResponseInterface;
use Iapps\Common\Helper\StringMasker;

class EwalletClientResponse implements PaymentRequestResponseInterface{

    protected $raw;

    protected $status_code;
    protected $success;
    protected $request_token;

    function __construct(array $response)
    {
        $this->setRaw($response);
    }

    public function setRaw(array $raw)
    {
        $this->raw = $raw;
        $this->_extractResponse($raw);
        return $this;
    }

    public function getRaw()
    {
        return $this->raw;
    }

    public function setRequestToken($token)
    {
        $this->request_token = $token;
        return $this;
    }

    public function getRequestToken()
    {
        return $this->request_token;
    }

    public function setStatusCode($code)
    {
        $this->status_code = $code;
        return $this;
    }

    public function getStatusCode()
    {
        return $this->status_code;
    }

    public function setSuccess($success)
    {
        $this->success = $success;
        return $this;
    }

    public function getSuccess()
    {
        return $this->success;
    }

    protected function _extractResponse(array $fields)
    {
        foreach($fields AS $field => $value )
        {
            if( $field == 'success' )
                $this->setSuccess($value);

            if( $field == 'response' )
            {
                if( is_array($value) )
                {
                    $status_code = isset($value['status_code']) ? $value['status_code'] : NULL;
                    $this->setStatusCode($status_code);

                    if( isset($value['result']) )
                    {
                        if( is_array($value['result']) )
                            $token = isset($value['result']['token']) ? $value['result']['token'] : NULL;
                        else
                            $token = isset($value['result']->token) ? $value['result']->token : NULL;

                        $this->setRequestToken($token);
                    }

                }
            }
        }
    }

    public function getResponse()
    {
        return json_encode($this->getRaw());
    }

    public function isSuccess()
    {
        return ($this->getSuccess() === true);
    }
}