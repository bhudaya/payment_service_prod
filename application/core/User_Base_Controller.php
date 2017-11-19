<?php (defined('BASEPATH')) OR exit('No direct script access allowed');

use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Microservice\AccountService\SessionType;

class User_Base_Controller extends Base_Controller
{
    function __construct()
    {
        parent::__construct();

        $this->_authoriseClient();
    }

    //override
    protected function _getUserProfileId($function = NULL, $access_type = NULL, $session_type = NULL)
    {
        if ($function == NULL) {
            $function = FunctionCode::PUBLIC_FUNCTIONS;
        }
        if ($access_type == NULL) {
            $access_type = AccessType::WRITE;
        }
        if ($session_type == NULL) {
            $session_type = SessionType::LOGIN;
        }

        return parent::_getUserProfileId($function, $access_type, $session_type);
    }
}