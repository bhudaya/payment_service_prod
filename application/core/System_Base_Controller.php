<?php (defined('BASEPATH')) OR exit('No direct script access allowed');

use Iapps\Common\Microservice\AccountService\FunctionCode;
use Iapps\Common\Microservice\AccountService\AccessType;
use Iapps\Common\Microservice\AccountService\SessionType;
use Iapps\Common\Microservice\AccountService\AccountServiceFactory;
use Iapps\Common\Helper\ResponseHeader;

class System_Base_Controller extends Base_Controller
{
    function __construct()
    {
        parent::__construct();

        $this->_authoriseClient();
    }

    //override
    protected function _getUserProfileId($function = NULL, $access_type = NULL, $session_type = NULL)
    {
        $accessToken = $this->clientToken;

        $account_serv = AccountServiceFactory::build();
        AccountServiceFactory::reset();
        if( $user_profile_id = $account_serv->checkAccess($accessToken, $function, $access_type, $session_type) )
        {
            return $user_profile_id;
        }

        $this->response_message->getHeader()->setStatus(ResponseHeader::HEADER_FORBIDDEN);
        $this->response_message->setStatusCode(ResponseHeader::HEADER_FORBIDDEN);
        $this->response_message->setMessage('Invalid oauth token credentials.');

        $this->set_output();
        return false;
    }
}