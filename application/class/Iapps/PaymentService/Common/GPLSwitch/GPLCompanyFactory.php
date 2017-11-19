<?php

namespace Iapps\PaymentService\Common\GPLSwitch;

/*
* This Factory will build GPLCompany object by getting credential from core config
*/
use Iapps\PaymentService\Common\CoreConfigDataServiceFactory;

class GPLCompanyFactory{

    protected static $_companyObj;

    public static function build()
    {
        if( self::$_companyObj == NULL )
        {
            $core_config = CoreConfigDataServiceFactory::build();

            if( $userId = $core_config->getConfig('gpl_switch_userid') AND
                $password = $core_config->getConfig('gpl_switch_userkey') AND
                $corporateId = $core_config->getConfig('gpl_switch_corporate_id') AND
                $branch_code = $core_config->getConfig('gpl_switch_branch_code') )
            {
                self::$_companyObj = new GPLCompany();
                self::$_companyObj->setUserName($userId);
                self::$_companyObj->setPassword($password);
                self::$_companyObj->setCorporateId($corporateId);
                self::$_companyObj->setBranchCode($branch_code);
            }
            else
                throw new \Exception("GPL Config is not setup! Aborting...", 1);
        }

        return self::$_companyObj;
    }
}