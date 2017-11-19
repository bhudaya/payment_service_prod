<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\Core\IappsBaseEntityCollection;

class PaymentModeCollection extends IappsBaseEntityCollection{

    public function getByCode($code)
    {
        foreach( $this AS $pm )
        {
            if( $pm instanceof PaymentMode )
            {
                if( $pm->getCode() == $code )
                    return $pm;
            }
        }

        return false;
    }
}