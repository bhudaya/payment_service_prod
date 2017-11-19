<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\Core\IappsBaseEntityCollection;

class PaymentModeLocationCollection extends IappsBaseEntityCollection{

    public function getByCode($code)
    {
        foreach( $this AS $pm )
        {
            if( $pm instanceof PaymentModeLocation )
            {
                if( $pm->getPaymentCode() == $code )
                    return $pm;
            }
        }

        return false;
    }
}