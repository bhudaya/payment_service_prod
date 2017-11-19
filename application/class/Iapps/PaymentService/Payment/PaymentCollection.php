<?php

namespace Iapps\PaymentService\Payment;

use Iapps\Common\Core\IappsBaseEntityCollection;

class PaymentCollection extends IappsBaseEntityCollection{

    public function sortByCreatedAt()
    {
        $data = $this->toArray();

        if( $sortedArray = usort($data, array($this, "_sorByCreatedAt") ))
        {
            $sortedCollection = new PaymentCollection();
            foreach($data AS $payment)
            {
                $sortedCollection->addData($payment);
            }

            return $sortedCollection;
        }

        return $this;
    }

    // Define the custom sort function
    private function _sorByCreatedAt($a,$b) {
        if( $a instanceof Payment AND
            $b instanceof Payment )
        {
            return $a->getCreatedAt()->getUnix() < $b->getCreatedAt()->getUnix();
        }

        //remain same order if
        return false;
    }
}