<?php

namespace Iapps\PaymentService\PaymentMode;

use Iapps\Common\SystemCode\SystemCodeInterface;

class DeliveryTime implements SystemCodeInterface{

    const WITHIN_ONE_HOUR = 'one_hour';
    const SAME_DAY_DELIVERY = 'same_day';
    const NEXT_DAY_DELIVERY = 'next_day';
    const MORE_THAN_ONE_DAY = 'more_than_one_day';

    public static function getSystemGroupCode()
    {
        return 'delivery_time';
    }
}