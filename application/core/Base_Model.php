<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

use Iapps\Common\Core\IappsDateTime;
use Iapps\Common\Core\PaginatedResult;

class Base_Model extends CI_Model
{
    protected $frCreatedAt;
    protected $toCreatedAt;

    function __construct()
    {
        parent::__construct();
		date_default_timezone_set('UTC');

        $this->load->database('iafb_payment');

        $this->frCreatedAt = new IappsDateTime();
        $this->toCreatedAt = new IappsDateTime();
	}

    public function TransStart()
    {
        $this->db->trans_start();
    }

    public function TransRollback()
    {
        $this->db->trans_rollback();
    }

    public function TransComplete()
    {
        $this->db->trans_complete();
    }

    public function mapCollection(array $data, $collection, $total)
    {
        foreach($data AS $info)
        {
            $entity = $this->map($info);
            $collection->addData($entity);
        }

        if( $collection->count() > 0 )
        {
            $object = new PaginatedResult();
            $object->result = $collection;
            $object->total = $total;
            return $object;
        }

        return false;
    }

    public function setFromCreatedAt(IappsDateTime $dt)
    {
        $this->frCreatedAt = $dt;
        return $this;
    }

    public function getFromCreatedAt()
    {
        return $this->frCreatedAt;
    }

    public function setToCreatedAt(IappsDateTime $dt)
    {
        $this->toCreatedAt = $dt;
        return $this;
    }

    public function getToCreatedAt()
    {
        return $this->toCreatedAt;
    }
}
