<?php (defined('BASEPATH')) OR exit('No direct script access allowed');

class Front_Controller extends Base_Controller
{

    public function __construct()
    {
        parent::__construct();
        $this->load->library(array('assets', 'template'));

        Template::set_default_theme('default');
    }

}
