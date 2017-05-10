<?php

	namespace Aff\Ad\Core;

	use Aff\Framework;


	abstract class ControllerAbstract extends Framework\ControllerAbstract
	{

        protected $_registry;


		public function __construct ( Framework\Registry $registry )
		{
			parent::__construct( $registry );

            $this->_registry = $registry;
		}


		public function render ( $view )
		{
            $registry = $this->_registry;

            switch ( $registry->status )
            {
                case 200: // OK
                    http_response_code(200);
                    require_once( './View/' . $view . '.php' );
                break;
                case 400: // Bad Request (validation error)
                    http_response_code(400);
                    require_once( './View/400.php' );
                break;
                case 500: // Internal server error (exceptions)
                    http_response_code(500);
                    require_once( './View/500.php' );
                break;                
                default: // Not Found (everything else)                         
                    http_response_code(404);
                    require_once( './View/404.php' );
                break;
            }
		}

	}

?>