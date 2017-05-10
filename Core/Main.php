<?php

	namespace Aff\Ad\Core;

	use Aff\Framework,
		Aff\Config;


	class Main extends Framework\ObjectAbstract
	{

		protected $_registry;        
        protected $_controller;


		public function __construct ( )
		{
			parent::__construct( );

			$this->_init();

			if ( Config\Ad::DISABLED )
			{
				$this->render( 'disabled', 503 );
			}
		}		


		public function run ( )
		{
			$this->_controller->route();
           	exit();
		}


		public function render ( $view, $status )
		{
			\http_response_code( $status );

			require_once( '.' . Config\Ad::DIR_SEPARATOR . 'View' . Config\ad::DIR_SEPARATOR . $view . '.php' );

			exit();
		}


		private function _init ( )
		{
            //Packages\PHP\Helper::setIniOption( 'expose_php', 0 );

            $this->_registry = new Framework\Registry();
			$this->_registry->httpRequest = new Framework\TCP\HTTP\Server\Request();

            $this->_setController();
            $this->_setErrorHandling();
		}


        private function _setController ( )
        {
        	if ( $name = $this->_registry->httpRequest->getPathElement(0) )
        	{
	            $class = 'Aff\Ad\Controller\\' . $name;

	            if ( !\class_exists( $class ) )
				{
					$class = 'Aff\Ad\Controller\\' . Config\Ad::DEFAULT_CONTROLLER;
				}
        	}
        	else
        	{
				$class = 'Aff\Ad\Controller\\' . Config\Ad::DEFAULT_CONTROLLER;
        	}

			$this->_controller = new $class( $this->_registry );
        }


		private function _setErrorHandling ( )
		{
			if ( Config\Ad::DEBUG_MODE )
			{
	            \ini_set('display_errors', 1);
	            \ini_set('display_startup_errors', 1);
	            \error_reporting( \E_ALL );			
			}
			else
			{
				\set_exception_handler( array( $this, 'handleException') );		
				\set_error_handler( array( $this, 'handleError' ), \E_ALL );				
			}
		}


		public function handleError ( $num, $str, $file, $line, $context )
		{			
			$this->render ( '500', 500 );
		}


		public function handleException ( \Throwable $e )
		{
			$this->render ( '500', 500 );
		}

	}

?>