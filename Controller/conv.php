<?php

	namespace Nigma2\Ad\Controller;

	use Aff\Framework,
		Nigma2\Ad\Model,
		Nigma2\Config,
		Nigma2\Ad\Core;


	class conv extends Core\ControllerAbstract
	{

		public function __construct ( Framework\Registry $registry )
		{
			parent::__construct( $registry );
		}


		public function route ( )
        {
        	$convs= new Model\Convs(
        		$this->_registry,
        		new Framework\Database\Redis\Predis( 'tcp://'.Config\Ad::REDIS_CONFIG.':6379' )
        	);

        	$clickId = $this->_registry->httpRequest->getPathElement(1);
        	$convs->log( $clickId );

            $this->render( 'conv' );
        }

	}

?>