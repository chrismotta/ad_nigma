<?php

	namespace Nigma2\Ad\Controller;

	use Aff\Framework,
		Nigma2\Ad\Model,
		Nigma2\Config,
		Nigma2\Priv,
		Nigma2\Ad\Core;


	class ad extends Core\ControllerAbstract
	{

		public function __construct ( Framework\Registry $registry )
		{
			parent::__construct( $registry );
		}


		public function route ( )
        {
        	$ad = new Model\Ad(
        		$this->_registry,
        		new Framework\AdServing\FraudDetection\Forensiq(
        			new Framework\TCP\HTTP\Client\cURL(),
        			new Framework\TCP\HTTP\Client\Request(),
        			Config\Ad::FORENSIQ_KEY
        		),
        		new Framework\Database\Redis\Predis( 'tcp://'.Config\Ad::REDIS_CONFIG.':6379' ),
        		new Framework\Device\Detection\Piwik(),
        		new Framework\TCP\Geolocation\Source\IP2Location( Config\Ad::IP2LOCATION_BIN )
        	);

        	$placementId = $this->_registry->httpRequest->getPathElement(0);

        	$ad->render( $placementId );

            $this->render( 'ad' );
        }

	}

?>