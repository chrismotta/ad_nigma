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
            //$ip2Location = new Framework\TCP\Geolocation\Source\IP2Location( Config\Ad::IP2LOCATION_BIN );
            
            $maxmind = new Framework\TCP\Geolocation\Source\Maxmind([
                'path_conn_type' => Config\Ad::MAXMIND_DB_CONN_TYPE, 
                'path_country'   => Config\Ad::MAXMIND_DB_COUNTRY, 
                'path_isp'       => Config\Ad::MAXMIND_DB_ISP 
            ]);

        	$ad = new Model\Ad(
        		$this->_registry,
        		new Framework\AdServing\FraudDetection\Forensiq(
        			new Framework\TCP\HTTP\Client\cURL(),
        			new Framework\TCP\HTTP\Client\Request(),
        			Config\Ad::FORENSIQ_KEY
        		),
        		new Framework\Database\Redis\Predis( 'tcp://'.Config\Ad::REDIS_CONFIG.':6379' ),
        		new Framework\Device\Detection\Piwik(),
        	    $maxmind	
        	);

        	$path0 = $this->_registry->httpRequest->getPathElement(0);

            switch ( $path0 )
            {
                case 'js':
                    $tagType = 'js';
                    $tagId   = $this->_registry->httpRequest->getPathElement(1);
                break;
                case 'js2':
                    $tagType = 'js2';
                    $tagId   = $this->_registry->httpRequest->getPathElement(1);
                break;                
                default:
                    $tagType = null;
                    $tagId   = $path0;
                break;
            }

        	$ad->render( $tagId, $tagType );

            $this->render( $this->_registry->view );
        }

	}

?>