<?php

	namespace Nigma2\Ad\Model;

	use Aff\Framework,
		Nigma2\Config;


	class Ad extends Framework\ModelAbstract
	{

		private $_deviceDetection;
		private $_geolocation;
		private $_cache;
		private $_fraudDetection;


		public function __construct ( 
			Framework\Registry $registry,
			Framework\AdServing\FraudDetectionInterface $fraudDetection,			
			Framework\Database\KeyValueInterface $cache,
			Framework\Device\DetectionInterface $deviceDetection,
			Framework\TCP\Geolocation\SourceInterface $geolocation
		)
		{
			parent::__construct( $registry );

			$this->_deviceDetection 	= $deviceDetection;
			$this->_geolocation     	= $geolocation;
			$this->_cache           	= $cache;
			$this->_fraudDetection		= $fraudDetection;
		}


		public function render ( $tag_id )
		{
			if ( Config\Ad::DEBUG_CACHE )
				$this->_cache->incrementMapField( 'addebug', 'requests' );

			$userAgent   = $this->_registry->httpRequest->getUserAgent();
			$sessionId   = $this->_registry->httpRequest->getParam('session_id');
			$placementId = $this->_registry->httpRequest->getParam('pid');
			$publisherId = $this->_registry->httpRequest->getParam('pubid');
			$timestamp   = $this->_registry->httpRequest->getTimestamp();

			//-------------------------------------
			// GET & VALIDATE USER DATA
			//-------------------------------------

			// check if load balancer exists. If exists get original ip from X-Forwarded-For header
			$ip = $this->_registry->httpRequest->getHeader('X-Forwarded-For');
			if ( !$ip )
				$ip = $this->_registry->httpRequest->getSourceIp();

			if ( !$userAgent || !$ip )
			{
				$this->_createWarning( 'Bad request', 'M000000A', 400 );
				return false;
			}


			//-------------------------------------
			// MATCH TAG AND PLACEMENT
			//-------------------------------------
			if ( !$tag_id )
			{
				$this->_createWarning( 'Tag not found', 'M000001A', 404 );
				return false;
			}

			$tag = $this->_cache->getMap( 'tag:'.$tag_id );

			if ( !$tag )
			{
				$this->_createWarning( 'Tag not found', 'M000002A', 404 );
				return false;				
			}			

			if ( !$placementId )
			{
				$this->_createWarning( 'Placement not found', 'M000003A', 404 );
				return false;
			}

			$placement = $this->_cache->getMap( 'placement:'.$placementId );

			if ( !$placement )
			{
				$this->_createWarning( 'Placement not found', 'M000004A', 404 );
				return false;				
			}

			if ( Config\Ad::DEBUG_HTML )
			{
				echo '<!-- ip: '.$ip.' -->';
				echo '<!-- user agent: '.$userAgent.' -->';					
			}

			//-------------------------------------
			// CALCULATE SESSION HASH
			//-------------------------------------

			// check if sessionId comes as request parameter and use it to calculate sessionHash. Otherwise use ip + userAgent
			if ( $sessionId )
			{
				$sessionHash = \md5( 
					\date( 'Y-m-d', $timestamp ) . 
					$tag_id . 
					$placementId . 
					$sessionId 
				);
			}
			else
			{
				$sessionHash = \md5( 
					\date( 'Y-m-d', $timestamp ) .
					$tag_id .
					$placementId . 
					$ip . 
					$userAgent								
				);

				/*
				$sessionHash = \md5(rand());
				*/
			}			

			//-------------------------------------
			// LOG
			//-------------------------------------
			$this->_log(
				$sessionHash, 
				$timestamp, 
				$ip, 
				$userAgent,
				$placement, 
				$tag_id,
				$placementId
			);


			// match campaign targeting. If not, skip retargeting
			if ( $this->_matchCampaignTargeting( $cluster, $device ) )
			{
				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'addebug', 'target_matches' );

				if ( Config\Ad::DEBUG_HTML )
					echo '<!-- matched campaign targeting -->';
			}	


			//-------------------------------------
			// RENDER
			//-------------------------------------

			$this->_registry->$tag = $tag;
			$this->_registry->code = $this->_replaceMacros( 
				$tag['code'], 
				[
					'{pubid}' => $publisherId
				] 
			);

			// pass sid for testing
			//$this->_registry->sid = $sessionHash;
			//echo '<!-- session_hash: '.$sessionHash.' -->';
			// Tell controller process completed successfully
			$this->_registry->status = 200;
			return true;
		}


		private function _log ( 
			$sessionHash, 
			$timestamp, 
			$ip, 
			$userAgent,
			array $placement, 
			$tagId,
			$placementId
		)
		{
			$sessionImpCount = $this->_cache->getMapField( 'log:'.$sessionHash, 'imps' );

			// if session log exists, increment. Otherwise write new one.
			if ( $sessionImpCount >= 0 )
			{	
				// if imp count is under frequency cap, add cost
				if ( $sessionImpCount < $placement['frequency_cap'] )
				{
					switch ( $placement['model'] )
					{
						case 'CPM':
							$this->_cache->incrementMapField( 'log:'.$sessionHash, 'cost', $placement['payout']/1000 );
						break;
					}
				}

				$this->_cache->addToSortedSet( 'sessionhashes', $timestamp, $sessionHash );
				$this->_cache->incrementMapField( 'log:'.$sessionHash, 'imps' );
			
				if ( Config\Ad::DEBUG_HTML )
					echo '<!-- incremented log -->';
			}
			else
			{
				// calculate cost
				switch ( $placement['model'] )
				{
					case 'CPM':
						$cost = $placement['payout']/1000;
					break;
					default:
						$cost = 0;
					break;
				}

				// save log index into a set in order to know all logs from ETL script
				$this->_cache->addToSortedSet( 'sessionhashes', $timestamp, $sessionHash );

				// detections
				$device = $this->_getDeviceData( $userAgent );

				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'addebug', 'geodetections' );

				$this->_geolocation->detect( $ip );

				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'addebug', 'geodetections' );				

				// write log
				$this->_cache->setMap( 'log:'.$sessionHash, [
					'tag_id'		  => $tagId, 
					'placement_id'	  => $placementId, 
					'imp_time'        => $timestamp, 
					'ip'	          => $ip, 
					'country'         => $this->_geolocation->getCountryCode(), 
					'connection_type' => $this->_geolocation->getConnectionType(), 
					'carrier'		  => $this->_geolocation->getMobileCarrier(), 
					'os'			  => $device['os'], 
					'os_version'	  => $device['os_version'], 
					'device'		  => $device['device'], 
					'device_model'    => $device['device_model'], 
					'device_brand'	  => $device['device_brand'], 
					'browser'		  => $device['browser'], 
					'browser_version' => $device['browser_version'], 
					'imps'			  => 1, 				 
					'cost'			  => $cost
				]);	

				if ( Config\Ad::DEBUG_HTML )
					echo '<!-- new log -->';					
			}
		}


		private function _replaceMacros ( $code, array $macros = [] )
		{
			return \str_replace( \array_keys( self::macros() ), \array_values( self::macros() ), $code );
		}


		private function _getDeviceData( $ua )
		{
			$uaHash = md5($ua);
			$data   = $this->_cache->getMap( 'ua:'.$uaHash );

			// if devie data is not in cache, use device detection
			if ( !$data )
			{
				$this->_deviceDetection->detect( $ua );

				if ( Config\Ad::DEBUG_HTML )
					echo '<!-- using device detector: yes -->';

				$data = array(
					'os' 			  => $this->_deviceDetection->getOs(),
					'os_version'	  => $this->_deviceDetection->getOsVersion(), 
					'device'		  => $this->_deviceDetection->getType(), 
					'device_model'    => $this->_deviceDetection->getModel(), 
					'device_brand'	  => $this->_deviceDetection->getBrand(), 
					'browser'		  => $this->_deviceDetection->getBrowser(), 
					'browser_version' => $this->_deviceDetection->getBrowserVersion() 
				);

				$this->_cache->setMap( 'ua:'.$uaHash, $data );

				// add user agent identifier to a set in order to be found by ETL
				$this->_cache->addToSet( 'uas', $uaHash );
			}

			return $data;
		}


		private function _createWarning( $message, $code, $status )
		{
			$this->_registry->message = $message;
			$this->_registry->code    = $code;
			$this->_registry->status  = $status;			
		}

	}

?>
