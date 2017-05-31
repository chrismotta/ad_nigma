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


		public function render ( $tag_id, $tag_type = null )
		{
			if ( Config\Ad::DEBUG_CACHE )
				$this->_cache->incrementMapField( 'adstats', 'requests' );

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

			$ips = \explode( ',', $ip );
			$ip = $ips[0];

			if ( !$userAgent || !$ip || !\filter_var($ip, \FILTER_VALIDATE_IP) )
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

			if ( $placementId )
			{
				$placement = $this->_cache->getMap( 'placement:'.$placementId );
			}
			else
			{
				$placement = null;
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
				$tag,
				$placement, 
				$tag_id,
				$placementId
			);


			//-------------------------------------
			// RENDER
			//-------------------------------------

			$tag['id'] = $tag_id;

			$this->_render( 
				$tag, 
				$tag_type, 
				$this->_registry->httpRequest->getParam('width'),
				$this->_registry->httpRequest->getParam('height'),
				$placementId,
				$publisherId
			);

			// Tell controller process completed successfully
			$this->_registry->status = 200;
			return true;
		}


		private function _render( 
			array $tag, 
			$tag_type, 
			$width = null,
			$height = null,
			$placementId = null, 
			$publisherId = null 
		)
		{
			switch ( $tag_type )
			{
				case 'js':
					$this->_registry->view   	  = 'js';
					$this->_registry->tag    	  = $tag;
					$this->_registry->width  	  = $width;
					$this->_registry->height 	  = $height;
					$this->_registry->placementId = $placementId;
					$this->_registry->publisherId = $publisherId;
				break;
				default:
					$this->_registry->view = 'iframe';
					$this->_registry->tag  = $tag;
					$this->_registry->code = $this->_replaceMacros( 
						$tag['code'], 
						[
							'{pubid}' => $publisherId
						] 
					);				
				break;
			}
		}


		private function _log ( 
			$sessionHash, 
			$timestamp, 
			$ip, 
			$userAgent,
			array $tag,
			array $placement = null,
			$tagId,
			$placementId,
			$publisherId = null
		)
		{
			$sessionImpCount = $this->_cache->getMapField( 'log:'.$sessionHash, 'imps' );

			// if session log exists, increment. Otherwise write new one.
			if ( $sessionImpCount && $sessionImpCount >= 0 )
			{	
				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'adstats', 'repeated_imps' );					
				// if tag is open or imp count is under frequency cap, calculate cost and revenue
				if ( !$tag['frequency_cap'] || $tag['frequency_cap']=='' || $sessionImpCount < $tag['frequency_cap'] )
				{
					if ( Config\Ad::DEBUG_CACHE )
						$this->_cache->incrementMapField( 'adstats', 'under_cap' );

					// detections
					$ua = $this->_getDeviceData( $userAgent, $timestamp );

					$this->_geolocation->detect( $ip );

					if ( Config\Ad::DEBUG_CACHE )
						$this->_cache->incrementMapField( 'adstats', 'geodetections' );				

					// calculate cost and revenue
					if ( $this->_matchTargeting( 
						$tag, 
						$this->_geolocation->getConnectionType(), 
						$this->_geolocation->getCountryCode(), 
						$ua['os'] 
					))
					{							
						$this->_cache->incrementMapField( 'log:'.$sessionHash, 'cost', $placement['payout']/1000 );
						$this->_cache->incrementMapField( 'log:'.$sessionHash, 'revenue', $tag['payout']/1000 );						
					}
				}

				$this->_cache->addToSortedSet( 'sessionhashes', $timestamp, $sessionHash );
				$this->_cache->removeFromSortedSet( 'loadedlogs', $sessionHash );

				$this->_cache->incrementMapField( 'log:'.$sessionHash, 'imps' );

				if ( Config\Ad::DEBUG_HTML )
					echo '<!-- incremented log -->';
			}
			else
			{
				// save log index into a set in order to know all logs from ETL script
				$this->_cache->addToSortedSet( 'sessionhashes', $timestamp, $sessionHash );

				// detections
				$ua = $this->_getDeviceData( $userAgent, $timestamp );

				$this->_geolocation->detect( $ip );

				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'adstats', 'geodetections' );				

				// calculate cost and revenue
				if ( $this->_matchTargeting( 
					$tag, 
					$this->_geolocation->getConnectionType(), 
					$this->_geolocation->getCountryCode(), 
					$ua['os'] 
				))
				{					
					$cost    = $placement['payout']/1000;	
					$revenue = $tag['payout']/1000;
				}
				else
				{
					$cost 	 = 0;
					$revenue = 0;
				}

				// write log
				$this->_cache->setMap( 'log:'.$sessionHash, [
					'tag_id'		  => $tagId, 
					'placement_id'	  => $placementId, 
					'publisher_id'	  => $publisherId,
					'imp_time'        => $timestamp, 
					'ip'	          => $ip, 
					'country'         => $this->_geolocation->getCountryCode(), 
					'connection_type' => $this->_geolocation->getConnectionType(), 
					'carrier'		  => $this->_geolocation->getMobileCarrier(),
					'user_agent'	  => $ua['ua'],
					'os' 			  => $ua['os'], 
					'os_version'	  => $ua['os_version'], 
					'device'		  => $ua['device'], 
					'device_model'    => $ua['device_model'], 
					'device_brand'	  => $ua['device_brand'], 
					'browser'		  => $ua['browser'], 
					'browser_version' => $ua['browser_version'], 
					'imps'			  => 1, 	
					'revenue'		  => $revenue,			 
					'cost'			  => $cost
				]);

				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'adstats', 'under_cap' );	

				if ( Config\Ad::DEBUG_HTML )
					echo '<!-- new log -->';					
			}
		}


		private function _replaceMacros ( $code, array $macros = [] )
		{
			return \str_replace( \array_keys( $macros ), \array_values( $macros ), $code );
		}


		private function _matchTargeting ( array $tag, $connection_type, $country, $os )
		{
			if ( 
				$tag['connection_type'] 
				&& $tag['connection_type'] != $connection_type 
				&& $tag['connection_type'] != '-' 
				&& $tag['connection_type'] != ''
			)
			{
				return false;
			}

			if ( Config\Ad::DEBUG_CACHE )
				$this->_cache->incrementMapField( 'adstats', 'conn_type_matches' );			


			if ( 
				$tag['country']
				&& $tag['country'] != $country
				&& $tag['country'] != '-'
				&& $tag['country'] != ''
			)
			{
				return false;			
			}


			if ( Config\Ad::DEBUG_CACHE )
				$this->_cache->incrementMapField( 'adstats', 'country_matches' );

			if ( 
				$tag['os'] 
				&& $tag['os'] != $os 
				&& $tag['os'] != '-'
				&& $tag['os'] != ''
			)
			{
				return false;
			}

			if ( Config\Ad::DEBUG_CACHE )
				$this->_cache->incrementMapField( 'adstats', 'os_matches' );

			return true;
		}


		private function _getDeviceData( $ua, $timestamp )
		{
			$uaHash = md5($ua);
			$data   = $this->_cache->getMap( 'ua:'.$uaHash );

			// if devie data is not in cache, use device detection
			if ( !$data )
			{
				$this->_deviceDetection->detect( $ua );

				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'adstats', 'devicedetections' );				

				if ( Config\Ad::DEBUG_HTML )
					echo '<!-- using device detector: yes -->';

				$data =  [
					'ua'			  => $ua,
					'os' 			  => $this->_deviceDetection->getOs(),
					'os_version'	  => $this->_deviceDetection->getOsVersion(), 
					'device'		  => $this->_deviceDetection->getType(), 
					'device_model'    => $this->_deviceDetection->getModel(), 
					'device_brand'	  => $this->_deviceDetection->getBrand(), 
					'browser'		  => $this->_deviceDetection->getBrowser(), 
					'browser_version' => $this->_deviceDetection->getBrowserVersion() 
				];

				$this->_cache->setMap( 'ua:'.$uaHash, $data );

				// add user agent identifier to a set in order to be found by ETL
				$this->_cache->addToSortedSet( 'uas', $timestamp, $uaHash );				
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
