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
		private $_passback;


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
			$this->_passback			= false;
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

			$this->_cache->useDatabase(0);
			$tag = $this->_cache->getMap( 'tag:'.$tag_id );

			if ( !$tag )
			{
				$this->_createWarning( 'Tag not found', 'M000002A', 404 );
				return false;				
			}			

			if ( $placementId )
			{
				$placement   = $this->_cache->getMap( 'placement:'.$placementId );
				
				if ( !$placement )
					$placementId = null;
			}
			else
			{
				$placement = null;
			}

			$this->_cache->useDatabase( $this->_getCurrentDatabase() );

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
				$placementId,
				$publisherId
			);

			//-------------------------------------
			// RENDER
			//-------------------------------------

			$tag['id'] = $tag_id;

			if ( 
				$this->_render( 
					$tag, 
					$tag_type, 
					$publisherId 
				)
			)
			{
				// Tell controller & view process completed successfully
				$this->_registry->status = 200;
				return true;
			}

			$this->_createWarning( 'No creative matched', 'M000003A', 404 );
			return false;
		}


		private function _render( 
			array $tag, 
			$tag_type,
			$publisherId = null 
		)
		{
			$this->_registry->tag  = $tag;

			if ( $this->_passback )
			{
				if ( !$tag['passback_tag'] )
				{
					// when no match and no passback tag returns false and send warning
					return false;
				}	
				else if ( $tag['passback_tag']=='{show_all}' )
				{
					// when no match and no passback tag returns true and sends tag code
					$code = $this->_replaceQueryStringMacros( $tag['code'] );
				}
				else
				{
					$code = $tag['passback_tag'];	
				}			
			}
			else
			{
				$code = $this->_replaceQueryStringMacros( $tag['code'] );
			}

			$this->_registry->code = $this->_replaceMacros( 
				$code,	
				[
					'{pubid}' => $publisherId
				] 
			);

			switch ( $tag_type )
			{
				case 'js':
					$this->_registry->view = 'js';
				break;
				default:
					$this->_registry->view = 'iframe';
				break;
			}

			return true;
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
			$cost 			 = 0.00;
			$revenue		 = 0.00;

			// if session log exists, increment. Otherwise write new one.
			if ( $sessionImpCount && $sessionImpCount >= 0 )
			{	
				$this->_cache->incrementMapField( 'log:'.$sessionHash, 'requests' );

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

					// if placement exists and matches target, calculate cost and revenue
					if ( 
						$this->_matchTargeting( 
							$tag, 
							$this->_geolocation->getConnectionType(), 
							$this->_geolocation->getCountryCode(), 
							$ua['os'],
							$ua['device'],
							$publisherId
						)
					)
					{
						if ( $placement )
						{
							$cost 	 = $placement['payout']/1000;				
							$revenue = $tag['payout']/1000;

							$this->_cache->incrementMapField( 'log:'.$sessionHash, 'cost', $cost );
							$this->_cache->incrementMapField( 'log:'.$sessionHash, 'revenue', $revenue );
						}			

						$this->_cache->incrementMapField( 'log:'.$sessionHash, 'imps' );
					}
					else
					{
						$this->_passback = true;
					}
				}
				else
				{
					$this->_passback = true;
				}

				$this->_cache->addToSortedSet( 'sessionhashes', $timestamp, $sessionHash );

				$this->_saveCounters( $tagId, $placementId, \date( 'Ymd', $timestamp ), false, $cost, $revenue, $timestamp );	

				if ( Config\Ad::DEBUG_HTML )
					echo '<!-- incremented log -->';
			}
			else
			{
				$imps = 1;

				// save log index into a set in order to know all logs from ETL script
				$this->_cache->addToSortedSet( 'sessionhashes', $timestamp, $sessionHash );

				// detections
				$ua = $this->_getDeviceData( $userAgent, $timestamp );

				$this->_geolocation->detect( $ip );

				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'adstats', 'geodetections' );				

				// if placement exists and matches target, calculate cost and revenue
				if ( 
					$this->_matchTargeting( 
						$tag, 
						$tagId,
						$this->_geolocation->getConnectionType(), 
						$this->_geolocation->getCountryCode(), 
						$ua['os'],
						$ua['device']
					)
				)
				{	
					if ( $placement )				
					{
						$cost    = $placement['payout']/1000;	
						$revenue = $tag['payout']/1000;
					}
					else
					{
						$cost 	 = 0.00;
						$revenue = 0.00;						
					}
				}
				else
				{
					$this->_passback = true;
					$imps 	 = 0;

					$cost 	 = 0.00;
					$revenue = 0.00;
				}

				// write log
				$this->_cache->setMap( 'log:'.$sessionHash, [
					'requests'		  => 1,
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
					'imps'			  => $imps, 	
					'revenue'		  => $revenue,			 
					'cost'			  => $cost
				]);

				$this->_saveCounters( $tagId, $placementId, \date( 'Ymd', $timestamp ), true, $cost, $revenue, $timestamp );

				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'adstats', 'under_cap' );	

				if ( Config\Ad::DEBUG_HTML )
					echo '<!-- new log -->';					
			}
		}


		private function _saveCounters ( 
			$tag_id, 
			$placement_id, 
			$date, 
			$first, 
			$cost = 0.00, 
			$revenue = 0.00,
			$timestamp
		)
		{
			if ( $this->_passback )
			{
				if ( $placement_id )
				{
					if ( $first )
					{
						$this->_cache->setMapField( 'req:p:'.$placement_id.':'.$date, 'unique_imps', 0 );
					}

					$this->_cache->incrementMapField( 'req:p:'.$placement_id.':'.$date, 'requests' );
					$this->_cache->incrementMapField( 'req:p:'.$placement_id.':'.$date, 'imps', 0 );
					$this->_cache->incrementMapField( 'req:p:'.$placement_id.':'.$date, 'cost', 0.00 );
					$this->_cache->incrementMapField( 'req:p:'.$placement_id.':'.$date, 'revenue', 0.00 );
				}

				if ( $first )
				{
					$this->_cache->setMapField( 'req:t:'.$tag_id.':'.$date, 'unique_imps', 0 );
				}

				$this->_cache->incrementMapField( 'req:t:'.$tag_id.':'.$date, 'requests' );
				$this->_cache->incrementMapField( 'req:t:'.$tag_id.':'.$date, 'imps', 0 );
				$this->_cache->incrementMapField( 'req:t:'.$tag_id.':'.$date, 'cost', 0.00 );
				$this->_cache->incrementMapField( 'req:t:'.$tag_id.':'.$date, 'revenue', 0.00 );				
			}
			else
			{
				if ( $placement_id )
				{
					if ( $first )
					{
						$this->_cache->setMapField( 'req:p:'.$placement_id.':'.$date, 'unique_imps', 1 );
					}

					$this->_cache->incrementMapField( 'req:p:'.$placement_id.':'.$date, 'requests' );
					$this->_cache->incrementMapField( 'req:p:'.$placement_id.':'.$date, 'imps' );
					$this->_cache->incrementMapField( 'req:p:'.$placement_id.':'.$date, 'cost', $cost );
					$this->_cache->incrementMapField( 'req:p:'.$placement_id.':'.$date, 'revenue', $revenue );
				}

				if ( $first )
				{
					$this->_cache->setMapField( 'req:t:'.$tag_id.':'.$date, 'unique_imps', 1 );
				}

				$this->_cache->incrementMapField( 'req:t:'.$tag_id.':'.$date, 'requests' );
				$this->_cache->incrementMapField( 'req:t:'.$tag_id.':'.$date, 'imps' );
				$this->_cache->incrementMapField( 'req:t:'.$tag_id.':'.$date, 'cost', $cost );
				$this->_cache->incrementMapField( 'req:t:'.$tag_id.':'.$date, 'revenue', $revenue );
			}

			$this->_cache->addToSortedSet( 'tags:'.$date, $timestamp, $tag_id );
			$this->_cache->addToSet( 'dates', \date('Y-m-d', $timestamp) );
		}


		private function _replaceMacros ( $code, array $macros = [] )
		{
			return \str_replace( \array_keys( $macros ), \array_values( $macros ), $code );
		}


		private function _matchTargeting ( array $tag, $tag_id, $connection_type, $country, $os, $device, $publisherId = null )
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

			/*
			if (
				$publisherId
				&& $this->_cache->isInSet( 'pubidblacklist:'.$tag['id'], $publisherId ) 
			)
			{
				return false;
			}			
			*/
		
			if ( Config\Ad::DEBUG_CACHE )
				$this->_cache->incrementMapField( 'adstats', 'os_matches' );

			if ( $tag['device'] )
			{
				$device = \strtolower($device);

				switch ( $tag['device'] )
				{
					case 'mobile+tablet':
						if ( $device!='phablet' && $device!='smartphone' && $device!='tablet' )
							return false;
					break;
					case 'mobile':
						if ( $device!='phablet' && $device!='smartphone' )
							return false;
					break;
					default:
						if ( 
							$tag['device'] != $device 
							&& $tag['device'] != '-'
							&& $tag['device'] != ''							
						)
							return false;
					break;
				}
			}

			if ( Config\Ad::DEBUG_CACHE )
				$this->_cache->incrementMapField( 'adstats', 'device_matches' );			

			return true;
		}


		private function _getDeviceData( $ua, $timestamp )
		{
			$this->_cache->useDatabase( 0 );

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

			$this->_cache->useDatabase( $this->_getCurrentDatabase() );

			return $data;
		}


		private function _replaceQueryStringMacros ( $tag_code )
		{
			foreach ( $this->_registry->httpRequest->getData() AS $param => $value )
			{
				if ( \preg_match( '/(QS)[a-zA-Z0-9_]+/', $param ) )
				{
					$tag_code = \preg_replace( '/({'.$param.'})/', $value, $tag_code  );
				}
			}

			return $tag_code;	
		}


		private function _createWarning( $message, $code, $status )
		{
			$this->_registry->message = $message;
			$this->_registry->code    = $code;
			$this->_registry->status  = $status;			
		}


		private function _getCurrentDatabase ( )
		{
			return \floor(($this->_registry->httpRequest->getTimestamp()/60/60/24))%2+1;
		}

	}

?>
