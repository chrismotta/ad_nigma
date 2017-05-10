<?php

	namespace Aff\Ad\Model;

	use Aff\Framework,
		Aff\Config;


	class Ad extends Framework\ModelAbstract
	{

		private $_deviceDetection;
		private $_geolocation;
		private $_cache;
		private $_campaignSelection;
		private $_fraudDetection;


		public function __construct ( 
			Framework\Registry $registry,
			CampaignSelectionInterface $campaignSelection,
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
			$this->_campaignSelection	= $campaignSelection;
			$this->_fraudDetection		= $fraudDetection;
		}


		public function render ( $placement_id )
		{
			if ( Config\Ad::DEBUG_CACHE )
				$this->_cache->incrementMapField( 'addebug', 'requests' );

			//-------------------------------------
			// GET & VALIDATE USER DATA
			//-------------------------------------
			$userAgent = $this->_registry->httpRequest->getUserAgent();
			$sessionId = $this->_registry->httpRequest->getParam('session_id');
			$timestamp = $this->_registry->httpRequest->getTimestamp();

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
			// MATCH PLACEMENT (placement_id)
			//-------------------------------------
			if ( !$placement_id )
			{
				$this->_createWarning( 'Placement not found', 'M000001A', 404 );
				return false;
			}

			$placement = $this->_cache->getMap( 'placement:'.$placement_id );

			if ( !$placement )
			{
				$this->_createWarning( 'Placement not found', 'M000002A', 404 );
				return false;				
			}

			//-------------------------------------
			// CALCULATE SESSION HASH
			//-------------------------------------

			// check if sessionId comes as request parameter and use it to calculate sessionHash. Otherwise use ip + userAgent
			if ( $sessionId )
			{
				$sessionHash = \md5( 
					\date( 'Y-m-d', $timestamp ) . 
					$placement['cluster_id'] . 
					$placement_id . 
					$sessionId 
				);
			}
			else
			{
				//echo '<!-- ip: '.$ip.' -->';
				//echo '<!-- user agent: '.$userAgent.' -->';
				$sessionHash = \md5( 
					\date( 'Y-m-d', $timestamp ) .
					$placement['cluster_id'] .
					$placement_id . 
					$ip . 
					$userAgent								
				);
				/*
				$sessionHash = \md5(rand());
				*/
			}			


			if (
				$placement['status'] == 'health_check' 
				|| $placement['status'] == 'testing' 
				|| ( $clusterImpCount && $logWasTargetted )
			)
			//-------------------------------------------------------			
			// LOG & SKIP RETARGETING
			//-------------------------------------------------------
			{


			}
			else
			//-------------------------------------------------------				
			// LOG AND DO RETARGETING
			//-------------------------------------------------------
			{
				$device  = $this->_getDeviceData( $userAgent );
				
				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'addebug', 'device_detections' );				

				$this->_geolocation->detect( $ip );

				if ( Config\Ad::DEBUG_CACHE )
					$this->_cache->incrementMapField( 'addebug', 'geodetections' );

				// if sessionhash already exists increment, otherwise create new
				if ( $this->_cache->isInSet( 'sessionhashes', $sessionHash ) )
				{
					if ( Config\Ad::DEBUG_HTML )
						echo '<!-- no cs => increment log -->';

					$this->_incrementLog( $sessionHash, $placement, $clusterImpCount, $timestamp );
				}
				else
				{
					if ( Config\Ad::DEBUG_HTML )
						echo '<!-- no cs => new log -->';

					$device = $this->_getDeviceData( $userAgent );
					$this->_geolocation->detect( $ip );

					$this->_newLog ( $sessionHash, $timestamp, $ip, $placement, $device, $placement_id,  false );
				}


				// match campaign targeting. If not, skip retargeting
				if ( $this->_matchCampaignTargeting( $cluster, $device ) )
				{
					if ( Config\Ad::DEBUG_CACHE )
						$this->_cache->incrementMapField( 'addebug', 'target_matches' );

					if ( Config\Ad::DEBUG_HTML )
						echo '<!-- matched campaign targeting -->';
	
				}	
			}


			//-------------------------------------
			// RENDER
			//-------------------------------------			

			$creativeSize = $placement['size'];
			if ( isset( $cluster ) )
			{
				$this->_registry->creativeUrl = $cluster['static_cp_'.$creativeSize];
				$this->_registry->landingUrl  = $cluster['static_cp_land'];
			}
			else
			{
				$this->_registry->creativeUrl = $this->_cache->getMapField( 'cluster:'.$placement['cluster_id'], 'static_cp_'.$creativeSize );
				$this->_registry->landingUrl  = $this->_cache->getMapField( 'cluster:'.$placement['cluster_id'], 'static_cp_land' );
			}

			// pass sid for testing
			//$this->_registry->sid = $sessionHash;
			//echo '<!-- session_hash: '.$sessionHash.' -->';
			// Tell controller process completed successfully
			$this->_registry->status = 200;
			return true;
		}


		private function _Log ( 
			$sessionHash, 
			$timestamp, 
			$ip, 
			array $placement, 
			array $device, 
			$placementId, 
			$targetted = false
		)
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

			// save cluster log index into a set in order to know all logs from ETL script
			$this->_cache->addToSortedSet( 'sessionhashes', $timestamp, $sessionHash );

			// write cluster log
			$this->_cache->setMap( 'clusterlog:'.$sessionHash, [
				'cluster_id'	  => $placement['cluster_id'], 
				'cluster_name'	  => $placement['cluster_name'],  
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
				'targetted'		  => $targetted, 
				'cost'			  => $cost
			]);
		}


		private function _incrementClusterLog ( $sessionHash, array $placement, $clusterImpCount, $timestamp )
		{
			// if imp count is under frequency cap, add cost
			if ( $clusterImpCount < $placement['frequency_cap'] )
			{
				switch ( $placement['model'] )
				{
					case 'CPM':
						$this->_cache->incrementMapField( 'clusterlog:'.$sessionHash, 'cost', $placement['payout']/1000 );
					break;
				}
			}
			$this->_cache->addToSortedSet( 'clusterlogs', $timestamp, $sessionHash );
			$this->_cache->incrementMapField( 'clusterlog:'.$sessionHash, 'imps' );
		}


		private function _newCampaignLog ( 
			$clickId,
			$sessionHash,
			$campaignId,
			$timestamp
		)
		{
			// save campaign log index into a set in order to know all logs from ETL script
			$this->_cache->addToSortedSet( 'clickids', $timestamp, $clickId );

			// write campaign log
			$this->_cache->setMap( 'campaignlog:'.$clickId, [
				'session_hash'    => $sessionHash, 
				'campaign_id'	  => $campaignId,
				'click_time'      => null
			]);
		}


		private function _matchClusterTargeting ( $cluster, array $deviceData )
		{
			if ( 
				( $cluster['os'] && $cluster['os']!=$deviceData['os'] )
				|| ( $cluster['country'] && $cluster['country'] != $this->_geolocation->getCountryCode() ) 
				|| ( $cluster['connection_type'] && $cluster['connection_type'] != $this->_geolocation->getConnectionType() )
			)
				return false;

			return true;
		}


		private function _getDeviceData( $ua )
		{
			$uaHash = md5($ua);
			$data   = $this->_cache->getMap( 'ua:'.$uaHash );

			// if devie data is not in cache, use device detection
			if ( !$data )
			{
				$this->_deviceDetection->detect( $ua );
				//echo '<!-- using device detector: yes -->';
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
