<?php

	namespace Aff\Ad\Model;

	use Aff\Framework;


	interface CampaignSelectionInterface
	{

		public function run ( array $campaigns_tags = null, array $options = null ); // bool

		/*
			options = [
				'tag_type'	= 'iframe' | 'script' | 'js_raw'
			]
		*/			

		public function getAdCode ( );

	}
	
?>