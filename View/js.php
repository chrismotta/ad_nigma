<?php

	if ( $registry->httpRequest->isHttps() ) 
		$protocol = 'https';
	else 
		$protocol = 'http';


	if( 
		$registry->placementId 
		&& $registry->width 
		&& $registry->height 
	)
	{
		echo 'document.write(\'<iframe src="'.$protocol.'://req.bidbox.co/'.$registry->tag['id'].'?pid='.$registry->placementId.'&pubid='.$registry->publisherId.'" width="'.$registry->width.'" height="'.$registry->height.'" frameborder="0" scrolling="no" ></iframe>\');';

	}else{

		echo 'document.write(\'ERROR: Ad not setted properly\');';
	}

?>