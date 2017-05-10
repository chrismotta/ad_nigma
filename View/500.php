<?php
	
	header( 'Content-Type: text/json;charset=UTF-8' );
	echo json_encode( array ( 
		'warning'	=>  array(
			'message'	=> $registry->message,
			'code'		=> $registry->code
		)
	), \JSON_PRETTY_PRINT );
?>