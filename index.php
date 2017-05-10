<?php 
	
    namespace Aff\Ad;

    // DEBUG
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting( E_ALL );


    // COMPOSER AUTOLOADER
	require_once( '..'.\DIRECTORY_SEPARATOR.'vendor'.\DIRECTORY_SEPARATOR.'autoload.php');


    // PROJECT AUTOLOADER
	spl_autoload_register( function ( $className ) {
		$fileName = '.' . DIRECTORY_SEPARATOR . str_replace( 'Aff\\Ad\\', '', $className ). '.php';		
		$fileName = str_replace( '\\', DIRECTORY_SEPARATOR, $fileName );

		if ( is_readable($fileName)  )
		{
			require_once( $fileName );	
		}		
	});	


	// FRAMEWORK AUTOLOADER
	spl_autoload_register( function ( $className ) {

		$fileName = '..' . DIRECTORY_SEPARATOR . str_replace( 'Aff\\Framework\\', 'framework\\', $className ). '.php';		
		$fileName = str_replace( '\\', DIRECTORY_SEPARATOR, $fileName );

		if ( is_readable($fileName)  )
		{
			require_once( $fileName );	
		}	

	});	


	// PRIVATE AUTOLOADER
	spl_autoload_register( function ( $className ) {

		$fileName = '..' . DIRECTORY_SEPARATOR . str_replace( 'Aff\\Priv\\', 'priv\\', $className ). '.php';		
		$fileName = str_replace( '\\', DIRECTORY_SEPARATOR, $fileName );

		if ( is_readable($fileName)  )
		{
			require_once( $fileName );	
		}	

	});	


	// CONFIG AUTOLOADER
	spl_autoload_register( function ( $className ) {

		$fileName = '..' . DIRECTORY_SEPARATOR . str_replace( 'Aff\\Config\\', 'config\\', $className ). '.php';		
		$fileName = str_replace( '\\', DIRECTORY_SEPARATOR, $fileName );
		
		if ( is_readable($fileName)  )
		{
			require_once( $fileName );	
		}
	});		


	// RUN
	$main = new Core\Main();
	$main->run();


?>