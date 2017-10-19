<!DOCTYPE html>
<html>
<head></head>
<body style="margin:0;padding:0">
<?php 

echo ($registry->code);

if( $registry->tag['analyze'] ){
	// forensiq pixel
	// cmp = Campaign
	// p = Source
	// a = SubSource
	// c1 = Device ID

	if ( $registry->qs_deviceid != '' )
		$deviceId = '&c1='.$registry->qs_deviceid;
	else
		$deviceId = '';

	if ( $registry->publisher_id != '' )
		$publisherId = '&a='.$registry->publisher_id;
	else
		$publisherId = '';

	echo '<img src="https://www.fqtag.com/pixel.cgi?org=2upravadave3hajasudr&p=TML_'.$registry->placement_id.$publisherId.$deviceId.'&cmp=TML_'.$registry->tag['id'].'&fmt=banner&rt=displayImg&pfm=Platform&sl=1&fq=1" width="1" height="1" border="0" />';
}

?>
</body>
</html>