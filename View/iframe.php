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
	echo '<img src="https://www.fqtag.com/pixel.cgi?org=2upravadave3hajasudr&p=TML_'.$registry->imp['placement_id'].'&a='.$registry->imp['publisher_id'].'&cmp=TML_'.$registry->tag['id'].'&fmt=banner&rt=displayImg&pfm=Platform&sl=1&fq=1" width="1" height="1" border="0" />';
}

?>
</body>
</html>