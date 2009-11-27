<?php
/*******************************************************************************
** Basic Analysis and Security Engine (BASE)
** Copyright (C) 2004 BASE Project Team
** Copyright (C) 2000 Carnegie Mellon University
**
** (see the file 'base_main.php' for license details)
**
** Project Leads: Kevin Johnson <kjohnson@secureideas.net>
** Built upon work by Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
**
** Purpose: Binary download of payload and pcap format packet download
**
** Input GET/POST variables
**   - sid
**   - cid
**   - download: 1 - binary download of payload. 
**               2 - download pcap format based packet (for FLoP extended db)
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net>
**
********************************************************************************
*/

include ("base_conf.php");
include ("$BASE_path/includes/base_constants.inc.php");
include ("$BASE_path/includes/base_include.inc.php");

   // Check role out and redirect if needed -- Kevin
  $roleneeded = 10000;
  $BUser = new BaseUser();
  if (($BUser->hasRole($roleneeded) == 0) && ($Use_Auth_System == 1))
  {
    header("Location: ". $BASE_urlpath . "/index.php");
  }

$cid = ImportHTTPVar("cid", VAR_DIGIT);
$sid = ImportHTTPVar("sid", VAR_DIGIT);
$download = ImportHTTPVar("download", VAR_DIGIT);

if ($download == 1){

	/* Connect to the Alert database */
	$db = NewBASEDBConnection($DBlib_path, $DBtype);
	$db->baseDBConnect($db_connect_method,
	$alert_dbname, $alert_host, $alert_port, $alert_user, $alert_password);

	/* Get the Payload from the database: */
	$sql2 = "SELECT data_payload FROM data WHERE sid='".$sid."' AND cid='".$cid."'";
	$result2 = $db->baseExecute($sql2);
	$myrow2 = $result2->baseFetchRow();
	$result2->baseFreeRows();

	/* get encoding information for payload */
	/* 0 == hex, 1 == base64, 2 == ascii;	*/
	$sql3 = 'SELECT encoding FROM sensor WHERE sid='.$sid;
	$result3 = $db->baseExecute($sql3);
	$myrow3 = $result3->baseFetchRow();
	$result3->baseFreeRows();

	if ( $myrow2[0] ){
		/****** database contains hexadecimal *******************/
		if ($myrow3[0] == 0){
			header ('HTTP/1.0 200');
			header ("Content-type: application/download");
			header ("Content-Disposition: attachment; filename=payload_".$sid."-".$cid.".bin");
			header ("Content-Transfer-Encoding: binary");
			ob_start();
			$payload = str_replace("\n", "", $myrow2[0]);
			$len = strlen($payload);
			$half = ($len / 2);
			header ("Content-Length: $half");
			$counter = 0;
			for ($i = 0; $i < ( $len + 32 ); $i += 2){
				$counter++;
				if ($counter > ($len / 2)){
					break;
				}
				$byte_hex_representation = ($payload[$i].$payload[$i+1]);
				echo chr(hexdec($byte_hex_representation));
			}
			ob_end_flush();	
			// nothing should come AFTER ob_end_flush().

		/********database contains base64 *******************/
		} elseif ($myrow3[0] == 1){
			header ('HTTP/1.0 200');
			header ("Content-type: application/octet-stream");
			header ("Content-Disposition: attachment; filename=payload".$sid."-".$cid.".bin");
			header ("Content-Transfer-Encoding: binary");
			ob_start();
			$pre_payload = str_replace("\n", "", $myrow2[0]);
			$payload = base64_decode($pre_payload);
			$len = strlen($payload);
			header ("Content-Length: $len");
			$counter = 0;
			for ($i = 0; $i < ($len + 16); $i++){
				$counter++;
				if ($counter > $len) {
					break;
				}	
				$byte = $payload[$i];
				print $byte;
			}
			ob_end_flush();	
			// nothing should come AFTER ob_end_flush().
		
		/********** database contains ASCII ***************/
		} elseif ($myrow3[0] == 2){
			header ('HTTP/1.0 200');
			header ('Content-Type: text/html');
			print "<h1> File not found:</h1>";

			print "<br>Output of binary data with storage method ASCII<br>";
			print "is NOT supported, because this method looses data<br>";
			print "So you can not definitely rebuild the binary,<br>";
			print "as one ASCII character may represent different<br>";
			print "binary values. Think of the dot, for example.<br>";

			print "<br><br><hr><i>Generated by base_payload.php</i><br>";
		} else {
			header ('HTTP/1.0 200');
			header ('Content-Type: text/html');
			print "<h1> File not found:</h1>";
			print "<br>Encoding type not implemented in base_payload.php.";
			print "<br><br><hr><i>Generated by base_payload.php</i><br>";
		}
	} else {
		header ('HTTP/1.0 200');
		header ('Content-Type: text/html');
		print "<h1> File not found:</h1>";
		print "<br>No payload data found, that could be downloaded or stored.";
		print "<br><br><hr><i>Generated by base_payload.php</i><br>";
	}

} else if ($download == 2) {
	/*
	 * If we have FLoP extended database schema then we can rebuild alert
	 * in pcap format which can be used to analyze it via tcpdump or
	 * ethereal to use their protocol analyzing features.
	 */

	/* Connect to the Alert database. */
	$db = NewBASEDBConnection($DBlib_path, $DBtype);
	$db->baseDBConnect($db_connect_method,
	$alert_dbname, $alert_host, $alert_port, $alert_user, $alert_password);

	/* Check do we have pcap_header and data_header columns in data table. */
	if ( !in_array("pcap_header", $db->DB->MetaColumnNames('data')) ||
	     !in_array("data_header", $db->DB->MetaColumnNames('data'))) {
		header ('HTTP/1.0 200');
		header ('Content-Type: text/html');
		print "<h1> File not found:</h1>";
		print "<br>Make sure you have FLoP extended database.";
		print "<br><br><hr><i>Generated by base_payload.php</i><br>";
		exit;
	}

	/* Get needed data from database. */
	$sql2 = "SELECT pcap_header, data_header, data_payload FROM data ";
	$sql2.= "WHERE sid='".$sid."' AND cid='".$cid."'";
	$result2 = $db->baseExecute($sql2);
	$myrow2 = $result2->baseFetchRow();
	$result2->baseFreeRows();

	/* Get encoding information for current sensor. */
	$sql3 = 'SELECT encoding FROM sensor WHERE sid='.$sid;
	$result3 = $db->baseExecute($sql3);
	$myrow3 = $result3->baseFetchRow();
	$result3->baseFreeRows();

	/* 0 == hex, 1 == base64, 2 == ascii; cf. snort-2.4.4/src/plugbase.h */
	if ($myrow3[0] == 0) {
		$pcap_header  = $myrow2[0];
		$data_header  = $myrow2[1];
		$data_payload = $myrow2[2];
	} elseif ($myrow3[0] == 1) {
		$pcap_header  = bin2hex(base64_decode($myrow2[0]));
		$data_header  = bin2hex(base64_decode($myrow2[1]));
		$data_payload = bin2hex(base64_decode($myrow2[2]));
	} else {
		/* database contains neither hex nor base64 encoding. */
		header ('HTTP/1.0 200');
		header ('Content-Type: text/html');
		print "<h1> File not found:</h1>";
		print "<br>Only HEX and BASE64 encoding types are supported, nothing else.";
		print "<br><br><hr><i>Generated by base_payload.php</i><br>";
		exit;
	}

	/* 
	 * From here on: pcap header, data_header and data_payload all contain data in hex 
	 * encoding, even if original encoding type was base64.
	 */

	if (strlen($pcap_header) > 32) {
		header ('HTTP/1.0 200');
		header ('Content-Type: text/html');
		print "<h1> File not found:</h1>";
		print "<br>Error in pcap_header, answer is too large: ".strlen($pcap_header)."!";
		print "<br><br><hr><i>Generated by base_payload.php</i><br>";
		exit;
	} else if (strlen($pcap_header) == 0) {
		header ('HTTP/1.0 200');
		header ('Content-Type: text/html');
		print "<h1> File not found:</h1>";
		print "<br>No pcap header, we can't rebuild the network packet.";
		print "<br><br><hr><i>Generated by base_payload.php</i><br>";
		exit;
	}

	header ('HTTP/1.0 200');
	header ("Content-type: application/octet-stream");
	header ("Content-Disposition: attachment; filename=base_packet_".$sid."-".$cid.".pcap");
	header ("Content-Transfer-Encoding: binary");
	/*
	 * Calculating snaplen which is length of payload plus header,
	 * for HEX we have to divide by two -> two HEX characters
	 * represent one binary byte.
	 */
	$snaplen = (strlen($data_header)+strlen($data_payload))/2;
	header ("Content-length: ". 40 + $snaplen);
	/* Create pcap file header. */
	$hdr['magic'] =         pack('L', 0xa1b2c3d4);  /* unsigned long  (always 32 bit, machine byte order) */
	$hdr['version_major'] = pack('S', 2);           /* unsigned short (always 16 bit, machine byte order) */
	$hdr['version_minor'] = pack('S', 4);           /* unsigned short (always 16 bit, machine byte order) */
	$hdr['thiszone'] =      pack('I', 0);           /* signed   long  (always 32 bit, machine byte order) */
	$hdr['sigfigs'] =       pack('L', 0);           /* unsigned long  (always 32 bit, machine byte order) */
	$hdr['snaplen'] =       pack('L', $snaplen);    /* unsigned long  (always 32 bit, machine byte order) */
	$hdr['linktype'] =      pack('L', 1);           /* unsigned long  (always 32 bit, machine byte order) */
	/* Create pcap packet header. Converting hex to decimal and then to network byte order (big endian). */
	list(, $phdr['timeval_sec']) =  unpack('L', pack('N', hexdec(substr($pcap_header, 0, 8)))); 
	list(, $phdr['timeval_usec']) = unpack('L', pack('N', hexdec(substr($pcap_header, 8, 8)))); 
	list(, $phdr['caplen']) =       unpack('L', pack('N', hexdec(substr($pcap_header, 16, 8))));
	list(, $phdr['len']) =          unpack('L', pack('N', hexdec(substr($pcap_header, 24, 8))));

	/* Copy header to packet, convert hex to dec and from dec to char. */
	for ($i = 0; $i < strlen($data_header); $i = $i + 2)
		$packet .= chr(hexdec(substr($data_header, $i, 2)));

	/* Copy payload to packet, convert hex to dec and from dec to char. */
	for ($i = 0; $i < strlen($data_payload); $i = $i + 2)
		$packet .= chr(hexdec(substr($data_payload, $i, 2)));

	ob_start();

	/* Writing pcap file header */
	foreach ($hdr as $value)
		echo $value;
 
	/* Writing pcap packet header */
	foreach ($phdr as $value)
		echo pack('L', $value);

	/* Writing packet */
	echo $packet;

	ob_end_flush();	
	/* nothing should come after ob_end_flush(). */

} else {
	header ('HTTP/1.0 200');
	header ('Content-Type: text/html');
	print "<h1> File not found:</h1>";
	print "<br>This page is only intended for downloading purposes; it has no content.";
	print "<br><br><hr><i>Generated by base_payload.php</i><br>";
}
?>
