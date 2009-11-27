<?php
/*******************************************************************************
** Basic Analysis and Security Engine (BASE)
** Copyright (C) 2004 BASE Project Team
** Copyright (C) 2000 Carnegie Mellon University
**
** (see the file 'base_main.php' for license details)
**
** Project Lead: Kevin Johnson <kjohnson@secureideas.net>
**                Sean Muller <samwise_diver@users.sourceforge.net>
** Built upon work by Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
**
** Purpose: IP DNS, whois, event cache library   
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net
**
********************************************************************************
*/
/** The below check is to make sure that the conf file has been loaded before this one....
 **  This should prevent someone from accessing the page directly. -- Kevin
 **/
defined( '_BASE_INC' ) or die( 'Accessing this file directly is not allowed.' );

include_once("$BASE_path/base_stat_common.php");
include_once("$BASE_path/includes/base_log_error.inc.php");

function UpdateDNSCache($db)
{
  GLOBAL $debug_mode, $dns_cache_lifetime;

  $cnt = 0;

  $ip_result = $db->baseExecute("SELECT DISTINCT ip_src FROM acid_event ".
                                "LEFT JOIN acid_ip_cache ON ipc_ip = ip_src ".
                                "WHERE ipc_fqdn IS NULL");

  while ( ($row = $ip_result->baseFetchRow()) != NULL )
  {
     if ( $debug_mode > 0 )  
        echo $row[0]." - ".baseLong2IP($row[0])."<BR>";
     baseGetHostByAddr(baseLong2IP($row[0]), $db, $dns_cache_lifetime);
     ++$cnt;
  }
  $ip_result->baseFreeRows();

  $ip_result = $db->baseExecute("SELECT DISTINCT ip_dst FROM acid_event ".
                                "LEFT JOIN acid_ip_cache ON ipc_ip = ip_dst ".
                                "WHERE ipc_fqdn IS NULL");
  while ( ($row = $ip_result->baseFetchRow()) != NULL )
  {
     if ( $debug_mode > 0 )  
        echo $row[0]." - ".baseLong2IP($row[0])."<BR>";  
     baseGetHostByAddr(baseLong2IP($row[0]), $db, $dns_cache_lifetime);
     ++$cnt;
  }
  $ip_result->baseFreeRows();

  ErrorMessage(_ADDED.$cnt._HOSTNAMESDNS);
}

function UpdateWhoisCache($db)
{
  GLOBAL $debug_mode, $whois_cache_lifetime;

  $cnt = 0;

  $ip_result = $db->baseExecute("SELECT DISTINCT ip_src FROM acid_event ".
                                "LEFT JOIN acid_ip_cache ON ipc_ip = ip_src ".
                                "WHERE ipc_whois IS NULL");

  while ( ($row = $ip_result->baseFetchRow()) != NULL )
  {
     if ( $debug_mode > 0 )  echo $row[0]." - ".baseLong2IP($row[0])."<BR>";
     baseGetWhois(baseLong2IP($row[0]), $db, $whois_cache_lifetime);
     ++$cnt;
  }
  $ip_result->baseFreeRows();

  $ip_result = $db->baseExecute("SELECT DISTINCT ip_dst FROM acid_event ".
                                "LEFT JOIN acid_ip_cache ON ipc_ip = ip_dst ".
                                "WHERE ipc_whois IS NULL");

  while ( ($row = $ip_result->baseFetchRow()) != NULL )
  {
     if ( $debug_mode > 0 )  echo $row[0]." - ".baseLong2IP($row[0])."<BR>";  
     baseGetWhois(baseLong2IP($row[0]), $db, $whois_cache_lifetime);
     ++$cnt;
  }
  $ip_result->baseFreeRows();

  ErrorMessage(_ADDED.$cnt._HOSTNAMESWHOIS);
}

function CacheAlert($sid, $cid, $db)
{
  $signature = $timestamp = $ip_src = $ip_dst = null;
  $ip_proto = $layer4_sport = $layer4_dport = $sig_name = null;
  $sig_class_id = $sig_priority = null;

  $sql = "SELECT signature, timestamp, ip_src, ip_dst, ip_proto FROM event ".
         "LEFT JOIN iphdr ON (event.sid=iphdr.sid AND event.cid = iphdr.cid) ".
         "WHERE (event.sid='".$sid."' AND event.cid='".$cid."') ORDER BY event.cid";

  $result = $db->baseExecute($sql);

  $row = $result->baseFetchRow();
  if ( $row )
  {
     $signature = $row[0];
     $timestamp = $row[1];
     $ip_src    = $row[2];
     $ip_dst    = $row[3];
     $ip_proto  = $row[4];
     $result->baseFreeRows();

     if ( $ip_proto == TCP )
     {
        $result = $db->baseExecute("SELECT tcp_sport, tcp_dport FROM
                                    tcphdr WHERE sid='".$sid."' AND cid='".$cid."'");
        $row = $result->baseFetchRow();
        if ( $row )
        {
           $layer4_sport = $row[0];
           $layer4_dport = $row[1];
           $result->baseFreeRows();
        }
     }

     else if ( $ip_proto == UDP )
     {
        $result = $db->baseExecute("SELECT udp_sport, udp_dport FROM
                                    udphdr WHERE sid='".$sid."' AND cid='".$cid."'");
        $row = $result->baseFetchRow();
        if ( $row )
        {
           $layer4_sport = $row[0];
           $layer4_dport = $row[1];
           $result->baseFreeRows();
        }
     }

     if ( $db->baseGetDBversion() >= 100 )
     {
        if ( $db->baseGetDBversion() >= 103 )
           $result = $db->baseExecute("SELECT sig_name, sig_class_id, sig_priority ".
                                      " FROM signature ".
                                      "WHERE sig_id = '".$signature."'");
        else
           $result = $db->baseExecute("SELECT sig_name FROM signature ".
                                      "WHERE sig_id = '".$signature."'");
        $row = $result->baseFetchRow();
        if ( $row )
        {
           $sig_name = $row[0];
           if ( $db->baseGetDBversion() >= 103 )
           {
              $sig_class_id = $row[1];
              $sig_priority = $row[2];
           }
           $result->baseFreeRows();
        } 
     }
  }
  else
  {
    ErrorMessage(_ERRCACHENULL);
    echo "<PRE>".$sql."</PRE>";
  }

  /* There can be events without certain attributes */
  if ($ip_src=='') $ip_src='NULL';
  if ($ip_dst=='') $ip_dst='NULL';
  if ($ip_proto=='') $ip_proto='NULL';
  if ($layer4_sport=='') $layer4_sport='NULL';
  if ($layer4_dport=='') $layer4_dport='NULL';

  if ( $db->baseGetDBversion() >= 100 ) {
      $sql = "INSERT INTO acid_event (sid, cid, signature, sig_name, sig_class_id, sig_priority, ";
      $sql.= "timestamp, ip_src, ip_dst, ip_proto, layer4_sport, layer4_dport) ";
      $sql.= "VALUES ($sid, $cid, $signature, '$sig_name', $sig_class_id, $sig_priority,";
      $sql.= "'$timestamp', $ip_src, $ip_dst, $ip_proto, $layer4_sport, $layer4_dport)";
  } else {
      $sql = "INSERT INTO acid_event (sid, cid, signature, timestamp, ip_src, ";
      $sql.= "ip_dst, ip_proto, layer4_sport,layer4_dport) ";
      $sql.= "VALUES ($sid, $cid, '$signature', '$timestamp', $ip_src, $ip_dst, ";
      $sql.= "$ip_proto, $layer4_sport, $layer4_dport)";
  }

  $db->baseExecute($sql); 

  if ( $db->baseErrorMessage() != "" )
     return 0;
  else 
     return 1;
}

function CacheSensor($sid, $cid, $db)
/*
  Caches all alerts for sensor $sid newer than the event $cid
 */
{
  $schema_specific = array(2);

  $schema_specific[0] = "";
  $schema_specific[1] = "";
  $schema_specific[2] = "";

  if ( $db->baseGetDBversion() >= 100 ) 
  {
     $schema_specific[1] = ", sig_name"; 
     $schema_specific[2] = " INNER JOIN signature ON (signature = signature.sig_id)";
  }
  if ( $db->baseGetDBversion() >= 103 )
  {
     $schema_specific[0] = $schema_specific[0].", sig_priority, sig_class_id";
     $schema_specific[1] = $schema_specific[1].", sig_priority, sig_class_id"; 
     $schema_specific[2] = $schema_specific[2]."";
  }
  if ( $db->baseGetDBversion() < 100 )
     $schema_specific[1] = $schema_specific[1].", signature";

  $update_sql = array(4);

  /* IP events only */
   if ( $db->baseGetDBversion() >= 100 )
      $schema_specific[3] = " (sig_name LIKE '(spp_%') ";
   else
      $schema_specific[3] = " (signature LIKE '(spp_%') ";
  
  /* TCP events */
   if( $db->DB_type == 'oci8' ) {
  $update_sql[0] =
    "INSERT INTO acid_event (sid,cid,signature,timestamp,
                             ip_src,ip_dst,ip_proto,
                             layer4_sport,layer4_dport,
                             sig_name".
                             $schema_specific[0].")
     SELECT a.sid as sid, a.cid as cid, a.signature, a.timestamp,
            b.ip_src, ip_dst, ip_proto,
            tcp_sport as layer4_sport, tcp_dport as layer4_dport".
            $schema_specific[1]."
    FROM event a
    ".$schema_specific[2]." 
    INNER JOIN iphdr b ON (a.sid=b.sid AND a.cid=b.cid) 
    LEFT JOIN tcphdr c ON (a.sid=c.sid AND a.cid=c.cid)
    WHERE (a.sid = $sid AND a.cid > $cid) AND ip_proto = 6
    AND ( NOT ".$schema_specific[3].")";
  }
  else {
  $update_sql[0] =
    "INSERT INTO acid_event (sid,cid,signature,timestamp,
                             ip_src,ip_dst,ip_proto,
                             layer4_sport,layer4_dport,
                             sig_name".
                             $schema_specific[0].")
     SELECT event.sid as sid, event.cid as cid, signature, timestamp, 
            ip_src, ip_dst, ip_proto,
            tcp_sport as layer4_sport, tcp_dport as layer4_dport".
            $schema_specific[1]."
    FROM event
    ".$schema_specific[2]." 
    INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) 
    LEFT JOIN tcphdr ON (event.sid=tcphdr.sid AND event.cid=tcphdr.cid)
    WHERE (event.sid = $sid AND event.cid > $cid) AND ip_proto = 6
    AND ( NOT ".$schema_specific[3].")";
  }
  /* UDP events */

   if( $db->DB_type == 'oci8' ) {
  $update_sql[1] = 
    "INSERT INTO acid_event (sid,cid,signature,timestamp,
                             ip_src,ip_dst,ip_proto,
                             layer4_sport,layer4_dport,
                             sig_name".
                             $schema_specific[0].")
     SELECT a.sid as sid, a.cid as cid, signature, a.timestamp,
            ip_src, ip_dst, ip_proto,
            udp_sport as layer4_sport, udp_dport as layer4_dport".
            $schema_specific[1]."
     FROM event a
     ".$schema_specific[2]."
     INNER JOIN iphdr b ON (a.sid=b.sid AND a.cid=b.cid)
     LEFT JOIN udphdr c ON (a.sid=c.sid AND a.cid=c.cid)
     WHERE (a.sid = $sid AND a.cid > $cid) AND ip_proto = 17
     AND ( NOT ".$schema_specific[3].")";
  }
  else {
  $update_sql[1] = 
    "INSERT INTO acid_event (sid,cid,signature,timestamp,
                             ip_src,ip_dst,ip_proto,
                             layer4_sport,layer4_dport,
                             sig_name".
                             $schema_specific[0].")
     SELECT event.sid as sid, event.cid as cid, signature, timestamp,
            ip_src, ip_dst, ip_proto,
            udp_sport as layer4_sport, udp_dport as layer4_dport".
            $schema_specific[1]."
     FROM event
     ".$schema_specific[2]."
     INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid)
     LEFT JOIN udphdr ON (event.sid=udphdr.sid AND event.cid=udphdr.cid)
     WHERE (event.sid = $sid AND event.cid > $cid) AND ip_proto = 17
     AND ( NOT ".$schema_specific[3].")";
  }

   /* ICMP events */
   if( $db->DB_type == 'oci8' ) {
   $update_sql[2] = 
     "INSERT INTO acid_event (sid,cid,signature,timestamp,
                              ip_src,ip_dst,ip_proto,
                              sig_name".
                              $schema_specific[0].")
      SELECT a.sid as sid, a.cid as cid, signature, a.timestamp,
             ip_src, ip_dst, ip_proto".
             $schema_specific[1]."
      FROM event a
      ".$schema_specific[2]."
      INNER JOIN iphdr b ON (a.sid=b.sid AND a.cid=b.cid)
      LEFT JOIN icmphdr c ON (a.sid=c.sid AND a.cid=c.cid)
      WHERE (a.sid = $sid AND a.cid > $cid) and ip_proto = 1
      AND ( NOT ".$schema_specific[3].")";
   }
   else {
   $update_sql[2] = 
     "INSERT INTO acid_event (sid,cid,signature,timestamp,
                              ip_src,ip_dst,ip_proto,
                              sig_name".
                              $schema_specific[0].")
      SELECT event.sid as sid, event.cid as cid, signature, timestamp,
             ip_src, ip_dst, ip_proto".
             $schema_specific[1]."
      FROM event
      ".$schema_specific[2]."
      INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid)
      LEFT JOIN icmphdr ON (event.sid=icmphdr.sid AND event.cid=icmphdr.cid)
      WHERE (event.sid = $sid AND event.cid > $cid) and ip_proto = 1
      AND ( NOT ".$schema_specific[3].")";
   }

   if( $db->DB_type == 'oci8' ) {
   $update_sql[3] = 
     "INSERT INTO acid_event (sid,cid,signature,timestamp,
                              ip_src,ip_dst,ip_proto,
                              sig_name".
                              $schema_specific[0].")
      SELECT a.sid as sid, a.cid as cid, signature, a.timestamp,
             ip_src, ip_dst, ip_proto".
             $schema_specific[1]."
      FROM event a
      ".$schema_specific[2]."
      LEFT JOIN iphdr b ON (a.sid=b.sid AND a.cid=b.cid)
      WHERE (NOT (ip_proto IN (1, 6, 17))) AND ".
            " ( NOT ".$schema_specific[3].") AND
            (a.sid = $sid AND a.cid > $cid)";
   }
   else {
   $update_sql[3] = 
     "INSERT INTO acid_event (sid,cid,signature,timestamp,
                              ip_src,ip_dst,ip_proto,
                              sig_name".
                              $schema_specific[0].")
      SELECT event.sid as sid, event.cid as cid, signature, timestamp,
             ip_src, ip_dst, ip_proto".
             $schema_specific[1]."
      FROM event
      ".$schema_specific[2]."
      LEFT JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid)
      WHERE (NOT (ip_proto IN (1, 6, 17))) AND ".
            " ( NOT ".$schema_specific[3].") AND
            (event.sid = $sid AND event.cid > $cid)";
   }
   /* Event only -- pre-processor alerts */
   if( $db->DB_type == 'oci8' ) {
     $update_sql[4] = 
       "INSERT INTO acid_event (sid,cid,signature,timestamp,
                                ip_src,ip_dst,ip_proto,
                                sig_name".
                                $schema_specific[0].")
        SELECT a.sid as sid, a.cid as cid, signature, a.timestamp,
               ip_src, ip_dst, ip_proto".
               $schema_specific[1]."
        FROM event a
        ".$schema_specific[2]."
        LEFT JOIN iphdr b ON (a.sid=b.sid AND a.cid=b.cid)
        WHERE ".$schema_specific[3]." AND 
        (a.sid = $sid AND a.cid > $cid)";
   }
   else {
     $update_sql[4] = 
       "INSERT INTO acid_event (sid,cid,signature,timestamp,
                                ip_src,ip_dst,ip_proto,
                                sig_name".
                                $schema_specific[0].")
         SELECT event.sid as sid, event.cid as cid, signature, timestamp,
               ip_src, ip_dst, ip_proto".
               $schema_specific[1]."
        FROM event
        ".$schema_specific[2]."
        LEFT JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid)
        WHERE ".$schema_specific[3]." AND 
        (event.sid = $sid AND event.cid > $cid)";
   }

   $update_cnt = count($update_sql);
   for ( $i = 0; $i < $update_cnt; $i++ )
   {
       $db->baseExecute($update_sql[$i]); 

       if ( $db->baseErrorMessage() != "" )
          ErrorMessage(_ERRCACHEERROR." ["._SENSOR." #$sid]["._EVENTTYPE." $i]".
                       " "._ERRCACHEUPDATE);
   }

}

function UpdateAlertCache($db)
{
  GLOBAL $debug_mode;
  GLOBAL $archive_exists;
  GLOBAL $DBlib_path, $DBtype, 
         $archive_dbname, $archive_host, $archive_port,
         $archive_user, $archive_password;

  $batch_sql = "";
  $batch_cnt = 0;

  $updated_cache_cnt = 0;

  $sensor_lst = $db->baseExecute("SELECT sid FROM sensor");
  
  /* Iterate through all sensors in the SENSOR table */
  while ( ($sid_row = $sensor_lst->baseFetchRow()) != NULL )
  {
     $sid = $sid_row[0];

     /* Get highest CID for a given sensor */
     $cid_lst = $db->baseExecute("SELECT MAX(cid) FROM event WHERE sid='".$sid."'");
     $cid_row = $cid_lst->baseFetchRow();
     $cid = $cid_row[0];
     if ( $cid == NULL ) $cid = 0;

     /* Get highest CID for a given sensor in the cache */
     $ccid_lst = $db->baseExecute("SELECT MAX(cid) FROM acid_event WHERE sid='".$sid."'");
     $ccid_row = $ccid_lst->baseFetchRow();
     $ccid = $ccid_row[0];
     if ( $ccid == NULL ) $ccid = 0;

     if ( $debug_mode > 0 )
        echo "sensor #$sid: event.cid = $cid, acid_event.cid = $ccid";

     /* if the CID in the cache < the CID in the event table 
      *  then there are events which have NOT been added to the cache 
      */
     if ( $cid > $ccid )
     {
        $before_cnt = EventCntBySensor($sid, $db);        
        CacheSensor($sid, $ccid, $db);
        $updated_cache_cnt += EventCntBySensor($sid, $db) - $before_cnt;
     }

     if ( $debug_mode > 0 )
        echo "<BR>";

     $cid_lst->baseFreeRows();
     $ccid_lst->baseFreeRows();
 
      /* BEGIN LOCAL FIX */
 
      /* If there's an archive database, and this isn't it, get the MAX(cid) from there */
      if ( ($archive_exists == 1) && (@$_COOKIE['archive'] != 1) ) { 
        $db2 = NewBASEDBConnection($DBlib_path, $DBtype);
        $db2->baseConnect($archive_dbname, $archive_host, $archive_port,
                          $archive_user, $archive_password);
        $archive_ccid_lst = $db2->baseExecute("SELECT MAX(cid) FROM acid_event WHERE sid='".$sid."'"); 
        $archive_ccid_row = $archive_ccid_lst->baseFetchRow();
        $archive_ccid = $archive_ccid_row[0];
		$archive_ccid_lst->baseFreeRows();
		$db2->baseClose();
        if ( $archive_ccid == NULL ) $archive_ccid = 0;
	$archive_ccid_lst->baseFreeRows();
	$db2->baseClose();
      } else {
        $archive_ccid = 0; 
      }
 
      if ( $archive_ccid > $ccid ) {
        $max_ccid = $archive_ccid;
      } else {
        $max_ccid = $ccid;
      }
 
      /* Fix the last_cid value for the sensor */
      $db->baseExecute("UPDATE sensor SET last_cid=$max_ccid WHERE sid=$sid"); 
 
      /* END LOCAL FIX */
  }  

 if ( $updated_cache_cnt != 0 )
 {
   if ( preg_match("/base_main.php/", $_SERVER['SCRIPT_NAME']) )
         ErrorMessage(_ADDED.$updated_cache_cnt._ALERTSCACHE, "yellow");
   else
         ErrorMessage(_ADDED.$updated_cache_cnt._ALERTSCACHE);
  }
}

function DropAlertCache($db)
{
  $db->baseExecute("DELETE FROM acid_event");
}

function DropDNSCache($db)
{
  $db->baseExecute("UPDATE acid_ip_cache SET ipc_fqdn = NULL, ipc_dns_timestamp = NULL");
}

function DropWhoisCache($db)
{
  $db->baseExecute("UPDATE acid_ip_cache SET ipc_whois = NULL, ipc_whois_timestamp = NULL");
}
?>
