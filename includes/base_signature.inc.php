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
** Purpose: Handles signatures and references in the 
**          Snort signature language
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

function GetSignatureName($sig_id, $db)
{
   $name = "";

   $temp_sql = "SELECT sig_name FROM signature WHERE sig_id='$sig_id'";
   $tmp_result = $db->baseExecute($temp_sql);
   if ( $tmp_result )
   {
      $myrow = $tmp_result->baseFetchRow();
      $name = $myrow[0];
      $tmp_result->baseFreeRows();
   }
   else
      $name = "["._ERRSIGNAMEUNK."]";

   return $name;
}

function GetSignaturePriority($sig_id, $db)
{
   $priority = "";

   $temp_sql = "SELECT sig_priority FROM signature WHERE sig_id='$sig_id'";
   $tmp_result = $db->baseExecute($temp_sql);
   if ( $tmp_result )
   {
     $myrow = $tmp_result->baseFetchRow();
     $priority = $myrow[0];

     $tmp_result->baseFreeRows();
   }
   else
     $priority = "["._ERRSIGPROIRITYUNK."]";

   return $priority;
}

function GetSignatureID($sig_id, $db)
{
   $id = "";
  
   if ( $sig_id == "" )
      return $id;

   $temp_sql = "SELECT sig_id FROM signature WHERE sig_name='$sig_id'";
   if ($db->DB_type == "mssql")
     $temp_sql = "SELECT sig_id FROM signature WHERE sig_name LIKE '".MssqlKludgeValue($sig_id)."' ";

   $tmp_result = $db->baseExecute($temp_sql);
   if ( $tmp_result )
   {
      $myrow = $tmp_result->baseFetchRow();
      $id = $myrow[0];
      $tmp_result->baseFreeRows();
   }

   return $id;
}

function GetRefSystemName($ref_system_id, $db)
{
   if ( $ref_system_id == "" )
      return "";

   $ref_system_name = "";

   $tmp_sql = "SELECT ref_system_name FROM reference_system WHERE ref_system_id='".$ref_system_id."'";
   $tmp_result = $db->baseExecute($tmp_sql);
   if ( $tmp_result )
   {
      $myrow = $tmp_result->baseFetchRow();
      $ref_system_name = $myrow[0];
      $tmp_result->baseFreeRows();
   }

   return trim($ref_system_name);
}

function GetSingleSignatureReference($ref_system, $ref_tag, $style)
{
   $tmp_ref_system_name = strtolower($ref_system);
   if ( in_array($tmp_ref_system_name, array_keys($GLOBALS['external_sig_link'])) )
   {
      if ( $style == 1 )
         return "<FONT SIZE=-1>[".
                "<A HREF=\"".$GLOBALS['external_sig_link'][$tmp_ref_system_name][0].
                             $ref_tag.
                             $GLOBALS['external_sig_link'][$tmp_ref_system_name][1]."\" ".
                             "TARGET=\"_ACID_ALERT_DESC\">".$ref_system."</A>".
                 "]</FONT> ";
      else if ( $style == 2 )
         return "[".$ref_system."/$ref_tag] ";
   }            
   else
   {
      return $ref_system;
   }
}

function GetSignatureReference($sig_id, $db, $style)
{
   $ref = "";
   GLOBAL $BASE_display_sig_links;
   
   if ( $BASE_display_sig_links == 1)
   {
      $temp_sql = "SELECT ref_seq, ref_id FROM sig_reference WHERE sig_id='".$sig_id."'";
      $tmp_sig_ref = $db->baseExecute($temp_sql);
   
      if ( $tmp_sig_ref )
      {
         $num_references = $tmp_sig_ref->baseRecordCount();
         for ( $i = 0; $i < $num_references; $i++)
         {
            $mysig_ref = $tmp_sig_ref->baseFetchRow();
   
            $temp_sql = "SELECT ref_system_id, ref_tag FROM reference WHERE ref_id='".$mysig_ref[1]."'";
            $tmp_ref_tag = $db->baseExecute($temp_sql);
   
            if ( $tmp_ref_tag )
            {
               $myrow = $tmp_ref_tag->baseFetchRow();
               $ref_tag = $myrow[1];
               $ref_system = GetRefSystemName($myrow[0], $db);
            }
   
            $ref = $ref.GetSingleSignatureReference($ref_system, $ref_tag, $style);
   
            /* Automatically add an ICAT reference is a CVE reference exists */
            if ( $ref_system == "cve" )
                $ref = $ref.GetSingleSignatureReference("icat", $ref_tag, $style);
          
            $tmp_ref_tag->baseFreeRows();
         }
         $tmp_sig_ref->baseFreeRows();
      }
   
      if ( $db->baseGetDBversion() >= 103 )
      {
         if ( $db->baseGetDBversion() >= 107 )
            $tmp_sql = "SELECT sig_sid, sig_gid FROM signature WHERE sig_id='".$sig_id."'";
         else
            $tmp_sql = "SELECT sig_sid FROM signature WHERE sig_id='".$sig_id."'";
   
         $tmp_sig_sid = $db->baseExecute($tmp_sql);
   
         if ( $tmp_sig_sid )
         {
            $myrow = $tmp_sig_sid->baseFetchRow();
            $sig_sid = $myrow[0];
            if ( $db->baseGetDBversion() >= 107 )
               $sig_gid = $myrow[1];
   
         }
      }
      else
         $sig_sid = "";
   
      $href = "";
   
      /* xxx jl: provided, that there is a subdirectory "signatures/" in $BASE_urlpath */
      if ( ( is_numeric($sig_id) ) && ($sig_sid >= 103) ) {
         $ref = $ref.GetSingleSignatureReference("local", $sig_sid, $style);
      }
   
   
      /* snort.org should be documenting all official signatures,
       * so automatically add a link
       */
      if ( $sig_sid != "") {
         if ( $db->baseGetDBversion() >= 107 )
	    /* Hack to finx blank gid from barnyard -- Kevin Johnson */
	    if ( $sig_gid != "") {
            	$ref = $ref.GetSingleSignatureReference("snort", $sig_gid .':'. $sig_sid, $style);
	    } else {
		$ref = $ref.GetSingleSignatureReference("snort", $sig_sid, $style);
	    }
         else
            $ref = $ref.GetSingleSignatureReference("snort", $sig_sid, $style);
      }
   }

   return $ref;
}

function BuildSigLookup($signature, $style)
/* - Paul Harrington <paul@pizza.org> : reference URL links
 * - Michael Bell <michael.bell@web.de> : links for IP address in spp_portscan alerts
 */
{
  if ($style == 2)
     return $signature;

  /* create hyperlinks for references */
  $pattern=array("/(IDS)(\d+)/", 
                 "/(IDS)(0+)(\d+)/",
                 "/BUGTRAQ ID (\d+)/",
                 "/MCAFEE ID (\d+)/",
                 "/(CVE-\d+-\d+)/");

  $replace=array("<A HREF=\"http://www.whitehats.com/\\1/\\2\" TARGET=\"_ACID_ALERT_DESC\">\\1\\2</A>",
                 "<A HREF=\"http://www.whitehats.com/\\1/\\3\" TARGET=\"_ACID_ALERT_DESC\">\\1\\2\\3</A>",
                 "<A HREF=\"".$GLOBALS['external_sig_link']['bugtraq'][0]."\\1\" TARGET=\"_ACID_ALERT_DESC\">BUGTRAQ ID \\1</A>",
                 "<A HREF=\"".$GLOBALS['external_sig_link']['mcafee'][0]."\\1\" TARGET=\"_ACID_ALERT_DESC\">MCAFEE ID \\1</A>",
                 "<A HREF=\"".$GLOBALS['external_sig_link']['cve'][0]."\\1\" TARGET=\"_ACID_ALERT_DESC\">\\1</A>");

  $msg = preg_replace($pattern, $replace, $signature);

  /* fixup portscan message strings */
  if ( stristr($msg, "spp_portscan") )
  {
      /* replace "spp_portscan: portscan status" => "spp_portscan"  */
      $msg = preg_replace("/spp_portscan: portscan status/", "spp_portscan", $msg);

      /* replace "spp_portscan: PORTSCAN DETECTED" => "spp_portscan detected" */
      $msg = preg_replace("/spp_portscan: PORTSCAN DETECTED/", "spp_portscan detected", $msg);

      /* create hyperlink for IP addresses in portscan alerts */
      $msg = preg_replace("/([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)/",
                          "<A HREF=\"base_stat_ipaddr.php?ip=\\1&amp;netmask=32\">\\1</A>",
                          $msg);
  }

  return $msg;
}

function BuildSigByID($sig_id, $db, $style = 1)
/*
 * sig_id: DB schema dependent
 *         - < v100: a text string of the signature
 *         - > v100: an ID (key) of a signature
 * db    : database handle
 * style : how should the signature be returned?
 *         - 1: (default) HTML
 *         - 2: text
 *
 * RETURNS: a formatted signature and the associated references
 */
{
  if ( $db->baseGetDBversion() >= 100 )
  {
     /* Catch the odd circumstance where $sig_id is still an alert text string
      * despite using normalized signature as of DB version 100. 
      */
     if ( !is_numeric($sig_id) )
        return $sig_id;
     $sig_name = GetSignatureName($sig_id, $db);
     if ( $sig_name != "" )
        return GetSignatureReference($sig_id, $db, $style)." ".BuildSigLookup($sig_name, $style);
     else
     {
        if ( $style == 1 )
           return "($sig_id)<I>"._ERRSIGNAMEUNK."</I>";
        else
           return "($sig_id) "._ERRSIGNAMEUNK;
     }
  }
  else
     return BuildSigLookup($sig_id, $style);
}

function GetSigClassID($sig_id, $db)
{
  $sql = "SELECT sig_class_id FROM signature ".
         "WHERE sig_id = '$sig_id'";

  $result = $db->baseExecute($sql);
  $row = $result->baseFetchRow();

  return $row[0]; 
}

function GetSigClassName ($class_id, $db)
{
  if ( $class_id == "" )
    return "<I>unclassified</I>";

  $sql = "SELECT sig_class_name FROM sig_class ". 
         "WHERE sig_class_id = '$class_id'";
  $result = $db->baseExecute($sql);

  $row = $result->baseFetchRow();
  if ( $row == "" )  
    return "<I>"._UNCLASS."</I>";
  else
    return $row[0]; 
}

function GetTagTriger($current_sig, $db, $sid, $cid)
{

      /* add to signature name sig_name of tagged alert which trigered this alert -- nikns */
      if (stristr($current_sig, "Tagged Packet")) {

           /* thats possible only if we have FLoP extended db */
           if ( in_array("reference", $db->DB->MetaColumnNames('event')) ) {

                /* get event reference */
                $sql2 = "SELECT signature, reference FROM event ";
                $sql2.= "WHERE sid='".$sid."' AND cid='".$cid."'";
                $result2 = $db->baseExecute($sql2);
                $row2 = $result2->baseFetchRow();
                $result2->baseFreeRows();
                $event_sig = $row2[0];
                $event_reference = $row2[1];

                /* return if we couldn't get event signature or event reference */
                if ( ($event_sig == "") || ($event_reference == "") )
                   return $current_sig;

                /* get triger signature id */
                $sql2 = "SELECT signature, sid, cid FROM event WHERE sid='".$sid."' ";
                $sql2.= "AND reference='".$event_reference."' AND NOT signature='".$event_sig."'";
                $result2 = $db->baseExecute($sql2);
                $row2 = $result2->baseFetchRow();
                $result2->baseFreeRows();
                $triger_sig = $row2[0];
                $triger_sid = $row2[1];
                $triger_cid = $row2[2];

                if ( $triger_sig != "" ) {

                   /* get triger signature name from signature */
                   $sql2 = "SELECT sig_name FROM signature ";
                   $sql2.= "WHERE sig_id='".$triger_sig."'";
                   $result2 = $db->baseExecute($sql2);
                   $row2 = $result2->baseFetchRow();
                   $result2->baseFreeRows();
                   $triger_sig_name = $row2[0];  

                   if ( $triger_sig_name != "" ) {
                      /* return added tagged alert sig_name to signature name */
                      $current_sig.= " <i>(<a href=\"base_qry_alert.php?submit=".rawurlencode("#(0-".$triger_sid."-".$triger_cid.")")."\">";
                      $current_sig.= "#(".$triger_sid."-".$triger_cid."</a>) ".$triger_sig_name.")</i>";

                   }
                }

           }
      }
      return $current_sig;
}

?>
