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
** Purpose: extracts and calculates the data to plot
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net
**
********************************************************************************
*/

include_once("base_conf.php");
include_once("$BASE_path/base_qry_common.php");
include_once("$BASE_path/includes/base_signature.inc.php");

// Some colors to be used in graphs.
$named_colors = array('aliceblue','antiquewhite','aqua','aquamarine','azure','beige','bisque','black','blanchedalmond','blue','blueviolet','brown','burlywood','cadetblue','chartreuse','chocolate','coral','cornflowerblue','cornsilk','crimson','cyan','darkblue','darkcyan','darkgoldenrod','darkdray','darkgreen','darkhaki','darkorange','darkolivegreen','darkmagenta','darkorchid','darkred','darksalmon','darkseagreen','darkviolet','deeppink','deepskyblue','dimgray','dodgerblue','firebrick','floralwhite','forestgreen','fuchsia','gainsboro','ghostwhite','gold','goldenrod','gray','green','greenyellow','indianred','indigo','ivory');

function VerifyGraphingLib()
{
  GLOBAL $debug_mode;
   /* Check if GD is compiled into PHP */
   if ( !(function_exists("ImageDestroy")) )
   {
      echo "<FONT COLOR=\"#FF0000\">"._ERRPHPERROR."</FONT>:
            <B>PHP build incomplete</B>: <FONT>
            the prerequisite GD support required to
            generate graphs was not built into PHP.
            Please recompile PHP with the necessary library 
            (<CODE>--with-gd</CODE>)</FONT>";
      die();
   }
   
    // We have to locate Image/Graph.php -- Alejandro
    $file = "Image/Graph.php";
    $found = false;
    // Will search in Path   
    $paths = explode(PATH_SEPARATOR, ini_get('include_path'));
    foreach ($paths as $path) {
        $fullpath = $path . DIRECTORY_SEPARATOR . $file; 
        if (file_exists($fullpath)) {
            $found = true;
           break;         
        }
    }
    
    if ( $found ) {
            // Cool, file was found, so you have Image_Graph installed. -- Alejandro
            include($file);
            return true;
    } else {
            // Sorry dude, you haven't finished your home work. -- Alejandro
      echo "<P><B>Error loading the Graphing library: </B>".
           "<P>Check your Pear::Image_Graph installation!".
            "<P>".
            "Image_Graph can be found here:".
            "at <A HREF=\"http://pear.veggerby.dk/\">http://pear.veggerby.dk/</A>.  Without this ".
            "library no graphing operations can be performed.";

      die();

    }      
}

/* Generates the required SQL from the chart time criteria */
function ProcessChartTimeConstraint($start_hour, $start_day, $start_month, $start_year,
                                    $stop_hour,  $stop_day,  $stop_month,  $stop_year ) 
{
   /* if any of the hour, day criteria is blank ' ', set it to NULL */
   /**
   ereg_replace(" ", "", $start_hour);
   ereg_replace(" ", "", $stop_hour);
   ereg_replace(" ", "", $start_day);
   ereg_replace(" ", "", $stop_day);
   */
   $start_hour = trim($start_hour);
   $stop_hour = trim($stop_hour);
   $start_day = trim($start_day);
   $stop_day = trim($stop_day);

   $tmp_sql = "";
   $tmp_time = array ( array (" ",
                              ">=",
                              $start_month, $start_day, $start_year,
                              $start_hour, "", "",
                              " ", "AND"),
                       array (" ",
                              "<=",
                              $stop_month, $stop_day, $stop_year,
                              $stop_hour, "", "",
                              " ", " ") );
    DateTimeRows2sql($tmp_time, 2, $tmp_sql);

    return $tmp_sql;
}

function StoreAlertNum($sql, $label, &$xdata, &$cnt, $min_threshold)
{  
  GLOBAL $db, $debug_mode;

  if ( $debug_mode > 0 )     echo $sql."<BR>";

  $result = $db->baseExecute($sql);
  if ( $myrow = $result->baseFetchRow() )
  {
     if ( $myrow[0] >= $min_threshold )
     {
        $xdata [ $cnt ][0] = $label;
        $xdata [ $cnt ][1] = $myrow[0];
     }
     $result->baseFreeRows();

     $cnt++;
  }
}

function GetTimeDataSet(&$xdata, $chart_type, $data_source, $min_threshold, $criteria)
{
  GLOBAL $db, $debug_mode;

   if ( $debug_mode > 0 )
   {
      echo "chart_type = $chart_type<BR>
            data_source = $data_source<BR>";
   }

   $sql = "SELECT min(timestamp), max(timestamp) FROM acid_event ".
          $criteria[0].
          " WHERE ".$criteria[1];
 
   $result = $db->baseExecute($sql);
   $myrow = $result->baseFetchRow();
   $start_time = $myrow[0];
   $stop_time = $myrow[1];
   $result->baseFreeRows();

   $year_start  = date("Y", strtotime($start_time));
   $month_start = date("m", strtotime($start_time));
   $day_start   = date("d", strtotime($start_time));
   $hour_start  = date("H", strtotime($start_time));

   $year_end  = date("Y", strtotime($stop_time));
   $month_end = date("m", strtotime($stop_time));
   $day_end   = date("d", strtotime($stop_time));
   $hour_end  = date("H", strtotime($stop_time));

  // using the settings from begin_xyz and end_xyz
  // minutes are not supported actually
  
  // begin
  global $chart_begin_year;
  global $chart_begin_month;
  global $chart_begin_day;
  global $chart_begin_hour;
  if ( strcmp ($chart_begin_year, " ") and 
       ($year_start < $chart_begin_year) ) {
    $year_start  = $chart_begin_year;
    $month_start = "01";
    $day_start   = "01";
    $hour_start  = "00";
  }
  if ( strcmp ($chart_begin_month, " ") and
       ($month_start < $chart_begin_month) ) {
    $month_start = $chart_begin_month;
    $day_start   = "01";
    $hour_start  = "00";
  }
  if ( strcmp ($chart_begin_day, " ") and
       ($day_start < $chart_begin_day) ) {
    $day_start  = $chart_begin_day;
    $hour_start  = "00";
  }
  if ( strcmp ($chart_begin_hour, " ") and
       ($hour_start < $chart_begin_hour) ) {
    $hour_start  = $chart_begin_hour;
  }

  //end
  global $chart_end_year;
  global $chart_end_month;
  global $chart_end_day;
  global $chart_end_hour;
  if ( strcmp ($chart_end_year, " ") and 
       ($year_end < $chart_end_year) ) {
    $year_end  = $chart_end_year;
    $month_end = "01";
    $day_end   = "01";
    $hour_end  = "00";
  }
  if ( strcmp ($chart_end_month, " ") and
       ($month_end < $chart_end_month) ) {
    $month_end = $chart_end_month;
    $day_end   = "01";
    $hour_end  = "00";
  }
  if ( strcmp ($chart_end_day, " ") and
       ($day_end < $chart_end_day) ) {
    $day_end  = $chart_end_day;
    $hour_end  = "00";
  }
  if ( strcmp ($chart_end_hour, " ") and
       ($hour_end < $chart_end_hour) ) {
    $hour_end  = $chart_end_hour;
  }


   switch($chart_type)
   { 
     case 2:  // day          
     { 
        $hour_start = -1;
        break; 
     }
     case 4:  // month           
     { 
        $day_start = -1;
        $hour_start = -1;
        break; 
     }
  }

  if ( $debug_mode > 0 )
  {
     echo '<TABLE BORDER=1>
            <TR>
              <TD>year_start<TD>year_end<TD>month_start<TD>month_end
              <TD>day_start<TD>day_end<TD>hour_start<TD>hour_end
            <TR>
              <TD>'.$year_start.'<TD>'.$year_end.'<TD>'.$month_start.'<TD>'.$month_end.
              '<TD>'.$day_start.'<TD>'.$day_end.'<TD>'.$hour_start.'<TD>'.$hour_end.
           '</TABLE>';
  }

  $cnt = 0;
  $ag = $criteria[0];
  $ag_criteria = $criteria[1];
  
  for ( $i_year = $year_start; $i_year <= $year_end; $i_year++ )
  {
    // removed AND below
    // !!! AVN !!!
    // to_date() must used!
      $sql = "SELECT count(*) FROM acid_event ".$ag." WHERE $ag_criteria AND ".
             $db->baseSQL_YEAR("timestamp", "=", $i_year);

      if ( $month_start != -1 )
      {
         if ($i_year == $year_start)  $month_start2 = $month_start;  else  $month_start2 = 1;
         if ($i_year == $year_end)    $month_end2 = $month_end;      else  $month_end2 = 12;

         for ( $i_month = $month_start2; $i_month <= $month_end2; $i_month++ )
         {
             $sql = "SELECT count(*) FROM acid_event $ag WHERE $ag_criteria AND".
                    $db->baseSQL_YEAR("timestamp", "=", $i_year)." AND ".
                    $db->baseSQL_MONTH("timestamp", "=", FormatTimeDigit($i_month));

             if ( $day_start != -1 )
             {
                if ($i_month == $month_start)  $day_start2 = $day_start;  else  $day_start2 = 1;
                if ($i_month == $month_end)    $day_end2 = $day_end;      else  $day_end2 = 31;

                for ( $i_day = $day_start2; $i_day <= $day_end2; $i_day++ )
                {
                  if ( checkdate($i_month, $i_day, $i_year) )
                  {
                    $sql = "SELECT count(*) FROM acid_event $ag WHERE $ag_criteria AND ".
                           $db->baseSQL_YEAR("timestamp", "=", $i_year)." AND ".
                           $db->baseSQL_MONTH("timestamp", "=",FormatTimeDigit($i_month))." AND ".
                           $db->baseSQL_DAY("timestamp", "=", FormatTimeDigit($i_day));

                    if ( $hour_start != -1 )
                    {
                       for ( $i_hour = $hour_start; $i_hour <= $hour_end; $i_hour++ )
                       {
					       
                           //if($i_hour < 10 && strlen($i_hour) == 1)
                             // $i_hour = "0".$i_hour;
							 $i_hour = FormatTimeDigit($i_hour);
                           $sql = "SELECT count(*) FROM acid_event $ag WHERE $ag_criteria AND ".
                                  $db->baseSQL_YEAR("timestamp", "=", $i_year)." AND ".
                                  $db->baseSQL_MONTH("timestamp", "=", FormatTimeDigit($i_month))." AND ".
                                  $db->baseSQL_DAY("timestamp", "=", FormatTimeDigit($i_day))." AND ".
                                  $db->baseSQL_HOUR("timestamp", "=", $i_hour);

						   
                           StoreAlertNum($sql, FormatTimeDigit($i_month)."/".FormatTimeDigit($i_day)."/".$i_year." ".
                                               $i_hour.":00:00 - ".$i_hour.":59:59", 
                                               $xdata, $cnt, $min_threshold);
                       }  // end hour
                    }
                    else
                        StoreAlertNum($sql, FormatTimeDigit($i_month)."/".FormatTimeDigit($i_day)."/".$i_year, 
                                      $xdata, $cnt, $min_threshold);
                  }
                }   // end day
             }
             else
               StoreAlertNum($sql, FormatTimeDigit($i_month)."/".$i_year, $xdata, $cnt, $min_threshold);
         }   // end month
      }
      else
        StoreAlertNum($sql, $i_year, $xdata, $cnt, $min_threshold);
  }   // end year

  return $cnt;
}

function GetIPDataSet(&$xdata, $chart_type, $data_source, $min_threshold, $criteria)
{
   GLOBAL $db, $debug_mode;

   if ( $chart_type == 6 ) 
      $sql = "SELECT DISTINCT ip_src, COUNT(acid_event.cid) ".
             "FROM acid_event ".$criteria[0].
             "WHERE ".$criteria[1]." AND ip_src is NOT NULL ".
             "GROUP BY ip_src ORDER BY ip_src";
   else if ( $chart_type == 7 )
      $sql = "SELECT DISTINCT ip_dst, COUNT(acid_event.cid) ".
             "FROM acid_event ".$criteria[0].
             "WHERE ".$criteria[1]." AND ip_dst is NOT NULL ".
             "GROUP BY ip_dst ORDER BY ip_dst";

   if ( $debug_mode > 0)  echo $sql."<BR>";
   
   $result = $db->baseExecute($sql);

   $cnt = 0;
   while ( $myrow = $result->baseFetchRow() )
   {
      if ( $myrow[1] >= $min_threshold )
      {
         $xdata[$cnt][0] = baseLong2IP($myrow[0]); 
         $xdata[$cnt][1] = $myrow[1]; 
         ++$cnt;
      }
   }

   $result->baseFreeRows();
   return $cnt;
}

function GetPortDataSet(&$xdata, $chart_type, $data_source, $min_threshold, $criteria)
{
   GLOBAL $db, $debug_mode;

   if ( ($chart_type == 8) || ($chart_type == 9) ) 
      $sql = "SELECT DISTINCT layer4_dport, COUNT(acid_event.cid) ".
             "FROM acid_event ".$criteria[0].
             "WHERE ".$criteria[1]." AND layer4_dport is NOT NULL ".
             "GROUP BY layer4_dport ORDER BY layer4_dport";
   else if ( ($chart_type == 10) || ($chart_type == 11) ) 
      $sql = "SELECT DISTINCT layer4_sport, COUNT(acid_event.cid) ".
             "FROM acid_event ".$criteria[0].
             "WHERE ".$criteria[1]." AND layer4_sport is NOT NULL ".
             "GROUP BY layer4_sport ORDER BY layer4_sport";

   if ( $debug_mode > 0)  echo $sql."<BR>";
   
   $result = $db->baseExecute($sql);

   $cnt = 0;
   while ( $myrow = $result->baseFetchRow() )
   {
      if ( $myrow[1] >= $min_threshold )
      {
         $xdata[$cnt][0] = $myrow[0]; 
         $xdata[$cnt][1] = $myrow[1]; 
         ++$cnt;
      }
   }

   $result->baseFreeRows();
   return $cnt;
}

function GetClassificationDataSet(&$xdata, $chart_type, $data_source, $min_threshold, $criteria)
{
   GLOBAL $db, $debug_mode;
  
   $sql = "SELECT DISTINCT sig_class_id, COUNT(acid_event.cid) ".
          "FROM acid_event ".$criteria[0].
          "WHERE ".$criteria[1].
          " GROUP BY sig_class_id ORDER BY sig_class_id";

   if ( $debug_mode > 0)  echo $sql."<BR>";
   
   $result = $db->baseExecute($sql);

   $cnt = 0;
   while ( $myrow = $result->baseFetchRow() )
   {
      if ( $myrow[1] >= $min_threshold )
      {
         $xdata[$cnt][0] = strip_tags(GetSigClassName($myrow[0], $db)); 
         $xdata[$cnt][1] = $myrow[1];
         ++$cnt;
      }
   }

   $result->baseFreeRows();
   return $cnt;
}

function GetSensorDataSet(&$xdata, $chart_type, $data_source, $min_threshold, $criteria)
{
   GLOBAL $db, $debug_mode;

   $sql = "SELECT DISTINCT acid_event.sid, COUNT(acid_event.cid) ".
          "FROM acid_event ".$criteria[0].
          "WHERE ".$criteria[1].
          " GROUP BY acid_event.sid ORDER BY acid_event.sid";

   if ( $debug_mode > 0)  echo $sql."<BR>";
   
   $result = $db->baseExecute($sql);

   $cnt = 0;
   while ( $myrow = $result->baseFetchRow() )
   {
      if ( $myrow[1] >= $min_threshold )
      {
         $result2 = $db->baseExecute("SELECT hostname FROM sensor where sid=".$myrow[0]);
         $sensor_name = $result2->baseFetchRow();
         $xdata[$cnt][0] = $sensor_name[0];
         $result2->baseFreeRows();
 
         $xdata[$cnt][1] = $myrow[1];
         ++$cnt;
      }
   }

   $result->baseFreeRows();
   return $cnt;
}

?>
