<?php
/*******************************************************************************
** Basic Analysis and Security Engine (BASE)
** Copyright (C) 2004 BASE Project Team
** Copyright (C) 2000 Carnegie Mellon University
**
** (see the file 'base_main.php' for license details)
**
** Project Leads: Kevin Johnson <kjohnson@secureideas.net>
**                Sean Muller <samwise_diver@users.sourceforge.net>
** Built upon work by Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
**
** Purpose: Input GET/POST variables
**   - submit:
**   - time:
**   - time_sep:
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net
**
********************************************************************************
*/

  include ("base_conf.php");
  include ("$BASE_path/includes/base_constants.inc.php");
  include ("$BASE_path/includes/base_include.inc.php");
  include_once ("$BASE_path/base_db_common.php");
  include_once ("$BASE_path/base_common.php");
  include_once ("$BASE_path/base_graph_common.php");

  ($debug_time_mode >= 1) ? $et = new EventTiming($debug_time_mode) : '';
  $cs = new CriteriaState("base_stat_alerts.php");
  $cs->ReadState();
  
  $submit = ImportHTTPVar("submit", VAR_ALPHA | VAR_SPACE);

  /**
  * Set default values if the submit button hasnt been pressed
  */
  if ( $submit == "" )
  {
     	$height 		= 400;
     	$width 			= 600;
     	$pmargin0 		= 50;
     	$pmargin1 		= 50;
     	$pmargin2 		= 70;
     	$pmargin3 		= 80;
     	$user_chart_title	= _CHRTTITLE;
     	$min_size 		= 0;
     	$rotate_xaxis_lbl 	= 0;
     	$xaxis_label_inc 	= 1;
     	$yaxis_scale 		= 0;
     	$chart_style 		= "bar";
     	$use_alerts 		= 0;
     	$xaxis_grid 		= 0;
     	$yaxis_grid 		= 1;
  } else {
	/**
	* Otherwise, retrieve the data from the submit and
	* store it in local variables for use later
	*/
  	$height 		= ImportHTTPVar("height", VAR_DIGIT);
  	$width 			= ImportHTTPVar("width", VAR_DIGIT);  
  	$pmargin0 		= ImportHTTPVar("pmargin0", VAR_DIGIT);
  	$pmargin1 		= ImportHTTPVar("pmargin1", VAR_DIGIT);
  	$pmargin2 		= ImportHTTPVar("pmargin2", VAR_DIGIT);
  	$pmargin3 		= ImportHTTPVar("pmargin3", VAR_DIGIT);
  	$user_chart_title 	= ImportHTTPVar("user_chart_title", VAR_ALPHA | VAR_SPACE);
  	$min_size 		= ImportHTTPVar("min_size", VAR_DIGIT);
  	$rotate_xaxis_lbl 	= ImportHTTPVar("rotate_xaxis_lbl", VAR_DIGIT);
  	$xaxis_label_inc 	= ImportHTTPVar("xaxis_label_inc", VAR_DIGIT);
 	$yaxis_scale 		= ImportHTTPVar("yaxis_scale", VAR_DIGIT);
  	$chart_style 		= ImportHTTPVar("chart_style", VAR_ALPHA);
  	$xaxis_grid 		= ImportHTTPVar("xaxis_grid", VAR_DIGIT);
  	$yaxis_grid 		= ImportHTTPVar("yaxis_grid", VAR_DIGIT);
  }

  $data_source 		= ImportHTTPVar("data_source", VAR_DIGIT);
  $chart_type 		= ImportHTTPVar("chart_type", VAR_DIGIT);
  $chart_interval 	= ImportHTTPVar("chart_interval", VAR_DIGIT);
  $chart_begin_hour 	= ImportHTTPVar("chart_begin_hour", VAR_DIGIT);
  $chart_begin_month	= ImportHTTPVar("chart_begin_month", VAR_DIGIT);
  $chart_begin_day 	= ImportHTTPVar("chart_begin_day", VAR_DIGIT);
  $chart_begin_year 	= ImportHTTPVar("chart_begin_year", VAR_DIGIT);
  $chart_end_hour 	= ImportHTTPVar("chart_end_hour", VAR_DIGIT);
  $chart_end_month 	= ImportHTTPVar("chart_end_month", VAR_DIGIT);
  $chart_end_day 	= ImportHTTPVar("chart_end_day", VAR_DIGIT);
  $chart_end_year 	= ImportHTTPVar("chart_end_year", VAR_DIGIT);
  $aggregate_type 	= ImportHTTPVar("aggregate_type", VAR_DIGIT);

   // Check role out and redirect if needed -- Kevin
  $roleneeded = 10000;
  $BUser = new BaseUser();
  if (($BUser->hasRole($roleneeded) == 0) && ($Use_Auth_System == 1))
    base_header("Location: ". $BASE_urlpath . "/index.php");

  $page_title = _GRAPHALERTDATA;
  PrintBASESubHeader($page_title, $page_title, $cs->GetBackLink(), 1);

// Check if Image_Graph install is ok -- Alejandro
  VerifyGraphingLib();  

  /* Connect to the Alert database */
  $db = NewBASEDBConnection($DBlib_path, $DBtype);
  $db->baseDBConnect($db_connect_method,
                     $alert_dbname, $alert_host, $alert_port, $alert_user, $alert_password);

  if ( $event_cache_auto_update == 1 )  UpdateAlertCache($db);

  if ( ini_get("safe_mode") != true )
     set_time_limit($max_script_runtime);

  include("$BASE_path/base_graph_form.php");

  $data_pnt_cnt = 0;
  /* Error Conditions */
   if ( $submit != "" && $chart_type == " " )
     echo '<B>'._ERRCHRTNOTYPE.'</B>.';

  /* Calculate the data set */
  else if ($submit != "")
  {
     if ( $data_source == " " )
     {
        ErrorMessage(_ERRNOAGSPEC);
        $data_source = NULL;
     }

     unset($xdata);
     unset($xlabel);

     if ( $debug_mode > 1 )  echo "<H3>"._CHRTDATAIMPORT."...</H3>";

     /* Building Criteria */
     $time_constraint = ProcessChartTimeConstraint($chart_begin_hour, 
                                                   $chart_begin_day, 
                                                   $chart_begin_month, 
                                                   $chart_begin_year,
                                                   $chart_end_hour,  
                                                   $chart_end_day,  
                                                   $chart_end_month, 
                                                   $chart_end_year );

     $criteria = array(2);
     if ( $data_source != NULL )
     {
        $criteria[0] = "LEFT JOIN acid_ag_alert ".
                      "ON (acid_event.sid=acid_ag_alert.ag_sid AND acid_event.cid=acid_ag_alert.ag_cid) ";
        $criteria[1] = "acid_ag_alert.ag_id = $data_source";

        if ( $time_constraint != NULL )
           $criteria[1] = $criteria[1].$time_constraint; 
     }
     else
     {
        $criteria[0] = "";
        // $criteria[1] = "acid_event.sid > 0 ".$time_constraint;
        $criteria[1] = " 1 = 1 ".$time_constraint;
     }

     if ( $debug_mode > 0 ) 
     {
       echo "<H3>Chart criteria</H3><PRE>";
       print_r($criteria);
       echo "</PRE>";
     }

     switch ($chart_type)
     {
         case 1:
         case 2:
         case 3:
         case 4:
         case 5:
         {
            $chart_title = _CHRTTIMEVNUMBER;
            $xaxis_label = _CHRTTIME;
            $yaxis_label = _CHRTALERTOCCUR;
            $data_pnt_cnt = GetTimeDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
            $chart_title = $chart_title."\n ( ".$xdata[0][0]." - ".$xdata[count($xdata)-1][0]." )";
            break;
         }
         case 6:  // Src. IP vs. Num Alerts
         {
            $chart_title = _CHRTSIPNUMBER;
            $xaxis_label = _CHRTSIP;
            $yaxis_label = _CHRTALERTOCCUR;

            $data_pnt_cnt = GetIPDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
            break;
         }
         case 7:  // Dst. IP vs. Num Alerts
         {
            $chart_title = _CHRTDIPALERTS;
            $xaxis_label = _CHRTDIP;
            $yaxis_label = _CHRTALERTOCCUR;

            $data_pnt_cnt = GetIPDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
            break;
         }
         case 8:  // UDP Port vs. Num Alerts 
         {
            $chart_title = _CHRTUDPPORTNUMBER;
            $xaxis_label = _CHRTDUDPPORT;
            $yaxis_label = _CHRTALERTOCCUR;

            $data_pnt_cnt = GetPortDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
            break;
         }
         case 10:  // UDP Port vs. Num Alerts 
         {
            $chart_title = _CHRTSUDPPORTNUMBER;
            $xaxis_label = _CHRTSUDPPORT;
            $yaxis_label = _CHRTALERTOCCUR;

            $data_pnt_cnt = GetPortDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
            break;
         }
         case 9:  // TCP Port vs. Num Alerts 
         {
            $chart_title = _CHRTPORTDESTNUMBER;
            $xaxis_label = _CHRTPORTDEST;
            $yaxis_label = _CHRTALERTOCCUR;

            $data_pnt_cnt = GetPortDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
            break;
         }
         case 11:  // TCP Port vs. Num Alerts 
         {
            $chart_title = _CHRTPORTSRCNUMBER;
            $xaxis_label = _CHRTPORTSRC;
            $yaxis_label = _CHRTALERTOCCUR;

            $data_pnt_cnt = GetPortDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
            break;
         }
         case 12:  // Classification vs. Num Alerts 
         {
            $chart_title = _CHRTSIGNUMBER;
            $xaxis_label = _CHRTCLASS;
            $yaxis_label = _CHRTALERTOCCUR;

            $data_pnt_cnt = GetClassificationDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
            break;
         }
         case 13:  // Sensor vs. Num Alerts 
         {
            $chart_title = _CHRTSENSORNUMBER;
            $xaxis_label = _SENSOR;
            $yaxis_label = _CHRTALERTOCCUR;

            $data_pnt_cnt = GetSensorDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
            break;
         }
     }

     if ( $data_pnt_cnt > 0 )
     {
        if ( $debug_mode > 0 )
        {
           echo "chart_type = $chart_type<BR>
                 data_source = $data_source<BR>";
           echo "<H3>"._CHRTHANDLEPERIOD."...</H3>\n";
        }

        if ( $chart_interval ) {
          // set up array
          for ( $i = 0; $i < $chart_interval; $i++ ) {
            $chart_array [$i][0] = $i;
            $chart_array [$i][1] = 0;
          }
          // loading data
          for ( $i = 0; $i < count ($xdata); $i++ ) {
            $chart_array [ $i % $chart_interval ][1] += $xdata [$i][1];
          }
          // set up xdata
          $xdata = $chart_array;
        }

        if ( $debug_mode > 0 )   
           echo "<H3>"._CHRTDUMP." $xaxis_label_inc)</H3>";
        $data_str = "";
        $data_lbl_str = "";
        for ( $i = 0; $i < count($xdata); $i++)
        {
          if ( $debug_mode > 0 )
             echo $i." -- ".$xdata[$i][0]." - ".$xdata[$i][1]."<BR>";
        
          /* Apply the X-Axis label clean-up -- 
           * only write every N axis labels (erase the rest) 
           */
          if ( ($i % $xaxis_label_inc ) != 0 )
             $xdata[$i][0] = "";
        }

        if ( $debug_mode > 0 )  echo "<H3>"._CHRTDRAW." ($width x $height)</H3>";

        ($debug_time_mode >= 1) ? $et->Mark("Extracting data") : '';
        echo '<CENTER>
              <TABLE BGCOLOR="#000000" CELLSPACING=0 CELLPADDING=2 BORDER=0>
              <TR>
              <TD>';

        $_SESSION['xdata'] = $xdata;
        echo "<CENTER>
              <IMG SRC=\"base_graph_display.php?width=$width&amp;height=$height".
                      "&amp;pmargin0=$pmargin0&pmargin1=$pmargin1".
                      "&amp;pmargin2=$pmargin2&pmargin3=$pmargin3".
                      "&amp;title=".rawurlencode($user_chart_title."\n".$chart_title).
                      "&amp;xaxis_label=".rawurlencode($xaxis_label).
                      "&amp;yaxis_label=".rawurlencode($yaxis_label).
                      "&amp;yaxis_scale=".rawurlencode($yaxis_scale).
                      "&amp;rotate_xaxis_lbl=".rawurlencode($rotate_xaxis_lbl).
                      "&amp;yaxis_scale=".$yaxis_scale.
                      "&amp;xaxis_grid=".$xaxis_grid.
                      "&amp;yaxis_grid=".$yaxis_grid.
                      "&amp;chart_type=".$chart_type.
                      "&amp;style=".$chart_style."\"></CENTER>";

        echo '</TD>
              </TR>
              </TABLE>
              </CENTER>';
        ($debug_time_mode >= 1) ? $et->Mark("Rendering graph") : '';
      }
      else
        ErrorMessage(_ERRCHRTNODATAPOINTS);
   }

  ($debug_time_mode >= 1) ? $et->PrintTiming() : '';

  PrintBASESubFooter();
  echo "</body>\r\n</html>";
?>

