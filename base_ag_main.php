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
** Purpose: Maintenance and configuration page for
**          managing Alert Groups (AG)   
**
** Input GET/POST variables
**   - ag_action:
**   - ag_id: 
**   - submit:
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net
**
********************************************************************************
*/
  include("base_conf.php");
  include("$BASE_path/includes/base_constants.inc.php");
  include("$BASE_path/includes/base_include.inc.php");
  include_once("$BASE_path/includes/base_action.inc.php");
  include_once("$BASE_path/base_db_common.php");
  include_once("$BASE_path/base_common.php");
  include_once("$BASE_path/base_qry_common.php");
  include_once("$BASE_path/base_ag_common.php");

  ($debug_time_mode >= 1) ? $et = new EventTiming($debug_time_mode) : '';
  $cs = new CriteriaState("base_ag_main.php");
  $cs->ReadState();
  

  $qs = new QueryState();
  $submit = ImportHTTPVar("submit", VAR_ALPHA | VAR_SPACE, array(_SELECTED, _ALLONSCREEN, _ENTIREQUERY));
  $ag_action = ImportHTTPVar("ag_action", VAR_ALPHA | VAR_USCORE);
  $ag_id = ImportHTTPVar("ag_id", VAR_DIGIT);
  $ag_name = filterSql(ImportHTTPVar("ag_name"));
  $ag_desc = filterSql(ImportHTTPVar("ag_desc"));

   // Check role out and redirect if needed -- Kevin
  $roleneeded = 10000;
  $BUser = new BaseUser();
  if (($BUser->hasRole($roleneeded) == 0) && ($Use_Auth_System == 1))
  {
    header("Location: ". $BASE_urlpath . "/index.php");
  }

  $page_title = _AGMAINTTITLE;
  PrintBASESubHeader($page_title, $page_title, $cs->GetBackLink(), 1);

  /* Connect to the Alert database */
  $db = NewBASEDBConnection($DBlib_path, $DBtype);
  $db->baseDBConnect($db_connect_method,
                     $alert_dbname, $alert_host, $alert_port, $alert_user, $alert_password);

  /* a browsing button was clicked */
  if ( is_numeric($submit) )
  {
    if ( $debug_mode > 0 ) ErrorMessage("Browsing Clicked ($submit)");
    $qs->MoveView($submit);
    $ag_action = "view";
  }
?>

<CENTER>
 <A HREF="base_ag_main.php?ag_action=list"><?php echo _LISTALL;?></A> | 
 <A HREF="base_ag_main.php?ag_action=create"><?php echo _CREATE;?></A> |
 <A HREF="base_ag_main.php?ag_action=view"><?php echo _VIEW;?></A> |
 <A HREF="base_ag_main.php?ag_action=edit"><?php echo _EDIT;?></A> |
 <A HREF="base_ag_main.php?ag_action=delete"><?php echo _DELETE;?></A> |
 <A HREF="base_ag_main.php?ag_action=clear"><?php echo _CLEAR;?></A>
</CENTER>
<HR>

<FORM METHOD="POST" NAME="PacketForm" ACTION="base_ag_main.php">

<?php
  if ( $debug_mode == 1 )
     echo '<TABLE BORDER=1>
             <TR><TD>ag_action</TD><TD>submit</TD><TD>ag_id</TD></TR>
             <TR><TD>'.$ag_action.'</TD><TD>'.$submit.'</TD><TD>'.$ag_id.'</TD></TR>
           </TABLE>';

  $qs->AddValidAction("del_alert");
  $qs->AddValidAction("email_alert");
  $qs->AddValidAction("email_alert2");
  $qs->AddValidAction("clear_alert");

  $qs->AddValidActionOp(_SELECTED);
  $qs->AddValidActionOp(_ALLONSCREEN);
  $qs->AddValidActionOp(_ENTIREQUERY);

  $qs->SetActionSQL("SELECT ag_sid, ag_cid FROM acid_ag_alert WHERE ag_id='".$ag_id."'"); 
  ($debug_time_mode >= 1) ? $et->Mark("Initialization") : '';

  $qs->RunAction($submit, PAGE_QRY_AG, $db);
  ($debug_time_mode >= 1) ? $et->Mark("Alert Action") : '';

  if ( $ag_action == "create" )                                       echo '<H3>'._CREATEGROUPS.'</H3>';
  else if ($ag_action == "view" )                                     echo '<H3>'._VIEWGROUPS.'</H3>';
  else if ($ag_action == "edit" || $ag_action == "save" )             echo '<H3>'._EDITGROUPS.'</H3>';
  else if ($ag_action == "delete" || $ag_action == "delete_confirm" ) echo '<H3>'._DELETEGROUPS.'</H3>';
  else if ($ag_action == "clear" || $ag_action == "clear_confirm" )   echo '<H3>'._CLEARGROUPS.'</H3>';
  else if ($ag_action == "list" )                                     echo '<H3>'._LISTGROUPS.'</H3>';
  else
    $ag_action = "list";
  

  if ( $submit != "" )
  {
     if ( $ag_action == "create" )
     {
         $ag_id = CreateAG($db, $ag_name, $ag_desc);
         $ag_action = "view";
     }
     else if ( $ag_action == "save" )
     {
        $sql = "UPDATE acid_ag SET ag_name='".$ag_name."', ag_desc='".$ag_desc."' ".
               "WHERE ag_id='".$ag_id."'";

        $db->baseExecute($sql, -1, -1, false);
        if ( $db->baseErrorMessage() != "" )
           FatalError(_ERRAGUPDATE);

        $ag_action = "view";
     }
     else if ( $ag_action == "delete_confirm" )
     {
        /* Delete the packet list associated with the AG */
        $sql = "DELETE FROM acid_ag_alert WHERE ag_id='".$ag_id."'";
        $db->baseExecute($sql, -1, -1, false);
        if ( $db->baseErrorMessage() != "" )
           FatalError(_ERRAGPACKETLIST." ".$sql);

        /* Delete the AG */
        $sql = "DELETE FROM acid_ag WHERE ag_id='".$ag_id."'";
        $db->baseExecute($sql, -1, -1, false);
        if ( $db->baseErrorMessage() != "" )
           FatalError(_ERRAGDELETE.$sql);
     }
     else if ( $ag_action == "clear_confirm" )
     {
        /* Delete the packet list associated with the AG */
        $sql = "DELETE FROM acid_ag_alert WHERE ag_id='".$ag_id."'";
        $db->baseExecute($sql, -1, -1, false);
        if ( $db->baseErrorMessage() != "" )
           FatalError(_ERRAGPACKETLIST." ".$sql);
        
        $ag_action = "view";
     }

     if ( $ag_action == "delete_confirm" )
     {
        ErrorMessage("<B>"._AGDELETE."</B>");
        $ag_action = "view";
        $ag_name = $ag_desc = "<I>"._AGDELETEINFO."</I>";
     }
     else
     {
     /* Re-Query the information to print the AG info out */
     if ( $ag_id > 0)
        $sql = "SELECT ag_id, ag_name, ag_desc FROM acid_ag WHERE ag_id='".$ag_id."'";
     else
        $sql = "SELECT ag_id, ag_name, ag_desc FROM acid_ag WHERE ag_name='".$ag_name."'";

     $result = $db->baseExecute($sql, -1, -1, false);
     if ( $db->baseErrorMessage() != "" )
     {
        ErrorMessage(_ERRAGSEARCHINV);
        $submit = "";
     }
     else if ( $result->baseRecordCount() < 1 )
     {
        ErrorMessage(_ERRAGSEARCHNOTFOUND.$sql);
        $submit = "";
     }
     else
     {
        $myrow = $result->baseFetchRow();
        $ag_id = $myrow[0];
        $ag_name = $myrow[1];
        $ag_desc = $myrow[2]; 
     }
     }
  }

  if ( $ag_action == "list" )
  {
     $sql = "SELECT ag_id, ag_name, ag_desc FROM acid_ag";

     $result = $db->baseExecute($sql);
     $num = $result->baseRecordCount();
     if ( $num < 1 )
     {
        echo "<CENTER><B>"._NOALERTGOUPS."</B></CENTER>";
     }
     else
     {
       echo '<TABLE BORDER=1 CELLSPACING=0 PADDING=0 WIDTH="100%">
             <TR>
               <TD CLASS="plfieldhdr">'._ID.'</TD>
               <TD CLASS="plfieldhdr">'._NAME.'</TD>
               <TD CLASS="plfieldhdr">'._NUMALERTS.'</TD>
               <TD CLASS="plfieldhdr">'._DESC.'</TD>
               <TD CLASS="plfieldhdr">'._ACTIONS.'</TD>
              </TR>';
        for ( $i = 0; $i < $num; $i++)
        {
           $myrow = $result->baseFetchRow();

           /* count the number of alerts in the AG */
           $result2 = $db->baseExecute("SELECT count(ag_cid) FROM acid_ag_alert WHERE ag_id='".$myrow[0]."'");
           $myrow2 = $result2->baseFetchRow();
           $num_alerts = $myrow2[0];
           $result2->baseFreeRows();

           echo '<TR><TD CLASS="plfield">
                     <A HREF="base_ag_main.php?ag_action=view&ag_id='.$myrow[0].'&submit=x">'.$myrow[0].'</A></TD>
                     <TD CLASS="plfield">'.$myrow[1].'</TD>
                     <TD CLASS="plfield">'.$num_alerts.'</TD>
                     <TD CLASS="plfield">'.$myrow[2].'</TD>
                     <TD CLASS="plfield"> 
                       <A HREF="base_ag_main.php?ag_action=edit&ag_id='.$myrow[0].'&submit=x">'._EDIT.'</A> |
                       <A HREF="base_ag_main.php?ag_action=delete&ag_id='.$myrow[0].'&submit=x">'._DELETE.'</A> |
                       <A HREF="base_ag_main.php?ag_action=clear&ag_id='.$myrow[0].'&submit=x">'._CLEAR.'</A>
                     </TD>
                 </TR>';
        }
        echo '</TABLE>';
        $result->baseFreeRows();
     }
  }

  if ( $ag_action != "list" )
  {
     echo '<TABLE WIDTH="100%" BORDER=2 class="query">
           <TR>
            <TD WIDTH="10%"><B>ID #</B></TD>
            <TD>';

            if ( $ag_action == "create" && $submit == "")
               echo '&nbsp;<I> '._NOTASSIGN.' </I>&nbsp';
            else if ( $submit == "" )
               echo '<INPUT TYPE="text" NAME="ag_id" VALUE="'.$ag_id.'">';
            else if ( ($ag_action == "view" || $ag_action == "edit" || 
                       $ag_action == "delete" || $ag_action == "clear") &&
                      $submit != "" )
            {
               echo '<INPUT TYPE="hidden" NAME="ag_id" VALUE="'.$ag_id.'">';
               echo $ag_id;
            }

     echo ' </TD>
           <TR>
            <TD VALIGN=TOP><B>'._NAME.'</B></TD>
            <TD>';

            if ( $ag_action == "create" && $submit == "")
               echo '<INPUT TYPE="text" NAME="ag_name" SIZE=40 VALUE="'.$ag_name.'">';
            else if ( $submit == "" )
            {
               echo '<SELECT NAME="ag_name">
                       <OPTION VALUE="">{ AG Name }';
               $sql = "SELECT ag_name FROM acid_ag;";
               $result = $db->baseExecute($sql);
               if ( $result )
               {
                  while ( $myrow = $result->baseFetchRow() )
                      echo '<OPTION VALUE="'.$myrow[0].'">'.$myrow[0];

                  $result->baseFreeRows();
               }

               echo '</SELECT>';
            }
            else if ( $ag_action == "edit" && $submit != "" )
               echo '<INPUT TYPE="text" NAME="ag_name" SIZE=40" VALUE="'.$ag_name.'">';
            else if ( ($ag_action == "view" || $ag_action == "delete" || 
                       $ag_action = "clear") && 
                      $submit != "" )
               echo $ag_name;

     echo ' </TD>';
     
     if ( ($ag_action == "create" && $submit == "") ||
          (($ag_action == "view" || $ag_action == "edit" || 
            $ag_action == "delete" || $ag_action == "clear") && 
          $submit != "" ) )
     {
       echo '
          <TR>
           <TD VALIGN=TOP><B>'._DESC.'</B></TD>
           <TD>';

            if ( $ag_action == "create" && $submit == "" )
               echo '<TEXTAREA NAME="ag_desc" COLS=70 ROWS=4>'.$ag_desc.'</TEXTAREA>';
            else if ( $ag_action == "edit" && $submit != "" )
               echo '<TEXTAREA NAME="ag_desc" COLS=70 ROWS=4>'.$ag_desc.'</TEXTAREA>';
            else if ( ($ag_action == "view" || $ag_action == "delete" || 
                       $ag_action == "clear") && 
                      $submit != "" )
               echo $ag_desc;

       echo '
           </TD>
          </TR>';
     }

     echo '</TABLE>';
 
   /* Print the Appropriate button */
   if ( $submit == "" || $ag_action == "edit" || $ag_action == "delete" || $ag_action == "clear" )
   {
     echo '<CENTER> <FONT>';

     if ( $ag_action == "create" )      $button_text = _CREATEGROUPS;
     else if ( $ag_action == "view" )   $button_text = _VIEWGROUPS;
     else if ( $ag_action == "edit" && $submit == "" )   $button_text = _EDITGROUPS;
     else if ( $ag_action == "edit" && $submit != "" )  
     {  $button_text = _SAVECHANGES;  $ag_action = "save"; }
     else if ( $ag_action == "delete" && $submit == "" )  $button_text = _DELETEGROUPS;
     else if ( $ag_action == "delete" && $submit != "" ) 
     {  $button_text = _CONFIRMDELETE; $ag_action = "delete_confirm";  }
     else if ( $ag_action == "clear" && $submit == "" )  $button_text = _CLEARGROUPS;
     else if ( $ag_action == "clear" && $submit != "" ) 
     {  $button_text = _CONFIRMCLEAR; $ag_action = "clear_confirm";  }

     echo '<INPUT TYPE="submit" NAME="submit" VALUE="'.$button_text.'">';

     echo '</FONT> </CENTER>';
   }

  echo '<INPUT TYPE="hidden" NAME="ag_action" VALUE="'.$ag_action.'">';

  if ( $ag_action == "view" && $submit != "" )
  {
     /* Calculate the Number of Alerts */
     $cnt_sql = "SELECT count(ag_sid) FROM acid_ag_alert WHERE ag_id='".$ag_id."'";

     $save_sql = "SELECT acid_event.sid, acid_event.cid, signature, timestamp, ".
                  "ip_src, ip_dst, ip_proto ".
                  "FROM acid_event ".
                  "LEFT JOIN acid_ag_alert ON acid_event.sid=ag_sid AND acid_event.cid=ag_cid ".
                  "WHERE acid_event.cid > '0' AND ag_id = '".$ag_id."'";

     $printing_ag = true;
     $ag = $ag_id;
     include("$BASE_path/base_qry_sqlcalls.php");
  }
  }

  $qs->SaveState();
 
  /* Export action_arg = current AG ID, so that Actions work */
  ExportHTTPVar($ag_id, "action_arg");

  echo "\n</FORM>\n";
  
  PrintBASESubFooter();

  if ($debug_time_mode >= 1) {
	$et->Mark("Get Query Elements");
  	$et->PrintTiming();
  }

?>
