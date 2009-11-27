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
** Purpose: Displays form for graphing
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net
**
********************************************************************************
*/

  echo '<FORM ACTION="base_graph_main.php" METHOD="post">';

  echo '<TABLE WIDTH="100%" BORDER="2" class="query">
          <TR>
           <TD COLSPAN=2>';

  echo '<B>'._CHARTTITLE.'</B> &nbsp;
            <INPUT TYPE="text" NAME="user_chart_title" SIZE="60" VALUE="'.$user_chart_title.'"><BR>';

  echo '<B>'._CHARTTYPE.'</B>&nbsp;
        <SELECT NAME="chart_type">
         <OPTION VALUE=" "  '.chk_select($chart_type, " ").'>'._CHARTTYPES.'
         <OPTION VALUE="1" '.chk_select($chart_type, "1").'>'._CHRTTYPEHOUR.'
         <OPTION VALUE="2" '.chk_select($chart_type, "2").'>'._CHRTTYPEDAY.'
         <!--<OPTION VALUE="3" '.chk_select($chart_type, "3").'>'._CHRTTYPEWEEK.'-->
         <OPTION VALUE="4" '.chk_select($chart_type, "4").'>'._CHRTTYPEMONTH.'
         <!--<OPTION VALUE="5" '.chk_select($chart_type, "5").'>'._CHRTTYPEYEAR.'-->
         <OPTION VALUE="6" '.chk_select($chart_type, "6").'>'._CHRTTYPESRCIP.'
         <OPTION VALUE="7" '.chk_select($chart_type, "7").'>'._CHRTTYPEDSTIP.'
         <OPTION VALUE="8" '.chk_select($chart_type, "8").'>'._CHRTTYPEDSTUDP.'
         <OPTION VALUE="10" '.chk_select($chart_type, "10").'>'._CHRTTYPESRCUDP.'
         <OPTION VALUE="9" '.chk_select($chart_type, "9").'>'._CHRTTYPEDSTPORT.'
         <OPTION VALUE="11" '.chk_select($chart_type, "11").'>'._CHRTTYPESRCPORT.'
         <OPTION VALUE="12" '.chk_select($chart_type, "12").'>'._CHRTTYPESIG.'
         <OPTION VALUE="13" '.chk_select($chart_type, "13").'>'._CHRTTYPESENSOR.'
        </SELECT>';

  // Do you need other periods? Simply add them!
  echo '&nbsp;&nbsp;<b>'._CHARTPERIOD.'</B>&nbsp;
        <SELECT NAME="chart_interval">
         <OPTION VALUE="0"  '.chk_select($chart_interval, "0").'>'._PERIODNO.'
         <OPTION VALUE="7" '.chk_select($chart_interval, "7").'>'._PERIODWEEK.'
         <OPTION VALUE="24" '.chk_select($chart_interval, "24").'>'._PERIODDAY.'
         <OPTION VALUE="168" '.chk_select($chart_interval, "168").'>'._PERIOD168.'
        </SELECT><BR>';

  echo '&nbsp;&nbsp;<B>'._CHARTSIZE.'</B>
        &nbsp;<INPUT TYPE="text" NAME="width" SIZE=4 VALUE="'.$width.'">
        &nbsp;<B>x</B>
        &nbsp;<INPUT TYPE="text" NAME="height" SIZE=4 VALUE="'.$height.'">
        &nbsp;&nbsp;<BR>';

  echo '&nbsp;&nbsp;<B>'._PLOTMARGINS.'</B>
        &nbsp;<INPUT TYPE="text" NAME="pmargin0" SIZE=4 VALUE="'.$pmargin0.'">
        &nbsp;<B>x</B>
        &nbsp;<INPUT TYPE="text" NAME="pmargin1" SIZE=4 VALUE="'.$pmargin1.'">
        &nbsp;<B>x</B>
        &nbsp;<INPUT TYPE="text" NAME="pmargin2" SIZE=4 VALUE="'.$pmargin2.'">
        &nbsp;<B>x</B>
        &nbsp;<INPUT TYPE="text" NAME="pmargin3" SIZE=4 VALUE="'.$pmargin3.'">
        &nbsp;&nbsp;<BR>';

  echo '&nbsp;&nbsp;<B>'._PLOTTYPE.'</B> &nbsp;&nbsp;
            <INPUT TYPE="radio" NAME="chart_style"
                   VALUE="bar" '.chk_check($chart_style, "bar").'> '._TYPEBAR.' &nbsp;&nbsp
            <INPUT TYPE="radio" NAME="chart_style"
                   VALUE="line" '.chk_check($chart_style, "line").'> '._TYPELINE.' &nbsp;&nbsp
            <INPUT TYPE="radio" NAME="chart_style"
                   VALUE="pie" '.chk_check($chart_style, "pie").'> '._TYPEPIE.' ';

  echo '<br><b>'._CHRTBEGIN.'</B>&nbsp;
        <SELECT NAME="chart_begin_hour">
         <OPTION VALUE=" "  '.chk_select($chart_begin_hour, " ").'>'._CHARTHOUR."\n";
        for ( $i = 0; $i <= 23; $i++ )
            echo "<OPTION VALUE=\"$i\" ".chk_select($chart_begin_hour, $i)." >$i\n";

  echo '</SELECT>
        <SELECT NAME="chart_begin_day">
         <OPTION VALUE=" "  '.chk_select($chart_begin_day, " ").'>'._CHARTDAY."\n";
        for ( $i = 1; $i <= 31; $i++ )
            echo "<OPTION VALUE=\"$i\" ".chk_select($chart_begin_day, $i).">$i\n";

  echo '</SELECT>
        <SELECT NAME="chart_begin_month">
         <OPTION VALUE=" "  '.chk_select($chart_begin_month, " ").'>'._CHARTMONTH.'
         <OPTION VALUE="01" '.chk_select($chart_begin_month, "01").'>'._JANUARY.'
         <OPTION VALUE="02" '.chk_select($chart_begin_month, "02").'>'._FEBRUARY.'
         <OPTION VALUE="03" '.chk_select($chart_begin_month, "03").'>'._MARCH.'
         <OPTION VALUE="04" '.chk_select($chart_begin_month, "04").'>'._APRIL.'
         <OPTION VALUE="05" '.chk_select($chart_begin_month, "05").'>'._MAY.'
         <OPTION VALUE="06" '.chk_select($chart_begin_month, "06").'>'._JUNE.'
         <OPTION VALUE="07" '.chk_select($chart_begin_month, "07").'>'._JULY.'
         <OPTION VALUE="08" '.chk_select($chart_begin_month, "08").'>'._AUGUST.'
         <OPTION VALUE="09" '.chk_select($chart_begin_month, "09").'>'._SEPTEMBER.'
         <OPTION VALUE="10" '.chk_select($chart_begin_month, "10").'>'._OCTOBER.'
         <OPTION VALUE="11" '.chk_select($chart_begin_month, "11").'>'._NOVEMBER.'
         <OPTION VALUE="12" '.chk_select($chart_begin_month, "12").'>'._DECEMBER.'
        </SELECT>
        <SELECT NAME="chart_begin_year">'.
        dispYearOptions($chart_begin_year)
        .'</SELECT>';

  echo '<br><b>'._CHRTEND.'</B>&nbsp;&nbsp;&nbsp;&nbsp;
        <SELECT NAME="chart_end_hour">
         <OPTION VALUE=" "  '.chk_select($chart_end_hour, " ").'>'._CHARTHOUR."\n";
        for ( $i = 0; $i <= 23; $i++ )
           echo "<OPTION VALUE=$i ".chk_select($chart_end_hour, $i).">$i\n";

  echo '</SELECT>
        <SELECT NAME="chart_end_day">
         <OPTION VALUE=" "  '.chk_select($chart_end_day, " ").'>'._CHARTDAY."\n";
        for ( $i = 1; $i <= 31; $i++ )
           echo "<OPTION VALUE=$i ".chk_select($chart_end_day, $i).">$i\n";

  echo '</SELECT>
        <SELECT NAME="chart_end_month">
         <OPTION VALUE=" "  '.chk_select($chart_end_month, " ").'>'._CHARTMONTH.'
         <OPTION VALUE="01" '.chk_select($chart_end_month, "01").'>'._JANUARY.'
         <OPTION VALUE="02" '.chk_select($chart_end_month, "02").'>'._FEBRUARY.'
         <OPTION VALUE="03" '.chk_select($chart_end_month, "03").'>'._MARCH.'
         <OPTION VALUE="04" '.chk_select($chart_end_month, "04").'>'._APRIL.'
         <OPTION VALUE="05" '.chk_select($chart_end_month, "05").'>'._MAY.'
         <OPTION VALUE="06" '.chk_select($chart_end_month, "06").'>'._JUNE.'
         <OPTION VALUE="07" '.chk_select($chart_end_month, "07").'>'._JULY.'
         <OPTION VALUE="08" '.chk_select($chart_end_month, "08").'>'._AUGUST.'
         <OPTION VALUE="09" '.chk_select($chart_end_month, "09").'>'._SEPTEMBER.'
         <OPTION VALUE="10" '.chk_select($chart_end_month, "10").'>'._OCTOBER.'
         <OPTION VALUE="11" '.chk_select($chart_end_month, "11").'>'._NOVEMBER.'
         <OPTION VALUE="12" '.chk_select($chart_end_month, "12").'>'._DECEMBER.'
        </SELECT>
        <SELECT NAME="chart_end_year">'.
        dispYearOptions($chart_end_year)
        .'</SELECT>';

  echo '<INPUT TYPE="submit" NAME="submit" VALUE="'._GRAPHALERTS.'"><BR>
        &nbsp;&nbsp; <BR>
        </TD></TR>';

  echo '<TR><TD>
  <ul id="zMenu">
<li><a href="#">'._AXISCONTROLS.'</a>
  <ul>
        <TABLE WIDTH="100%" BORDER="1">
        <TR>
         <TD ALIGN="CENTER" WIDTH="50%"><B>'._CHRTX.'</B></TD>
         <TD ALIGN="CENTER" WIDTH="50%"><B>'._CHRTY.'</B></TD>
        </TR>
        <TR>
         <TD>
           <B>'._CHRTDS.'</B> &nbsp;
           <SELECT NAME="data_source">
           <OPTION VALUE=" " '.chk_select($data_source, " ").'>{ data source (AG) }';

           $temp_sql = "SELECT ag_id, ag_name FROM acid_ag";
           $tmp_result = $db->baseExecute($temp_sql);
           if ( ( $tmp_result ) )
           {
              while ( $myrow = $tmp_result->baseFetchRow() )
                echo '<OPTION VALUE="'.$myrow[0].'" '.chk_select($data_source, $myrow[0]).'>'.
                     '['.$myrow[0].'] '.$myrow[1];

              $tmp_result->baseFreeRows();
           }

           echo '</SELECT><BR>'.
                 '<B>'._CHRTMINTRESH.' ( &gt;= ):</B>
                 <INPUT TYPE="text" NAME="min_size" SIZE="5" VALUE='.$min_size.'>
                 &nbsp;&nbsp;
                 <BR>
                 <INPUT TYPE="checkbox" NAME="rotate_xaxis_lbl" VALUE="1" '.
                   chk_check($rotate_xaxis_lbl, "1").'>
                 &nbsp;
                 <B>'._CHRTROTAXISLABEL.'</B><BR>
                 <INPUT TYPE="checkbox" NAME="yaxis_grid" VALUE="1"  '.
                   chk_check($xaxis_grid, "1").'>
                  &nbsp;
                 <B>'._CHRTSHOWX.'</B><BR>
                 <B>'._CHRTDISPLABELX.'
                 <INPUT TYPE="text" NAME="xaxis_label_inc" SIZE=4 VALUE='.$xaxis_label_inc.'>
                 &nbsp; '._CHRTDATAPOINTS.'
         </TD>
         <TD VALIGN="top">
           <INPUT TYPE="checkbox" NAME="yaxis_scale" VALUE="1" '.
             chk_check($yaxis_scale, "1").'>&nbsp;
           <B>'._CHRTYLOG.'</B><BR>
           <INPUT TYPE="checkbox" NAME="yaxis_grid" VALUE="1"  '.
             chk_check($yaxis_grid, "1").'>&nbsp;
           <B>'._CHRTYGRID.'</B>
         </TD>
        </TR>
        </TABLE>
        </ul></li>
        </TD></TR>
     </TABLE>';

  echo '</FORM><P><HR>';
echo '
 <!-- ************ JavaScript for Hiding Details ******************** -->
 <script type="text/javascript">
// <![CDATA[
function loopElements(el,level){
        for(var i=0;i<el.childNodes.length;i++){
                //just want LI nodes:
                if(el.childNodes[i] && el.childNodes[i]["tagName"] && el.childNodes[i].tagName.toLowerCase() == "li"){
                        //give LI node a className
                        el.childNodes[i].className = "zMenu"+level
                        //Look for the A and if it has child elements (another UL tag)
                        childs = el.childNodes[i].childNodes
                        for(var j=0;j<childs.length;j++){
                                temp = childs[j]
                                if(temp && temp["tagName"]){
                                        if(temp.tagName.toLowerCase() == "a"){
                                                //found the A tag - set class
                                                temp.className = "zMenu"+level
                                                //adding click event
                                                temp.onclick=showHide;
                                        }else if(temp.tagName.toLowerCase() == "ul"){
                                                //Hide sublevels
                                                temp.style.display = "none"
                                                //Set class
                                                temp.className= "zMenu"+level
                                                //Recursive - calling self with new found element - go all the way through
                                                loopElements(temp,level +1)
                                        }
                                }
                        }
                }
        }
}

var menu = document.getElementById("zMenu") //get menu div
menu.className="zMenu"+0 //Set class to top level
loopElements(menu,0) //function call

function showHide(){
        //from the LI tag check for UL tags:
        el = this.parentNode
        //Loop for UL tags:
        for(var i=0;i<el.childNodes.length;i++){
                temp = el.childNodes[i]
                if(temp && temp["tagName"] && temp.tagName.toLowerCase() == "ul"){
                        //Check status:
                        if(temp.style.display=="none"){
                                temp.style.display = ""
                        }else{
                                temp.style.display = "none"
                        }
                }
        }
        return false
}
// ]]>
</script>
';
?>


