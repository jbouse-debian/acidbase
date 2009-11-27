<?php /*******************************************************************************
** Basic Analysis and Security Engine (BASE)
** Copyright (C) 2004 BASE Project Team
** Copyright (C) 2000 Carnegie Mellon University
**
** (see the file 'base_main.php' for license details)
**
** Project Lead: Kevin Johnson <kjohnson@secureideas.net>
** Built upon work by Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
**
** Purpose: Footer for each page
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net
**
********************************************************************************
*/

if (!isset($noDisplayMenu))
{
    echo ("<div class='mainheadermenu'><table width='90%' border='0'>
        <tr>
            <td class='menuitem'>
                <A class='menuitem' HREF='". $BASE_urlpath ."/base_ag_main.php?ag_action=list'>". _AGMAINT."</A>&nbsp;&nbsp;|&nbsp;&nbsp;
                <A class='menuitem' HREF='". $BASE_urlpath ."/base_maintenance.php'>". _CACHE."</A>&nbsp;&nbsp;|&nbsp;&nbsp;");
    if ($Use_Auth_System == 1)
    {
        echo("<A class='menuitem' HREF='". $BASE_urlpath ."/base_user.php'>". _USERPREF ."</A>&nbsp;&nbsp;|&nbsp;&nbsp;");
    }
    
    echo ("<A class='menuitem' HREF='". $BASE_urlpath ."/admin/index.php'>". _ADMIN ."</A>
            </td>
        </tr>
    </table></div>");
}      
?>


<div class="mainfootertext"><a class="largemenuitem" href="http://sourceforge.net/projects/secureideas" target="_NEW">BASE</a> <?php echo $BASE_VERSION;
echo _FOOTER; ?></div><br>
