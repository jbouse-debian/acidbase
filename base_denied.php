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
** Purpose: Page to send people to if they are not logged in
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net
**
********************************************************************************
*/
?>
<!doctype html public "-//w3c//dtd html 4.0 transitional//en">
<!-- Basic Analysis and Security Engine (BASE) -->
<HTML>

<HEAD>
  <META HTTP-EQUIV="pragma" CONTENT="no-cache">
  <TITLE>Basic Analysis and Security Engine (BASE)</TITLE>
  <LINK rel="stylesheet" type="text/css" HREF="styles/base_style.css">
</HEAD>
<BODY>
<TABLE WIDTH="100%" BORDER=0 CELLSPACING=0 CELLPADDING=5>
    <TR>
      <TD class="mainheader"> &nbsp </TD>
      <TD class="mainheadertitle">
         Basic Analysis and Security Engine (BASE)
      </TD>
    </TR>
</TABLE>
<br>
You must have a valid log in to use this system!
<a href="index.php">Go to Login!</a>
<P>
        <?php
          include("base_footer.php");
        ?>
</BODY>
</HTML>
