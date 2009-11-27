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
** Purpose: Determines if a login is needed.  If not, will redirect you
**  to base_main.php
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net
**
********************************************************************************
*/

/* Check to see if the base_conf.php file exists and is big enough...
    if not redirect to the setup/index.php page */
if ( !file_exists( 'base_conf.php' ) || filesize( 'base_conf.php' ) < 10 ) {
        header( 'Location: setup/index.php' );
        exit();
}

include("base_conf.php");
include("$BASE_path/includes/base_include.inc.php");
include_once("$BASE_path/base_db_common.php");

$errorMsg = "";
$displayError = 0;
$noDisplayMenu = 1;

// Redirect to base_main.php if auth system is off
if ( $Use_Auth_System == 0 )
{
    header("Location: base_main.php");
}

if (isset($_POST['submit']))
{
    $debug_mode = 0; // wont login with debug_mode
    $BASEUSER = new BaseUser();
    $user = filterSql($_POST['login']);
    $pwd = filterSql($_POST['password']);

    if (($BASEUSER->Authenticate($user, $pwd)) == 0)
    {
        header("Location: base_main.php");
    } else
    {
        $displayError = 1;
        $errorMsg = _LOGINERROR;
    }
}

?>
<!doctype html public "-//w3c//dtd html 4.0 transitional//en">
<!-- <?php echo(_TITLE . $BASE_VERSION); ?> -->
<HTML>

<HEAD>
  <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=<?php echo(_CHARSET); ?>" />
  <META HTTP-EQUIV="pragma" CONTENT="no-cache">
  <TITLE><?php echo(_TITLE . $BASE_VERSION); ?></TITLE>
  <LINK rel="stylesheet" type="text/css" HREF="styles/<?php echo($base_style); ?>">
</HEAD>
<BODY>
<TABLE WIDTH="100%" BORDER=0 CELLSPACING=0 CELLPADDING=5>
    <TR>
      <TD class="mainheader"> &nbsp </TD>
      <TD class="mainheadertitle">
         <?php echo _TITLE; ?>
      </TD>
    </TR>
</TABLE>
<br>
<?php
    if ($displayError == 1)
    {
        printf("<DIV class='errorMsg' align='CENTER'>" . $errorMsg . "</DIV>");
    }
?>
<form action="index.php" method="post" name="loginform">
    <table width="75%" border=0 cellspacing=0 cellpadding=0 align="center">
        <tr><td align="right" width="50%"><?php echo _FRMLOGIN; ?>&nbsp;</td>
            <td align="left" width="50%"><input type="text" name="login"></td></tr>
        <tr><td align="right"><?php echo _FRMPWD; ?>&nbsp;</td>
            <td align="left"><input type="password" name="password"></td></tr>
        <tr><td colspan=2" align="center"><input type="submit" name="submit" value="Login"><input type="reset" name="reset"></td></tr>
    </table>
</form>
<P>
        <?php
          include("$BASE_path/base_footer.php");
        ?>
</BODY>
</HTML>
