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
** Purpose: English language file
**      To translate into another language, copy this file and
**          translate each variable into your chosen language.
**          Leave any variable not translated so that the system will have
**          something to display.
********************************************************************************
** Authors:
********************************************************************************
** Kevin Johnson <kjohnson@secureideas.net>
** Joel Esler <joelesler@users.sourceforge.net>
********************************************************************************
*/

//locale
DEFINE('_LOCALESTR1', 'eng_ENG.ISO8859-1'); //NEW
DEFINE('_LOCALESTR2', 'eng_ENG.utf-8'); //NEW
DEFINE('_LOCALESTR3', '����'); //NEW
DEFINE('_STRFTIMEFORMAT','%a %B %d, %Y %H:%M:%S'); //NEW - see strftime() sintax

//common phrases
DEFINE('_CHARSET','UTF-8');
DEFINE('_TITLE','�w���򥻤��R����(BASE) '.$BASE_installID);
DEFINE('_FRMLOGIN','�ϥΪ̵n�J:');
DEFINE('_FRMPWD','�K�X:');
DEFINE('_SOURCE','�ӷ�');
DEFINE('_SOURCENAME','�ӷ��W��');
DEFINE('_DEST','�ئa');
DEFINE('_DESTNAME','�ئa�W��');
DEFINE('_SORD','�ӷ��Υئa');
DEFINE('_EDIT','�s��');
DEFINE('_DELETE','�R��');
DEFINE('_ID','�ѧO�X');
DEFINE('_NAME','�W��');
DEFINE('_INTERFACE','����');
DEFINE('_FILTER','�L�o��');
DEFINE('_DESC','����');
DEFINE('_LOGIN','�n�J');
DEFINE('_ROLEID','���� ID');
DEFINE('_ENABLED','�ҥ�');
DEFINE('_SUCCESS','�w���\ ');
DEFINE('_SENSOR','������');
DEFINE('_SENSORS','Sensors'); //NEW
DEFINE('_SIGNATURE','�S�x');
DEFINE('_TIMESTAMP','�ɶ��W�O');
DEFINE('_NBSOURCEADDR','�ӷ�&nbsp;��}');
DEFINE('_NBDESTADDR','�ئa&nbsp;��}');
DEFINE('_NBLAYER4','�q�T&nbsp;4&nbsp;�h��');
DEFINE('_PRIORITY','�u������');
DEFINE('_EVENTTYPE','�ƥ󫬺A');
DEFINE('_JANUARY','�@��');
DEFINE('_FEBRUARY','�G��');
DEFINE('_MARCH','�T��');
DEFINE('_APRIL','�|��');
DEFINE('_MAY','����');
DEFINE('_JUNE','����');
DEFINE('_JULY','�C��');
DEFINE('_AUGUST','�K��');
DEFINE('_SEPTEMBER','�E��');
DEFINE('_OCTOBER','�Q��');
DEFINE('_NOVEMBER','�Q�@��');
DEFINE('_DECEMBER','�Q�G��');
DEFINE('_LAST','�̫�');
DEFINE('_FIRST','�̦�'); //NEW
DEFINE('_TOTAL','�`��'); //NEW
DEFINE('_ALERT','ĵ�i��');
DEFINE('_ADDRESS','��}');
DEFINE('_UNKNOWN','����');
DEFINE('_AND','AND'); //NEW
DEFINE('_OR','OR'); //NEW
DEFINE('_IS','is'); //NEW
DEFINE('_ON','on'); //NEW
DEFINE('_IN','in'); //NEW
DEFINE('_ANY','any'); //NEW
DEFINE('_NONE','�L'); //NEW
DEFINE('_HOUR','Hour'); //NEW
DEFINE('_DAY','Day'); //NEW
DEFINE('_MONTH','Month'); //NEW
DEFINE('_YEAR','Year'); //NEW
DEFINE('_ALERTGROUP','ĵ�i�s��'); //NEW
DEFINE('_ALERTTIME','ĵ�i�ɶ�'); //NEW
DEFINE('_CONTAINS','�]�t'); //NEW
DEFINE('_DOESNTCONTAIN','���]�t'); //NEW
DEFINE('_SOURCEPORT','�ӷ��q�T��'); //NEW
DEFINE('_DESTPORT','�ئa�q�T��'); //NEW
DEFINE('_HAS','��'); //NEW
DEFINE('_HASNOT','���㦳'); //NEW
DEFINE('_PORT','�q�T��'); //NEW
DEFINE('_FLAGS','�X��'); //NEW
DEFINE('_MISC','��L'); //NEW
DEFINE('_BACK','Back'); //NEW
DEFINE('_DISPYEAR','{ �~ }'); //NEW
DEFINE('_DISPMONTH','{ �� }'); //NEW
DEFINE('_DISPHOUR','{ �� }'); //NEW
DEFINE('_DISPDAY','{ �� }'); //NEW
DEFINE('_DISPTIME','{ �ɶ� }'); //NEW
DEFINE('_ADDADDRESS','�Φ�}'); //NEW
DEFINE('_ADDIPFIELD','�� IP ���'); //NEW
DEFINE('_ADDTIME','�W�[�ɶ�'); //NEW
DEFINE('_ADDTCPPORT','�W�[ TCP �q�T��'); //NEW
DEFINE('_ADDTCPFIELD','�W�[ TCP �d��'); //NEW
DEFINE('_ADDUDPPORT','�W�[ UDP �q�T��'); //NEW
DEFINE('_ADDUDPFIELD','�W�[ UDP �d��'); //NEW
DEFINE('_ADDICMPFIELD','�W�[ ICMP �d��'); //NEW
DEFINE('_ADDPAYLOAD','�W�[ �ʥ]���e'); //NEW
DEFINE('_MOSTFREQALERTS','�̱`�o�ͪ�ĵ�i��'); //NEW
DEFINE('_MOSTFREQPORTS','�̱`�o�ͪ��q�T��'); //NEW
DEFINE('_MOSTFREQADDRS','�̱`�o�ͪ� IP ��}'); //NEW
DEFINE('_LASTALERTS','�̫᪺ĵ�i'); //NEW
DEFINE('_LASTPORTS','�̫᪺�q�T��'); //NEW
DEFINE('_LASTTCP','�̫᪺ TCP ĵ�i'); //NEW
DEFINE('_LASTUDP','�̫᪺ UDP ĵ�i'); //NEW
DEFINE('_LASTICMP','�̫᪺ ICMP ĵ�i'); //NEW
DEFINE('_QUERYDB','�d�� DB'); //NEW
DEFINE('_QUERYDBP','�d��+DB'); //NEW - Equals to _QUERYDB where spaces are '+'s. 
                                //Should be something like: DEFINE('_QUERYDBP',str_replace(" ", "+", _QUERYDB));
DEFINE('_SELECTED','�ҿ�w��'); //NEW
DEFINE('_ALLONSCREEN','�����b�ù��W��'); //NEW
DEFINE('_ENTIREQUERY','�i�J�d��'); //NEW
DEFINE('_OPTIONS','�ﶵ'); //NEW
DEFINE('_LENGTH','����'); //NEW
DEFINE('_CODE','�X'); //NEW
DEFINE('_DATA','���'); //NEW
DEFINE('_TYPE','���A'); //NEW
DEFINE('_NEXT','�U�@��'); //NEW
DEFINE('_PREVIOUS','�e�@��'); //NEW

//Menu items
DEFINE('_HOME','����');
DEFINE('_SEARCH','�d��');
DEFINE('_AGMAINT','ĵ�i�s�պ��@');
DEFINE('_USERPREF','�ϥΪ̰ѼƳ]�w');
DEFINE('_CACHE','�֨� & ���A');
DEFINE('_ADMIN','�޲z');
DEFINE('_GALERTD','ø�Xĵ�i���');
DEFINE('_GALERTDT','ø�Xĵ�i�����ɶ�');
DEFINE('_USERMAN','�ϥΪ̺޲z');
DEFINE('_LISTU','�C�X�ϥΪ�');
DEFINE('_CREATEU','�إߨϥΪ�');
DEFINE('_ROLEMAN','����޲z');
DEFINE('_LISTR','�C�X����');
DEFINE('_CREATER','�إߨ���');
DEFINE('_LISTALL','�C�X����');
DEFINE('_CREATE','�إ�');
DEFINE('_VIEW','���');
DEFINE('_CLEAR','�M��');
DEFINE('_LISTGROUPS','�C�X�s��');
DEFINE('_CREATEGROUPS','�إ߸s��');
DEFINE('_VIEWGROUPS','��ܸs��');
DEFINE('_EDITGROUPS','�s��s��');
DEFINE('_DELETEGROUPS','�R���s��');
DEFINE('_CLEARGROUPS','�M���s��');
DEFINE('_CHNGPWD','�ܧ�K�X');
DEFINE('_DISPLAYU','��ܨϥΪ�');

//base_footer.php
DEFINE('_FOOTER','(by <A class="largemenuitem" href="mailto:base@secureideas.net">Kevin Johnson</A> and the <A class="largemenuitem" href="http://sourceforge.net/project/memberlist.php?group_id=103348">BASE Project Team</A><BR>Built on ACID by Roman Danyliw ���� <a href="mailto:js547441@ms15.hinet.net">Johnson Chiang</a>  )');

//index.php --Log in Page
DEFINE('_LOGINERROR','�ϥΪ̤��s�b�αz���K�X�����T!<br>�ЦA�դ@��');

// base_main.php
DEFINE('_MOSTRECENT','�̪� ');
DEFINE('_MOSTFREQUENT','�̱`�X�{ ');
DEFINE('_ALERTS',' ĵ�i��:');
DEFINE('_ADDRESSES',' ��}');
DEFINE('_ANYPROTO','����q�T��w');
DEFINE('_UNI','��@');
DEFINE('_LISTING','�C��');
DEFINE('_TALERTS','���Ѫ�ĵ�i��: ');
DEFINE('_SOURCEIP','�ӷ� IP'); //NEW
DEFINE('_DESTIP','�ئa IP'); //NEW
DEFINE('_L24ALERTS','�̪� 24 �p��ĵ�i��: ');
DEFINE('_L72ALERTS','�̪� 72 �p��ĵ�i��: ');
DEFINE('_UNIALERTS',' �涵ĵ�i��');
DEFINE('_LSOURCEPORTS','�̪�ӷ��q�T���: ');
DEFINE('_LDESTPORTS','�̪�ئa�q�T���: ');
DEFINE('_FREGSOURCEP','�̱`�X�{�ӷ��q�T���: ');
DEFINE('_FREGDESTP','�̱`�X�{�ئa�q�T���: ');
DEFINE('_QUERIED','�d�ߦ�');
DEFINE('_DATABASE','��Ʈw:');
DEFINE('_SCHEMAV','Schema ����:');
DEFINE('_TIMEWIN','�ɶ����j:');
DEFINE('_NOALERTSDETECT','�S��ĵ�i�Q�˴��X��');
DEFINE('_USEALERTDB','�ϥ�ĵ�i��Ʈw'); //NEW
DEFINE('_USEARCHIDB','�ϥ��k�ɸ�Ʈw'); //NEW
DEFINE('_TRAFFICPROBPRO','�H�q�T��w���ǿ鷧�p'); //NEW

//base_auth.inc.php
DEFINE('_ADDEDSF','�s�W���\ ');
DEFINE('_NOPWDCHANGE','�L�k�ܧ�z���K�X: ');
DEFINE('_NOUSER','�ϥΪ̤��s�b!');
DEFINE('_OLDPWD','��J���±K�X�P�O�����۲�!');
DEFINE('_PWDCANT','�L�k�ܧ�z���K�X: ');
DEFINE('_PWDDONE','�z���K�X�w�g�ܧ�!');
DEFINE('_ROLEEXIST','����w�g�s�b');
DEFINE('_ROLEIDEXIST','�����ѧO�X�w�g�s�b');
DEFINE('_ROLEADDED','����s�W���\ ');

//base_roleadmin.php
DEFINE('_ROLEADMIN','�򥻨���޲z');
DEFINE('_FRMROLEID','�����ѧO�X:');
DEFINE('_FRMROLENAME','����W��:');
DEFINE('_FRMROLEDESC','����:');
DEFINE('_UPDATEROLE','��s����'); //NEW

//base_useradmin.php
DEFINE('_USERADMIN','�򥻨ϥΪ̺޲z');
DEFINE('_FRMFULLNAME','���W:');
DEFINE('_FRMROLE','����:');
DEFINE('_FRMUID','�ϥΪ��ѧO�X:');
DEFINE('_SUBMITQUERY','�T�{�e�X�d��'); //NEW
DEFINE('_UPDATEUSER','��s�ϥΪ�'); //NEW

//admin/index.php
DEFINE('_BASEADMIN','�򥻺޲z');
DEFINE('_BASEADMINTEXT','�Цۥ�������.');

//base_action.inc.php
DEFINE('_NOACTION','�bĵ�i�Ƥ��S���ʧ@�Q���w');
DEFINE('_INVALIDACT',' �O�@�Ӥ��X�k���ʧ@');
DEFINE('_ERRNOAG','��S�����wAG�ɤ���W�[ĵ�i��');
DEFINE('_ERRNOEMAIL','��q�l�l���}�S�����w�ɤ���۶l��ǰeĵ�i');
DEFINE('_ACTION','�ʧ@');
DEFINE('_CONTEXT','���e');
DEFINE('_ADDAGID','�W�[ �� ĵ�i�s�� (�H�ѧO�X)');
DEFINE('_ADDAG','�s�W-ĵ�i�s��');
DEFINE('_ADDAGNAME','�s�W �� ĵ�i�s�� (�H�W��)');
DEFINE('_CREATEAG','�إ� ĵ�i�s�� (�H�W��)');
DEFINE('_CLEARAG','��ĵ�i�s�ղM��');
DEFINE('_DELETEALERT','�R��ĵ�i�s�ռ�');
DEFINE('_EMAILALERTSFULL','�q�l�l��ĵ�i (����)');
DEFINE('_EMAILALERTSSUMM','�q�l�l��ĵ�i (�K�n)');
DEFINE('_EMAILALERTSCSV','�q�l�l��ĵ�i (csv)');
DEFINE('_ARCHIVEALERTSCOPY','�ʦsĵ�i (�ƻs)');
DEFINE('_ARCHIVEALERTSMOVE','�ʦsĵ�i (�h��)');
DEFINE('_IGNORED','�w���� ');
DEFINE('_DUPALERTS',' ĵ�i����');
DEFINE('_ALERTSPARA',' ĵ�i��');
DEFINE('_NOALERTSSELECT','�S��ĵ���Q��ܩ�');
DEFINE('_NOTSUCCESSFUL','�S�����\ ');
DEFINE('_ERRUNKAGID','����ĵ�i�s���ѧO�X�Q���w (ĵ�i�s�եi�ण�s�b)');
DEFINE('_ERRREMOVEFAIL','���ʨ�s��ĵ�i�s�ե���');
DEFINE('_GENBASE','�� BASE �ҫإ�');
DEFINE('_ERRNOEMAILEXP','�ץX���~: �L�k�ǰe�ץXĵ�i��');
DEFINE('_ERRNOEMAILPHP','�ˬdPHP�����q�l�l��]�w.');
DEFINE('_ERRDELALERT','�R��ĵ�i�o�Ϳ��~');
DEFINE('_ERRARCHIVE','�ʦs���~:');
DEFINE('_ERRMAILNORECP','�q�l�l����~: �S�����w����H');

//base_cache.inc.php
DEFINE('_ADDED','�s�W ');
DEFINE('_HOSTNAMESDNS',' �D���W�ٹ��� IP DNS �֨��Ȧs');
DEFINE('_HOSTNAMESWHOIS',' �D���W�ٹ��� Whois �֨��Ȧs');
DEFINE('_ERRCACHENULL','�֨��Ȧs�o�Ϳ��~: ���L�Ĩƥ�C?');
DEFINE('_ERRCACHEERROR','�ƥ�֨��Ȧs�X�{���~:');
DEFINE('_ERRCACHEUPDATE','�L�k��s�֨��ƥ�');
DEFINE('_ALERTSCACHE',' ĵ�i�ܧ֨��Ȧs');

//base_db.inc.php
DEFINE('_ERRSQLTRACE','�L�k�}�_ SQL �l���ɮ�');
DEFINE('_ERRSQLCONNECT','�s�����Ʈw�o�Ϳ��~:');
DEFINE('_ERRSQLCONNECTINFO','<P>�˹��Ʈw�s�u�Ѽ� <I>base_conf.php</I>
              <PRE>
               = $alert_dbname   : MySQL ĵ�i��Ʃҭn�x�s����Ʈw�W�� 
               = $alert_host     : �n�x�s��Ʈw���D��
               = $alert_port     : �n�x�s��Ʈw�ϥΪ��q�T��
               = $alert_user     : �i�J��Ʈw���ϥΪ̱b��
               = $alert_password : �ϥΪ̱K�X
              </PRE>
              <P>');
DEFINE('_ERRSQLPCONNECT','(p)connecting ���Ʈw�o�Ϳ��~:');
DEFINE('_ERRSQLDB','��Ʈw�o�Ϳ��~:');
DEFINE('_DBALCHECK','�ˬd��Ʈw���������禡�w');
DEFINE('_ERRSQLDBALLOAD1','<P><B>���J�������禡�w���o�Ϳ��~: </B> from ');
DEFINE('_ERRSQLDBALLOAD2','<P>�ˬd��Ʈw���禡�w�i�Ω� <CODE>$DBlib_path</CODE> in <CODE>base_conf.php</CODE>
            <P>
            ���h��Ʈw�s���禡�ƨϥ� ADODB, �ӵ{���i�U����
            <A HREF="http://adodb.sourceforge.net/">http://adodb.sourceforge.net/</A>');
DEFINE('_ERRSQLDBTYPE','���w�F���X�k����Ʈw���A');
DEFINE('_ERRSQLDBTYPEINFO1','�ܼ� <CODE>\$DBtype</CODE> �b <CODE>base_conf.php</CODE> �Q�]�����{�Ѫ���Ʈw���A ');
DEFINE('_ERRSQLDBTYPEINFO2','�u���U�C����Ʈw�Q�䴩: <PRE>
                MySQL         : \'mysql\'
                PostgreSQL    : \'postgres\'
                MS SQL Server : \'mssql\'
                Oracle        : \'oci8\'
             </PRE>');

//base_log_error.inc.php
DEFINE('_ERRBASEFATAL','BASE �Y�����~:');

//base_log_timing.inc.php
DEFINE('_LOADEDIN','���J��');
DEFINE('_SECONDS','��');

//base_net.inc.php
DEFINE('_ERRRESOLVEADDRESS','�L�k�ѪR��}');

//base_output_query.inc.php
DEFINE('_QUERYRESULTSHEADER','�d�ߵ��G��X���D');

//base_signature.inc.php
DEFINE('_ERRSIGNAMEUNK','SigName ����');
DEFINE('_ERRSIGPROIRITYUNK','SigPriority ����');
DEFINE('_UNCLASS','������');

//base_state_citems.inc.php
DEFINE('_DENCODED','��ƸѽX��');
DEFINE('_NODENCODED','(�S����ƳQ�ഫ, ��ܭ쥻���q��Ʈw�ѽX)');
DEFINE('_SHORTJAN','�@��'); //NEW
DEFINE('_SHORTFEB','�G��'); //NEW
DEFINE('_SHORTMAR','�T��'); //NEW
DEFINE('_SHORTAPR','�|��'); //NEW
DEFINE('_SHORTMAY','����'); //NEW
DEFINE('_SHORTJUN','����'); //NEW
DEFINE('_SHORTJLY','�C��'); //NEW
DEFINE('_SHORTAUG','�K��'); //NEW
DEFINE('_SHORTSEP','�E��'); //NEW
DEFINE('_SHORTOCT','�Q��'); //NEW
DEFINE('_SHORTNOV','�Q�@��'); //NEW
DEFINE('_SHORTDEC','�Q�G��'); //NEW
DEFINE('_DISPSIG','{ �S�x }'); //NEW
DEFINE('_DISPANYCLASS','{ ������� }'); //NEW
DEFINE('_DISPANYPRIO','{ �����u������ }'); //NEW
DEFINE('_DISPANYSENSOR','{ ���󰻴��� }'); //NEW
DEFINE('_DISPADDRESS','{ ��} }'); //NEW
DEFINE('_DISPFIELD','{ ��� }'); //NEW
DEFINE('_DISPPORT','{ �q�T�� }'); //NEW
DEFINE('_DISPENCODING','{ �ѽX }'); //NEW
DEFINE('_DISPCONVERT2','{ �ഫ�� }'); //NEW
DEFINE('_DISPANYAG','{ ����ĵ�i�s�� }'); //NEW
DEFINE('_DISPPAYLOAD','{ �ʥ]���e }'); //NEW
DEFINE('_DISPFLAGS','{ �X�� }'); //NEW
DEFINE('_SIGEXACTLY','��T��'); //NEW
DEFINE('_SIGROUGHLY','�ҽk��'); //NEW
DEFINE('_SIGCLASS','�S�x����'); //NEW
DEFINE('_SIGPRIO','�S�x�u������'); //NEW
DEFINE('_SHORTSOURCE','�ӷ�'); //NEW
DEFINE('_SHORTDEST','�ت�'); //NEW
DEFINE('_SHORTSOURCEORDEST','�ӷ��Υت�'); //NEW
DEFINE('_NOLAYER4','�L layer4'); //NEW
DEFINE('_INPUTCRTENC','��J�ѽX���A�W�h'); //NEW
DEFINE('_CONVERT2WS','�ഫ�� (��d�߮�)'); //NEW

//base_state_common.inc.php
DEFINE('_PHPERRORCSESSION','PHP ���~: �Q�˴��X�Ȥ� (�ϥΪ�) PHP �w�g�s�u. �L�צp��, BASE ���]�w���T���ϥγo�ӫȤ�B�z.  �]�w�� <CODE>use_user_session=1</CODE> in <CODE>base_conf.php</CODE>');
DEFINE('_PHPERRORCSESSIONCODE','PHP ���~: �Ȥ� (�ϥΪ�) PHP �s�u��ô�w�Q�]�w, ���O������ô�X�w�q�� <CODE>user_session_path</CODE> �O���X�k.');
DEFINE('_PHPERRORCSESSIONVAR','PHP ���~: �Ȥ� (�ϥΪ�) PHP �s�u��ô�w�Q�]�w, ���O�ظm�o�Ӻ�ô�S���b BASE �w�q.  �p�G�Ȥ�s�u��ô�O�ݭn��, �]�w <CODE>user_session_path</CODE> �ܼƦb�]�w�� <CODE>base_conf.php</CODE>.');
DEFINE('_PHPSESSREG','�s�u�w�n��');

//base_state_criteria.inc.php
DEFINE('_REMOVE','������');
DEFINE('_FROMCRIT','�q�з�');
DEFINE('_ERRCRITELEM','���X�k�зǤ���');

//base_state_query.inc.php
DEFINE('_VALIDCANNED','�X�k���s�d�ߦC��');
DEFINE('_DISPLAYING','��ܤ�');
DEFINE('_DISPLAYINGTOTAL','���ĵ�i�� %d-%d �� %d ����');
DEFINE('_NOALERTS','�䤣��ĵ�i.');
DEFINE('_QUERYRESULTS','�d�ߵ��G');
DEFINE('_QUERYSTATE','�d�ߪ��A');
DEFINE('_DISPACTION','{ �ʧ@ }'); //NEW

//base_ag_common.php
DEFINE('_ERRAGNAMESEARCH','���w�d�ߪ�ĵ�i�s�զW�٤��X�k.  �Э���!');
DEFINE('_ERRAGNAMEEXIST','���w��ĵ�i�s�դ��s�b.');
DEFINE('_ERRAGIDSEARCH','���w�d�ߪ�ĵ�i�s���ѧO�X���X�k.  �Э���!');
DEFINE('_ERRAGLOOKUP','�d��ĵ�i�s���ѧO�X�ɵo�Ϳ��~');
DEFINE('_ERRAGINSERT','���J�sĵ�i�s�ծɵo�Ϳ��~');

//base_ag_main.php
DEFINE('_AGMAINTTITLE','ĵ�i�s�� (AG) ���@');
DEFINE('_ERRAGUPDATE','��sĵ�i�s�ծɵo�Ϳ��~');
DEFINE('_ERRAGPACKETLIST','�qĵ�i�s�դ��R���ʥ]�C��ɵo�Ϳ��~:');
DEFINE('_ERRAGDELETE','�R��ĵ�i�s�ծɵo�Ϳ��~');
DEFINE('_AGDELETE','�w���\�R��');
DEFINE('_AGDELETEINFO','�T���w�R��');
DEFINE('_ERRAGSEARCHINV','��J���d�߼зǬO���X�k.  �Э���!');
DEFINE('_ERRAGSEARCHNOTFOUND','�θӼзǦbĵ�i�s�դ��䤣��.');
DEFINE('_NOALERTGOUPS','�o�بS��ĵ�i�s��');
DEFINE('_NUMALERTS','# ĵ�i��');
DEFINE('_ACTIONS','�ʧ@');
DEFINE('_NOTASSIGN','�٥����w');
DEFINE('_SAVECHANGES','�x�s�ܧ�'); //NEW
DEFINE('_CONFIRMDELETE','�T�{�R��'); //NEW
DEFINE('_CONFIRMCLEAR','�T�{�M��'); //NEW

//base_common.php
DEFINE('_PORTSCAN','�q�T�𱽴y�ǿ鱡��');

//base_db_common.php
DEFINE('_ERRDBINDEXCREATE','�L�k�إ� INDEX ���ަ�');
DEFINE('_DBINDEXCREATE','���\�إ߸�� INDEX ���ަ�');
DEFINE('_ERRSNORTVER','�o�i�O�O���ª���.  �u��ĵ�i��Ʈw�إߩ� Snort 1.7-beta0 �ΥH��~���䴩');
DEFINE('_ERRSNORTVER1','���h��Ʈw');
DEFINE('_ERRSNORTVER2','�X�{���ۮe/���X�k');
DEFINE('_ERRDBSTRUCT1','��Ʈw�����P BASE ��Ʈw���c���X�k');
DEFINE('_ERRDBSTRUCT2','�S���X�{. �ϥ� <A HREF="base_db_setup.php">Setup page</A> �ӽվ�γ]�w��Ʈw.');
DEFINE('_ERRPHPERROR','PHP ���~');
DEFINE('_ERRPHPERROR1','���ۮe����');
DEFINE('_ERRVERSION','����');
DEFINE('_ERRPHPERROR2',' PHP �����Ӧ���.  �Ъ@�Ŧ� 4.0.4 �ΥH�᪩��');
DEFINE('_ERRPHPMYSQLSUP','<B>PHP �ظm���ۮe</B>: <FONT>�w�d�ߪ� MySQL ��Ʈw�괩�ݭn
               �hŪ��ĵ�i��Ʈw�S���g�ѩҫإߪ� PHP�hŪ��.
               �Э��s�sĶ PHP �M�һݪ��{���w (<CODE>--with-mysql</CODE>)</FONT>');
DEFINE('_ERRPHPPOSTGRESSUP','<B>PHP �ظm���ۮe</B>: <FONT>�w�d�ߪ� PostgreSQL �䴩�ݭn
               �hŪ��ĵ�i��Ʈw�S���g�ѩҫإߪ� PHP �hŪ��.
               �Э��s�sĶ PHP �M�һݪ��{���w (<CODE>--with-pgsql</CODE>)</FONT>');
DEFINE('_ERRPHPMSSQLSUP','<B>PHP �ظm���ۮe</B>: <FONT>�w�d�ߪ� MS SQL Server ��Ʈw�䴩�ݭn
                   �hŪ��ĵ�i��Ʈw�S���g�ѩҫإߪ� PHP �hŪ��.
                   P�Э��s�sĶ PHP �M�һݪ��{���w  (<CODE>--enable-mssql</CODE>)</FONT>');
DEFINE('_ERRPHPORACLESUP','<B>PHP ������إ�</B>: <FONT>�b�w�]���p�n�䴩 Oracle �ݭn���s�sĶ�{���X 
                   ĵ�i��Ʈw�L�k�Q���� PHP Ū��.  
                   �Э��s�sĶ PHP �ݥ]�t Oracle �{���w (<CODE>--with-oci8</CODE>)</FONT>');

//base_graph_form.php
DEFINE('_CHARTTITLE','�ϧμ��D:');
DEFINE('_CHARTTYPE','�ϧΫ��A:'); //NEW
DEFINE('_CHARTTYPES','{ �Ϫ�Φ� }'); //NEW
DEFINE('_CHARTPERIOD','�Ϫ�g��:'); //NEW
DEFINE('_PERIODNO','�S���g��'); //NEW
DEFINE('_PERIODWEEK','7 (�@�g)'); //NEW
DEFINE('_PERIODDAY','24 (���)'); //NEW
DEFINE('_PERIOD168','168 (24x7)'); //NEW
DEFINE('_CHARTSIZE','�ؤo: (�e x ��)'); //NEW
DEFINE('_PLOTMARGINS','ø�Ͻd��: (�� x �k x �W x �U)'); //NEW
DEFINE('_PLOTTYPE','ø�ϫ��A:'); //NEW
DEFINE('_TYPEBAR','������'); //NEW
DEFINE('_TYPELINE','�u�ι�'); //NEW
DEFINE('_TYPEPIE','����'); //NEW
DEFINE('_CHARTHOUR','{��}'); //NEW
DEFINE('_CHARTDAY','{��}'); //NEW
DEFINE('_CHARTMONTH','{��}'); //NEW
DEFINE('_GRAPHALERTS','ĵ�i��'); //NEW
DEFINE('_AXISCONTROLS','X / Y ����'); //NEW
DEFINE('_CHRTTYPEHOUR','�ɶ� (�p��) vs. ĵ�i��');
DEFINE('_CHRTTYPEDAY','�ɶ� (��) vs. ĵ�i��');
DEFINE('_CHRTTYPEWEEK','�ɶ� (�g) vs. ĵ�i��');
DEFINE('_CHRTTYPEMONTH','�ɶ� (��) vs. ĵ�i��');
DEFINE('_CHRTTYPEYEAR','�ɶ� (�~) vs. ĵ�i��');
DEFINE('_CHRTTYPESRCIP','�ӷ�. IP ��} vs. ĵ�i��');
DEFINE('_CHRTTYPEDSTIP','�ئa. IP ��} vs. ĵ�i��');
DEFINE('_CHRTTYPEDSTUDP','�ئa. UDP �q�T�� vs. ĵ�i��');
DEFINE('_CHRTTYPESRCUDP','�ӷ�. UDP �q�T�� vs. ĵ�i��');
DEFINE('_CHRTTYPEDSTPORT','�ئa. TCP �q�T�� vs. ĵ�i��');
DEFINE('_CHRTTYPESRCPORT','�ӷ�. TCP �q�T�� vs. ĵ�i��');
DEFINE('_CHRTTYPESIG','�S�x. ���� vs. ĵ�i��');
DEFINE('_CHRTTYPESENSOR','������ vs. ĵ�i��');
DEFINE('_CHRTBEGIN','�ϧζ}�l:');
DEFINE('_CHRTEND','�ϧε���:');
DEFINE('_CHRTDS','��ƨӷ�:');
DEFINE('_CHRTX','X �b');
DEFINE('_CHRTY','Y �b');
DEFINE('_CHRTMINTRESH','�̤p�����');
DEFINE('_CHRTROTAXISLABEL','����b�аO (90 ��)');
DEFINE('_CHRTSHOWX','��� X-�b ��u');
DEFINE('_CHRTDISPLABELX','��� X-�b ���ҨC��');
DEFINE('_CHRTDATAPOINTS','����I��');
DEFINE('_CHRTYLOG','Y-�b ������');
DEFINE('_CHRTYGRID','��� Y-�b �u��');

//base_graph_main.php
DEFINE('_CHRTTITLE','BASE �ϧ�');
DEFINE('_ERRCHRTNOTYPE','�S���ϫ����A�Q���w');
DEFINE('_ERRNOAGSPEC','�S�� AG ĵ�i�s�ճQ���w.  �ϥΥ���ĵ�i.');
DEFINE('_CHRTDATAIMPORT','�}�l�����J');
DEFINE('_CHRTTIMEVNUMBER','�ɶ� vs. ĵ�i��');
DEFINE('_CHRTTIME','�ɶ�');
DEFINE('_CHRTALERTOCCUR','ĵ�i�ƥ�');
DEFINE('_CHRTSIPNUMBER','�ӷ� IP vs. Nĵ�i��s');
DEFINE('_CHRTSIP','�ӷ� IP ��}');
DEFINE('_CHRTDIPALERTS','�ئa IP vs. ĵ�i��');
DEFINE('_CHRTDIP','�ئa IP ��}');
DEFINE('_CHRTUDPPORTNUMBER','UDP �q�T�� (�ئa) vs. ĵ�i��');
DEFINE('_CHRTDUDPPORT','Dst. UDP �q�T��');
DEFINE('_CHRTSUDPPORTNUMBER','UDP �q�T�� (�ӷ�) vs. ĵ�i��');
DEFINE('_CHRTSUDPPORT','Src. UDP �q�T��');
DEFINE('_CHRTPORTDESTNUMBER','TCP �q�T�� (�ئa) vs. ĵ�i��');
DEFINE('_CHRTPORTDEST','Dst. TCP �q�T��');
DEFINE('_CHRTPORTSRCNUMBER','TCP �q�T�� (�ӷ�) vs. ĵ�i��');
DEFINE('_CHRTPORTSRC','Src. TCP �q�T��');
DEFINE('_CHRTSIGNUMBER','�S�x���� vs. ĵ�i��');
DEFINE('_CHRTCLASS','����');
DEFINE('_CHRTSENSORNUMBER','������ vs. ĵ�i��');
DEFINE('_CHRTHANDLEPERIOD','�����g�� �p�G�ݭn');
DEFINE('_CHRTDUMP','���J��Ƥ� ... (�C���u�g�J');
DEFINE('_CHRTDRAW','ø�s�Ϫ�');
DEFINE('_ERRCHRTNODATAPOINTS','�S������I�i�Hø�s');
DEFINE('_GRAPHALERTDATA','ø�Xĵ�i���'); //NEW

//base_maintenance.php
DEFINE('_MAINTTITLE','���@');
DEFINE('_MNTPHP','PHP �ب�:');
DEFINE('_MNTCLIENT','�Ȥ��:');
DEFINE('_MNTSERVER','���A��:');
DEFINE('_MNTSERVERHW','���A�ݵw��:');
DEFINE('_MNTPHPVER','PHP ����:');
DEFINE('_MNTPHPAPI','PHP API:');
DEFINE('_MNTPHPLOGLVL','PHP �n�J���:');
DEFINE('_MNTPHPMODS','���J�Ҳ�:');
DEFINE('_MNTDBTYPE','��Ʈw���A:');
DEFINE('_MNTDBALV','��Ʈw��H����:');
DEFINE('_MNTDBALERTNAME','ĵ�i��Ʈw�W��:');
DEFINE('_MNTDBARCHNAME','�ʦs��Ʈw�W��:');
DEFINE('_MNTAIC','ĵ�i��T�֨��Ȧs:');
DEFINE('_MNTAICTE','�����ƥ��:');
DEFINE('_MNTAICCE','�֨��ƥ��:');
DEFINE('_MNTIPAC','IP ��}�֨�');
DEFINE('_MNTIPACUSIP','��@�ӷ� IP:');
DEFINE('_MNTIPACDNSC','DNS �֨�:');
DEFINE('_MNTIPACWC','Whois �֨�:');
DEFINE('_MNTIPACUDIP','��@�ئa IP:');

//base_qry_alert.php
DEFINE('_QAINVPAIR','���X�k (sid,cid) �t��');
DEFINE('_QAALERTDELET','ĵ�i�w�R��');
DEFINE('_QATRIGGERSIG','Ĳ�o�ƥ�S�x');
DEFINE('_QANORMALD','���`���'); //NEW
DEFINE('_QAPLAIND','²�����'); //NEW
DEFINE('_QANOPAYLOAD','�w�ϥΧֳt�O���]���ʥ]���e�Q���'); //NEW

//base_qry_common.php
DEFINE('_QCSIG','�S�x');
DEFINE('_QCIPADDR','IP ��}');
DEFINE('_QCIPFIELDS','IP ���');
DEFINE('_QCTCPPORTS','TCP �q�T��');
DEFINE('_QCTCPFLAGS','TCP �X��');
DEFINE('_QCTCPFIELD','TCP ���');
DEFINE('_QCUDPPORTS','UDP �q�T��');
DEFINE('_QCUDPFIELDS','UDP ���');
DEFINE('_QCICMPFIELDS','ICMP ���');
DEFINE('_QCDATA','���');
DEFINE('_QCERRCRITWARN','�з�ĵ�i:');
DEFINE('_QCERRVALUE','�@�ӭȬ�');
DEFINE('_QCERRFIELD','�@����쬰');
DEFINE('_QCERROPER','�@�ӹB��l��');
DEFINE('_QCERRDATETIME','�@�Ӥ��/�ɶ��Ȭ�');
DEFINE('_QCERRPAYLOAD','�@�ӫʥ]���e�Ȭ�');
DEFINE('_QCERRIP','�@�� IP ��}��');
DEFINE('_QCERRIPTYPE','�@�� IP ��}���A');
DEFINE('_QCERRSPECFIELD',' �w�g��J�q�T��w���, ���O�S�w���S���Q���w.');
DEFINE('_QCERRSPECVALUE','�w�g��ܫ��X�o�����з�, ���O�S���ƭȳQ���w�۲�.');
DEFINE('_QCERRBOOLEAN','�h�ӳq�T��w���зǿ�J���O�S���޿�B��l (��. AND, OR) �b�Ǫ̤���.');
DEFINE('_QCERRDATEVALUE','�w�g��w�M���X���O�@�Ǥ��/�ɶ����ݭn�Q�ŦX, �S���ƭȫ��w.');
DEFINE('_QCERRINVHOUR','(���X�k���p��) �S���Ϋ��w���ɶ��ӿ�J�зǸ��.');
DEFINE('_QCERRDATECRIT','�w��ܫ��X�@�Ǥ��/�ɶ����ݭn�Q�ŦX, ���O�S���ƭȳQ���w.');
DEFINE('_QCERROPERSELECT','�w�g��J���O�S���B�⤸�Q���.');
DEFINE('_QCERRDATEBOOL','�h�Ӥ��/�ɶ��зǿ�J���S���޿�B��l (��. AND, OR) �����̤���.');
DEFINE('_QCERRPAYCRITOPER','�w�g��J�@���ʥ]�з����, ���B��l (��. has, has not) �S���Q���w.');
DEFINE('_QCERRPAYCRITVALUE','�w�g��ܫ��w�ʥ]�i�వ���з�, ���O�S���ƭȤ���ҫ��w��̤���.');
DEFINE('_QCERRPAYBOOL','�h�Ӹ�ƫʥ]�зǳQ��J���O�S���޿�B��l (��. AND, OR) �����̤���.');
DEFINE('_QCMETACRIT','Meta �з�');
DEFINE('_QCIPCRIT','IP �з�');
DEFINE('_QCPAYCRIT','�ʥ]���e�з�');
DEFINE('_QCTCPCRIT','TCP �з�');
DEFINE('_QCUDPCRIT','UDP �з�');
DEFINE('_QCICMPCRIT','ICMP �з�');
DEFINE('_QCLAYER4CRIT','�ĥ|�h�W�h'); //NEW
DEFINE('_QCERRINVIPCRIT','���X�k IP ��}�з�');
DEFINE('_QCERRCRITADDRESSTYPE','�w�g�Q��J�����зǭ�, ���O��}���A (��. �ӷ�, �ئa) �S���Q���w.');
DEFINE('_QCERRCRITIPADDRESSNONE','���X�@�� IP ��}���ݷ��з�, ���O�S����}�i�H�P���w���۲ŦX.');
DEFINE('_QCERRCRITIPADDRESSNONE1','�w�g��� (�� #');
DEFINE('_QCERRCRITIPIPBOOL','�h�� IP ��}�зǿ�J���O�S���@���޿�B��l (��. AND, OR) ������ IP �зǶ�');

//base_qry_form.php
DEFINE('_QFRMSORTORDER','�ƧǳW�h');
DEFINE('_QFRMSORTNONE','�L'); //NEW
DEFINE('_QFRMTIMEA','�ɶ��W�O (ascend)');
DEFINE('_QFRMTIMED','�ɶ��W�O (descend)');
DEFINE('_QFRMSIG','�S�x');
DEFINE('_QFRMSIP','�ӷ� IP');
DEFINE('_QFRMDIP','�ئa IP');

//base_qry_sqlcalls.php
DEFINE('_QSCSUMM','�K�n���A');
DEFINE('_QSCTIMEPROF','�ɶ��ƾ�');
DEFINE('_QSCOFALERTS','ĵ�i��');

//base_stat_alerts.php
DEFINE('_ALERTTITLE','ĵ�i�C��');

//base_stat_common.php
DEFINE('_SCCATEGORIES','�ؿ�:');
DEFINE('_SCSENSORTOTAL','������/����:');
DEFINE('_SCTOTALNUMALERTS','����ĵ�i��:');
DEFINE('_SCSRCIP','�ӷ� IP ��}:');
DEFINE('_SCDSTIP','�ئa IP ��}:');
DEFINE('_SCUNILINKS','��@ IP �s����');
DEFINE('_SCSRCPORTS','�ӷ� �q�T���: ');
DEFINE('_SCDSTPORTS','�ئa �q�T���: ');
DEFINE('_SCSENSORS','������');
DEFINE('_SCCLASS','����');
DEFINE('_SCUNIADDRESS','��@��}: ');
DEFINE('_SCSOURCE','�ӷ�');
DEFINE('_SCDEST','�ئa');
DEFINE('_SCPORT','�q�T��');

//base_stat_ipaddr.php
DEFINE('_PSEVENTERR','PORTSCAN �ƥ���~: ');
DEFINE('_PSEVENTERRNOFILE','�S���ɮ׳Q���w�b \$portscan_file �ܼ�.');
DEFINE('_PSEVENTERROPENFILE','�L�k�}�� �q�T�𱽴y �ƥ���');
DEFINE('_PSDATETIME','���/�ɶ�');
DEFINE('_PSSRCIP','�ӷ� IP');
DEFINE('_PSDSTIP','�ئa IP');
DEFINE('_PSSRCPORT','�ӷ��q�T��');
DEFINE('_PSDSTPORT','�ئa�q�T��');
DEFINE('_PSTCPFLAGS','TCP �X��');
DEFINE('_PSTOTALOCC','����<BR> �ƥ�');
DEFINE('_PSNUMSENSORS','�������ƥ�');
DEFINE('_PSFIRSTOCC','�̦�<BR> �ƥ�');
DEFINE('_PSLASTOCC','�̫�<BR> �ƥ�');
DEFINE('_PSUNIALERTS','��@ĵ�i��');
DEFINE('_PSPORTSCANEVE','�q�T�𱽴y�ƥ�');
DEFINE('_PSREGWHOIS','�n�J�d�� (whois) ��');
DEFINE('_PSNODNS','�S�� DNS �ѪR����');
DEFINE('_PSNUMSENSORSBR','������ <BR>�ƥ�');
DEFINE('_PSOCCASSRC','�o�� <BR>�����ӷ�');
DEFINE('_PSOCCASDST','�o�� <BR>�����ئa');
DEFINE('_PSWHOISINFO','Whois ��T');
DEFINE('_PSTOTALHOSTS','�������y��D��'); //NEW
DEFINE('_PSDETECTAMONG','%d �涵������ĵ�i�b %d ������ %s'); //NEW
DEFINE('_PSALLALERTSAS','����ĵ�i�Ƭ� %s/%s as'); //NEW
DEFINE('_PSSHOW','���'); //NEW
DEFINE('_PSEXTERNAL','�~��'); //NEW

//base_stat_iplink.php
DEFINE('_SIPLTITLE','IP �s����');
DEFINE('_SIPLSOURCEFGDN','�ӷ� FQDN');
DEFINE('_SIPLDESTFGDN','�ئa FQDN');
DEFINE('_SIPLDIRECTION','��V');
DEFINE('_SIPLPROTO','�q�T��w');
DEFINE('_SIPLUNIDSTPORTS','��@�ئa�q�T��');
DEFINE('_SIPLUNIEVENTS','��@�ƥ�');
DEFINE('_SIPLTOTALEVENTS','�����ƥ�');

//base_stat_ports.php
DEFINE('_UNIQ','��@');
DEFINE('_DSTPS','�ئa�q�T���');
DEFINE('_SRCPS','�ӷ��q�T���');
DEFINE('_OCCURRENCES','Occurrences'); //NEW

//base_stat_sensor.php
DEFINE('SPSENSORLIST','�������C��');

//base_stat_time.php
DEFINE('_BSTTITLE','ĵ�i�ɶ��ƾڪ�');
DEFINE('_BSTTIMECRIT','�ɶ��з�');
DEFINE('_BSTERRPROFILECRIT','<FONT><B>�S���ƾڮw�зǳQ���w!</B>  ��� "�p��", "��", �� "��" �ӿ�w�����ɪ������A.</FONT>');
DEFINE('_BSTERRTIMETYPE','<FONT><B>�q�L���ɶ��Ѽƫ��A�S���Q���w!</B>  ��� "on", ,���w����W����� "between" �ӫ��w�S�w����.</FONT>');
DEFINE('_BSTERRNOYEAR','<FONT><B>�S���~�ѼƳQ���w!</B></FONT>');
DEFINE('_BSTERRNOMONTH','<FONT><B>�S����ѼƳQ���w!</B></FONT>');
DEFINE('_BSTERRNODAY','<FONT><B>�S����ѼƳQ���w!</B></FONT>');
DEFINE('_BSTPROFILEBY','Profile by'); //NEW
DEFINE('_TIMEON','on'); //NEW
DEFINE('_TIMEBETWEEN','����'); //NEW
DEFINE('_PROFILEALERT','Profile Alert'); //NEW

//base_stat_uaddr.php
DEFINE('_UNISADD','��@�ӷ���}��)');
DEFINE('_SUASRCIP','�ӷ� IP ��}');
DEFINE('_SUAERRCRITADDUNK','�зǿ��~: ������}���A -- ��ܥئa��}');
DEFINE('_UNIDADD','��@�ئa��}��');
DEFINE('_SUADSTIP','�ئa IP ��}');
DEFINE('_SUAUNIALERTS','��@&nbsp;ĵ�i��');
DEFINE('_SUASRCADD','�ӷ�&nbsp;��}');
DEFINE('_SUADSTADD','�ئa&nbsp;��}');

//base_user.php
DEFINE('_BASEUSERTITLE','BASE �ϥΪ̰Ѽ�');
DEFINE('_BASEUSERERRPWD','�z���K�X���ର�ťթΨ�ӱK�X�S���k�X!');
DEFINE('_BASEUSEROLDPWD','�±K�X:');
DEFINE('_BASEUSERNEWPWD','�s�K�X:');
DEFINE('_BASEUSERNEWPWDAGAIN','�A��J�s�K�X�@��:');

DEFINE('_LOGOUT','�n�X');

?>
