*&---------------------------------------------------------------------*
*& Report  Z_BASIS_TOOLBOX
*& Version 1.0 RC1
*&---------------------------------------------------------------------*
*& SAP Basis Admin Toolbox for Private Cloud (no OS access)
*&
*& Features:
*&   File Operations:
*&   - File Manager (navigate, upload, download, copy, rename, delete,
*&     create directories, download folders as ZIP, Back/Forward nav)
*&   - Upload ZIP (extract flat to server directory)
*&   Transport:
*&   - Transport Download (Server -> PC, auto-detect K/R files)
*&   - Transport Upload (PC -> Server, up to 4 transports at once)
*&   Network & Security:
*&   - Network Diagnostics (ping, nslookup, traceroute, curl)
*&   - SSL Certificate Checker (PSE certs with traffic light status)
*&   System:
*&   - Grep (search text in files with ALV display)
*&   - Profile Parameter Browser (filter + display params with profile)
*&   - System Info (IP, disk space, instance details)
*&
*& Security Model (v1.0 RC1):
*&   Roles (self-contained, incl. S_PROGRAM/S_C_FUNCT/S_DATASET/S_GUI):
*&     Z_BASIS_TOOL_USER  - MODL in {FM,TRD,TRU,NET,CRT,GRP,PRF,SYS}, ACTN=01
*&                          (no ZIP Upload, no Curl)
*&     Z_BASIS_TOOL_ADMIN - MODL=*, ACTN in {01,02}
*&                          (PRD: no FM write except empty-dir delete,
*&                                no ZIP Upload, no Transport Upload)
*&     Z_BASIS_TOOL_DEBUG - MODL=*, ACTN in {01,02,99} - emergency bypass
*&
*&   Developer Flags (see section 2):
*&     c_audit_non_prd - write audit log on non-PRD too (default: off)
*&     c_debug_mode    - bypass all auth + audit checks (default: off)
*&
*&   Layers:
*&     Layer 1: Authorization Object Z_BASTOOL (ZBAS_MODL + ZBAS_ACTN)
*&     Layer 2: OS Command Whitelisting (no generic shell access)
*&     Layer 3: Audit Log (ZBAS_TOOL_LOG + SM20) - PRD-only by default
*&     Layer 4: Production System Restrictions (granular write blocks)
*&---------------------------------------------------------------------*
REPORT z_basis_toolbox.

" Include standard icons
INCLUDE <icon>.

TABLES: sscrfields,
        e070.   " type carrier for SELECT-OPTIONS s_stm_tr (TRKORR)

*----------------------------------------------------------------------*
* 1. CLASS DEFINITIONS (DEFERRED)
*----------------------------------------------------------------------*
CLASS lcl_event_receiver DEFINITION DEFERRED.

*----------------------------------------------------------------------*
* 2. GLOBAL CONSTANTS & DATA
*----------------------------------------------------------------------*
CONSTANTS: c_mode_init TYPE string VALUE 'INIT',
           c_mode_menu TYPE string VALUE 'MENU',
           c_mode_fm   TYPE string VALUE 'FILE_MANAGER',
           c_mode_zup  TYPE string VALUE 'ZIP_UP',
           c_mode_trd  TYPE string VALUE 'TRANS_DOWN',
           c_mode_tru  TYPE string VALUE 'TRANS_UP',
           c_mode_grp  TYPE string VALUE 'GREP',
           c_mode_sys  TYPE string VALUE 'SYSINFO',
           c_mode_net  TYPE string VALUE 'NETWORK',
           c_mode_cert TYPE string VALUE 'CERTS',
           c_mode_prof TYPE string VALUE 'PROFILE',
           c_mode_stm  TYPE string VALUE 'STMS_BUF'.

" Default = INIT so the very first PBO renders a fully blank selection
" screen. INITIALIZATION transitions to c_mode_menu after any startup
" popups (e.g. debug confirmation) have been answered. This guarantees
" no menu/module fields flicker behind the popup.
DATA: gv_mode TYPE string VALUE c_mode_init.
DATA: gv_current_dir TYPE string.

* Data Types for File List
TYPES: BEGIN OF ty_file_item,
         icon(4)      TYPE c,
         name(255)    TYPE c,
         size         TYPE i,
         size_fmt(12) TYPE c,
         owner(20)    TYPE c,
         datetime(19) TYPE c,
         type(10)     TYPE c,
         sort_type(1) TYPE c,
         abspath      TYPE string,
         date         TYPE d,
         time         TYPE t,
       END OF ty_file_item.

DATA: gt_file_list TYPE TABLE OF ty_file_item.

* Navigation History
DATA: gt_nav_history  TYPE TABLE OF string,
      gv_nav_idx      TYPE i VALUE 0,
      gv_nav_no_push  TYPE abap_bool.

* Grep Result Type
TYPES: BEGIN OF ty_grep_result,
         filename(255) TYPE c,
         line_no       TYPE i,
         content(255)  TYPE c,
       END OF ty_grep_result.

DATA: gt_grep_list TYPE TABLE OF ty_grep_result.

* System Info Type
TYPES: BEGIN OF ty_sysinfo_line,
         label(30)  TYPE c,
         value(100) TYPE c,
       END OF ty_sysinfo_line.

* Network Result Type
TYPES: BEGIN OF ty_net_result,
         line_no TYPE i,
         content(250) TYPE c,
       END OF ty_net_result.

* Certificate Info Type
TYPES: BEGIN OF ty_cert_info,
         icon(4)       TYPE c,
         context(40)   TYPE c,
         subject(100)  TYPE c,
         issuer(100)   TYPE c,
         valid_from(10) TYPE c,
         valid_to(10)  TYPE c,
         days_left     TYPE i,
         serial(40)    TYPE c,
       END OF ty_cert_info.

* Profile Parameter Type
TYPES: BEGIN OF ty_profile_param,
         name(40)        TYPE c,
         value(128)      TYPE c,
         profile(40)     TYPE c,
       END OF ty_profile_param.

* Helper
DATA: gt_split_dummy TYPE TABLE OF string.

* ALV Grid Globals
DATA: go_container TYPE REF TO cl_gui_docking_container,
      go_grid      TYPE REF TO cl_gui_alv_grid,
      go_event     TYPE REF TO lcl_event_receiver.

* Security Layer: Module IDs for Authorization
CONSTANTS: c_mod_fm  TYPE c LENGTH 3 VALUE 'FM',
           c_mod_zup TYPE c LENGTH 3 VALUE 'ZUP',
           c_mod_trd TYPE c LENGTH 3 VALUE 'TRD',
           c_mod_tru TYPE c LENGTH 3 VALUE 'TRU',
           c_mod_stm TYPE c LENGTH 3 VALUE 'STM',  " Add multiple transports to STMS buffer
           c_mod_grp TYPE c LENGTH 3 VALUE 'GRP',
           c_mod_net TYPE c LENGTH 3 VALUE 'NET',
           c_mod_crt TYPE c LENGTH 3 VALUE 'CRT',
           c_mod_prf TYPE c LENGTH 3 VALUE 'PRF',
           c_mod_sys TYPE c LENGTH 3 VALUE 'SYS'.
CONSTANTS: c_actn_display TYPE c LENGTH 2 VALUE '01',
           c_actn_execute TYPE c LENGTH 2 VALUE '02',
           c_actn_admin   TYPE c LENGTH 2 VALUE '03',
           c_actn_debug   TYPE c LENGTH 2 VALUE '99'.

* Developer flags - edit at compile-time to change default behavior
CONSTANTS: c_audit_non_prd TYPE abap_bool VALUE abap_false,  " 'X' = write audit log on non-PRD too
           c_debug_mode    TYPE abap_bool VALUE abap_false.  " 'X' = bypass ALL auth/audit (dev only)

* Security Layer: Production Restriction
DATA: gv_is_prd       TYPE abap_bool VALUE abap_false,
      gv_auth_ok      TYPE abap_bool,
      gv_fm_write     TYPE abap_bool VALUE abap_false,
      gv_debug_active TYPE abap_bool VALUE abap_false,
      gv_debug_audit  TYPE abap_bool VALUE abap_false.  " Debug mode: audit still enabled?

* Security Layer: Button -> Module map used by INIT (startup check) and PBO (button graying)
TYPES: BEGIN OF ty_btn_auth,
         btn TYPE c LENGTH 10,
         mod TYPE c LENGTH 3,
       END OF ty_btn_auth.
DATA: gt_btn_auth TYPE TABLE OF ty_btn_auth.

*----------------------------------------------------------------------*
* 3. LOCAL CLASS FOR EVENTS
*----------------------------------------------------------------------*
CLASS lcl_event_receiver DEFINITION.
  PUBLIC SECTION.
    METHODS:
      handle_toolbar FOR EVENT toolbar OF cl_gui_alv_grid
        IMPORTING e_object e_interactive,

      handle_user_command FOR EVENT user_command OF cl_gui_alv_grid
        IMPORTING e_ucomm,

      on_hotspot_click FOR EVENT hotspot_click OF cl_gui_alv_grid
        IMPORTING e_row_id e_column_id.
ENDCLASS.

*----------------------------------------------------------------------*
* 4. SELECTION SCREEN
*----------------------------------------------------------------------*
SELECTION-SCREEN BEGIN OF BLOCK b_info WITH FRAME TITLE tit_inf.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(15) lbl_sid.
    SELECTION-SCREEN COMMENT 17(10) val_sid MODIF ID inf.
    SELECTION-SCREEN COMMENT 50(15) lbl_cli.
    SELECTION-SCREEN COMMENT 66(10) val_cli MODIF ID inf.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(15) lbl_hst.
    SELECTION-SCREEN COMMENT 17(30) val_hst MODIF ID inf.
    SELECTION-SCREEN COMMENT 50(15) lbl_rel.
    SELECTION-SCREEN COMMENT 66(15) val_rel MODIF ID inf.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN SKIP 1.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(15) lbl_dbs.
    SELECTION-SCREEN COMMENT 17(10) val_dbs MODIF ID inf.
    SELECTION-SCREEN COMMENT 50(15) lbl_dbh.
    SELECTION-SCREEN COMMENT 66(30) val_dbh MODIF ID inf.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(15) lbl_dbv.
    SELECTION-SCREEN COMMENT 17(60) val_dbv MODIF ID inf.
  SELECTION-SCREEN END OF LINE.
SELECTION-SCREEN END OF BLOCK b_info.

SELECTION-SCREEN BEGIN OF BLOCK b_menu WITH FRAME TITLE tit_men.
  " --- File Operations ---
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_fm USER-COMMAND cmd_fm MODIF ID men.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_zup USER-COMMAND cmd_zup MODIF ID men.
  SELECTION-SCREEN END OF LINE.

  SELECTION-SCREEN SKIP 1.

  " --- Transport ---
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_trd USER-COMMAND cmd_trd MODIF ID men.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_tru USER-COMMAND cmd_tru MODIF ID men.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_stm USER-COMMAND cmd_stm MODIF ID men.
  SELECTION-SCREEN END OF LINE.

  SELECTION-SCREEN SKIP 1.

  " --- Network & Security ---
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_net USER-COMMAND cmd_net MODIF ID men.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_crt USER-COMMAND cmd_crt MODIF ID men.
  SELECTION-SCREEN END OF LINE.

  SELECTION-SCREEN SKIP 1.

  " --- System ---
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_grp USER-COMMAND cmd_grp MODIF ID men.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_prf USER-COMMAND cmd_prf MODIF ID men.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN PUSHBUTTON 12(60) btn_sys USER-COMMAND cmd_sys MODIF ID men.
  SELECTION-SCREEN END OF LINE.

  SELECTION-SCREEN SKIP 1.
  SELECTION-SCREEN COMMENT /1(50) txt_ver MODIF ID men.
SELECTION-SCREEN END OF BLOCK b_menu.

SELECTION-SCREEN BEGIN OF BLOCK b_fm WITH FRAME TITLE tit_fm.
  SELECTION-SCREEN COMMENT /1(79) txt_f_1 MODIF ID fm.
  PARAMETERS: p_fm_dir TYPE string LOWER CASE MODIF ID fm DEFAULT '/usr/sap/'.
  SELECTION-SCREEN SKIP 1.
  SELECTION-SCREEN COMMENT /1(79) txt_f_2 MODIF ID fm.
SELECTION-SCREEN END OF BLOCK b_fm.

SELECTION-SCREEN BEGIN OF BLOCK b_zup WITH FRAME TITLE tit_zup.
  SELECTION-SCREEN COMMENT /1(79) txt_zu1 MODIF ID zup.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_zuf MODIF ID zup.
    PARAMETERS: p_zu_fil TYPE string LOWER CASE MODIF ID zup.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_zud MODIF ID zup.
    PARAMETERS: p_zu_dir TYPE string LOWER CASE MODIF ID zup DEFAULT '/tmp/'.
  SELECTION-SCREEN END OF LINE.
SELECTION-SCREEN END OF BLOCK b_zup.

SELECTION-SCREEN BEGIN OF BLOCK b_trd WITH FRAME TITLE tit_trd.
  SELECTION-SCREEN COMMENT /1(79) txt_tr1 MODIF ID trd.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tid MODIF ID trd.
    PARAMETERS: p_tr_id  TYPE string MODIF ID trd.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tsd MODIF ID trd.
    PARAMETERS: p_tr_dir TYPE string LOWER CASE MODIF ID trd DEFAULT '/usr/sap/trans/'.
  SELECTION-SCREEN END OF LINE.
SELECTION-SCREEN END OF BLOCK b_trd.

SELECTION-SCREEN BEGIN OF BLOCK b_tru WITH FRAME TITLE tit_tru.
  SELECTION-SCREEN COMMENT /1(79) txt_tu1 MODIF ID tru.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_ttd MODIF ID tru.
    PARAMETERS: p_tru_td TYPE string LOWER CASE MODIF ID tru DEFAULT '/usr/sap/trans/'.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN SKIP 1.
  " Transport 1
  SELECTION-SCREEN COMMENT /1(30) lbl_t1 MODIF ID tru.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tk1 MODIF ID tru.
    PARAMETERS: p_tru_k1 TYPE string LOWER CASE MODIF ID tru.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tr1 MODIF ID tru.
    PARAMETERS: p_tru_r1 TYPE string LOWER CASE MODIF ID tru.
  SELECTION-SCREEN END OF LINE.
  " Transport 2
  SELECTION-SCREEN COMMENT /1(30) lbl_t2 MODIF ID tru.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tk2 MODIF ID tru.
    PARAMETERS: p_tru_k2 TYPE string LOWER CASE MODIF ID tru.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tr2 MODIF ID tru.
    PARAMETERS: p_tru_r2 TYPE string LOWER CASE MODIF ID tru.
  SELECTION-SCREEN END OF LINE.
  " Transport 3
  SELECTION-SCREEN COMMENT /1(30) lbl_t3 MODIF ID tru.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tk3 MODIF ID tru.
    PARAMETERS: p_tru_k3 TYPE string LOWER CASE MODIF ID tru.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tr3 MODIF ID tru.
    PARAMETERS: p_tru_r3 TYPE string LOWER CASE MODIF ID tru.
  SELECTION-SCREEN END OF LINE.
  " Transport 4
  SELECTION-SCREEN COMMENT /1(30) lbl_t4 MODIF ID tru.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tk4 MODIF ID tru.
    PARAMETERS: p_tru_k4 TYPE string LOWER CASE MODIF ID tru.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_tr4 MODIF ID tru.
    PARAMETERS: p_tru_r4 TYPE string LOWER CASE MODIF ID tru.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN SKIP 1.
  " Add-to-STMS-buffer checkbox (see B3 in plan)
  SELECTION-SCREEN BEGIN OF LINE.
    PARAMETERS: p_tru_bf AS CHECKBOX DEFAULT abap_false MODIF ID tru.
    SELECTION-SCREEN COMMENT 3(75) lbl_tbf FOR FIELD p_tru_bf MODIF ID tru.
  SELECTION-SCREEN END OF LINE.
SELECTION-SCREEN END OF BLOCK b_tru.

" --- STMS Buffer Add (multiple transports) ---
SELECTION-SCREEN BEGIN OF BLOCK b_stm WITH FRAME TITLE tit_stm.
  SELECTION-SCREEN COMMENT /1(79) txt_st1 MODIF ID stm.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lstmsys MODIF ID stm.
    PARAMETERS: p_stmsys TYPE tmssysnam DEFAULT sy-sysid MODIF ID stm.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lstmcli MODIF ID stm.
    PARAMETERS: p_stmcli TYPE mandt DEFAULT sy-mandt MODIF ID stm.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN SKIP 1.
  SELECT-OPTIONS s_stm_tr FOR e070-trkorr NO INTERVALS MODIF ID stm.
SELECTION-SCREEN END OF BLOCK b_stm.

SELECTION-SCREEN BEGIN OF BLOCK b_grp WITH FRAME TITLE tit_grp.
  SELECTION-SCREEN COMMENT /1(79) txt_g_1 MODIF ID grp.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_gdr MODIF ID grp.
    PARAMETERS: p_g_dir TYPE string LOWER CASE MODIF ID grp DEFAULT '/usr/sap/trans/log/'.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_gmk MODIF ID grp.
    PARAMETERS: p_g_msk TYPE string LOWER CASE MODIF ID grp DEFAULT '*'.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(25) lbl_gst MODIF ID grp.
    PARAMETERS: p_g_str TYPE string LOWER CASE MODIF ID grp.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN COMMENT /1(79) txt_g_2 MODIF ID grp.
SELECTION-SCREEN END OF BLOCK b_grp.

SELECTION-SCREEN BEGIN OF BLOCK b_net WITH FRAME TITLE tit_net.
  SELECTION-SCREEN COMMENT /1(79) txt_n_1 MODIF ID net.
  PARAMETERS: p_n_hst TYPE string LOWER CASE MODIF ID net.
  SELECTION-SCREEN BEGIN OF LINE.
    SELECTION-SCREEN COMMENT 1(10) lbl_ncmd MODIF ID net.
    PARAMETERS: p_nc_pn RADIOBUTTON GROUP ncm DEFAULT 'X' MODIF ID net.
    SELECTION-SCREEN COMMENT (7) lb_np FOR FIELD p_nc_pn MODIF ID net.
    PARAMETERS: p_nc_ns RADIOBUTTON GROUP ncm MODIF ID net.
    SELECTION-SCREEN COMMENT (10) lb_nn FOR FIELD p_nc_ns MODIF ID net.
    PARAMETERS: p_nc_tr RADIOBUTTON GROUP ncm MODIF ID net.
    SELECTION-SCREEN COMMENT (12) lb_nt FOR FIELD p_nc_tr MODIF ID net.
    PARAMETERS: p_nc_cu RADIOBUTTON GROUP ncm MODIF ID net.
    SELECTION-SCREEN COMMENT (6) lb_nc FOR FIELD p_nc_cu MODIF ID net.
  SELECTION-SCREEN END OF LINE.
  SELECTION-SCREEN COMMENT /1(79) txt_n_2 MODIF ID net.
SELECTION-SCREEN END OF BLOCK b_net.

SELECTION-SCREEN BEGIN OF BLOCK b_crt WITH FRAME TITLE tit_crt.
  SELECTION-SCREEN COMMENT /1(79) txt_c_1 MODIF ID crt.
  SELECTION-SCREEN COMMENT /1(79) txt_c_2 MODIF ID crt.
SELECTION-SCREEN END OF BLOCK b_crt.

SELECTION-SCREEN BEGIN OF BLOCK b_prf WITH FRAME TITLE tit_prf.
  SELECTION-SCREEN COMMENT /1(79) txt_p_1 MODIF ID prf.
  PARAMETERS: p_pf_nm TYPE string LOWER CASE MODIF ID prf.
  SELECTION-SCREEN COMMENT /1(79) txt_p_2 MODIF ID prf.
SELECTION-SCREEN END OF BLOCK b_prf.

*----------------------------------------------------------------------*
* INITIALIZATION
*----------------------------------------------------------------------*
INITIALIZATION.
  tit_inf = 'System Information'.
  tit_men = 'Basis Admin Toolbox - Main Menu'.
  tit_fm  = 'File Manager'.
  tit_zup = 'Upload Files (as ZIP)'.
  tit_trd = 'Transport Download (Server -> PC)'.
  tit_tru = 'Transport Upload (PC -> Server)'.
  tit_stm = 'STMS Buffer - Add Multiple Transports'.
  tit_grp = 'Search in Files (Grep)'.
  tit_net = 'Network Diagnostics'.
  tit_crt = 'SSL Certificate Checker'.
  tit_prf = 'Profile Parameters'.

  txt_ver = 'Version 1.0 RC1'.
  txt_f_1 = 'Navigate directories, download, upload, and delete files.'.
  txt_f_2 = 'Click on folders to navigate, click on files to download.'.
  txt_zu1 = 'ZIP content will be extracted flat into the target directory.'.
  txt_tr1 = 'Enter Transport Request (e.g. S4HK900123). K/R files are auto-detected.'.
  txt_tu1 = 'Select Co-File (K...) and Data-File (R...). Fill only what you need.'.
  txt_st1 = 'Add multiple transports to the STMS import buffer of the target system.'.
  txt_g_1 = 'Path to search in (e.g. /usr/sap/trans/log/).'.
  txt_g_2 = 'Filter example: dev_* or SLOG*. Search term is case-insensitive.'.
  txt_n_1 = 'Enter hostname or IP address to diagnose.'.
  txt_n_2 = 'For curl: enter full URL (e.g. https://example.com).'.
  txt_c_1 = 'Shows all PSE certificates from STRUST with expiry status.'.
  txt_c_2 = 'Press Execute (F8) to load certificate overview.'.
  txt_p_1 = 'Optional filter: parameter name pattern (e.g. rdisp/* or icm/*).'.
  txt_p_2 = 'Leave empty to show all parameters. Press Execute (F8).'.

  " Network Diagnostics labels
  lbl_ncmd = 'Command:'.
  lb_np = 'Ping'. lb_nn = 'NSLookup'. lb_nt = 'Traceroute'. lb_nc = 'Curl'.

  " Transport Upload labels
  lbl_t1 = '--- Transport 1 ---'.
  lbl_t2 = '--- Transport 2 ---'.
  lbl_t3 = '--- Transport 3 ---'.
  lbl_t4 = '--- Transport 4 ---'.

  " Inline parameter labels (plan B1)
  lbl_zuf = 'ZIP file (PC):'.
  lbl_zud = 'Target directory:'.
  lbl_tid = 'Transport Request:'.
  lbl_tsd = 'Source directory:'.
  lbl_ttd = 'Target directory:'.
  lbl_tk1 = 'Co-file (K...):'.
  lbl_tr1 = 'Data-file (R...):'.
  lbl_tk2 = 'Co-file (K...):'.
  lbl_tr2 = 'Data-file (R...):'.
  lbl_tk3 = 'Co-file (K...):'.
  lbl_tr3 = 'Data-file (R...):'.
  lbl_tk4 = 'Co-file (K...):'.
  lbl_tr4 = 'Data-file (R...):'.
  lbl_gdr = 'Directory:'.
  lbl_gmk = 'File pattern:'.
  lbl_gst = 'Search term:'.
  " Dynamic label for Add-to-STMS-buffer checkbox (plan B3)
  lbl_tbf = |Add to STMS import buffer of { sy-sysid }/{ sy-mandt } after upload|.

  " STMS Buffer (multi-transport) labels
  lstmsys = 'Target system:'.
  lstmcli = 'Target client:'.

  btn_fm  = 'File Manager'.
  btn_zup = 'Upload Files (as ZIP)'.
  btn_trd = 'Transport Down'.
  btn_tru = 'Transport Up'.
  btn_stm = 'STMS Buffer'.
  btn_net = 'Network Diagnostics'.
  btn_crt = 'Certificate Checker'.
  btn_grp = 'Search (Grep)'.
  btn_prf = 'Profile Parameters'.
  btn_sys = 'System Info'.

  PERFORM set_icon USING 'ICON_OPEN_LOCAL_OBJECT' CHANGING btn_fm.
  PERFORM set_icon USING 'ICON_IMPORT'           CHANGING btn_zup.
  PERFORM set_icon USING 'ICON_TRANSPORT'        CHANGING btn_trd.
  PERFORM set_icon USING 'ICON_TRANSPORT'        CHANGING btn_tru.
  PERFORM set_icon USING 'ICON_TRANSPORT'        CHANGING btn_stm.
  PERFORM set_icon USING 'ICON_WF_WORKITEM'      CHANGING btn_net.
  PERFORM set_icon USING 'ICON_LOCKED'           CHANGING btn_crt.
  PERFORM set_icon USING 'ICON_SEARCH'           CHANGING btn_grp.
  PERFORM set_icon USING 'ICON_PARAMETER'        CHANGING btn_prf.
  PERFORM set_icon USING 'ICON_SYSTEM_INFO'      CHANGING btn_sys.
  PERFORM get_system_info.

  " Security: Debug mode detection (compile-time flag OR Z_BASIS_TOOL_DEBUG role)
  IF c_debug_mode = abap_true.
    gv_debug_active = abap_true.
  ELSE.
    AUTHORITY-CHECK OBJECT 'Z_BASTOOL'
      ID 'ZBAS_MODL' FIELD '*'
      ID 'ZBAS_ACTN' FIELD c_actn_debug.
    IF sy-subrc = 0.
      gv_debug_active = abap_true.
    ENDIF.
  ENDIF.

  IF gv_debug_active = abap_true.
    DATA: lv_debug_ans    TYPE c LENGTH 1,
          lv_confirm_noau TYPE c LENGTH 1,
          lv_dbg_origin   TYPE string,
          lv_log_missing  TYPE abap_bool.

    " 3-option popup: With Audit / No Audit / Abort.
    " POPUP_TO_DECIDE has only 2 option-text params on most releases, so we
    " use POPUP_TO_CONFIRM with display_cancel_button = 'X' (answer 'A' = cancel/abort).
    CALL FUNCTION 'POPUP_TO_CONFIRM'
      EXPORTING
        titlebar              = '*** Z_BASIS_TOOLBOX - DEBUG MODE ***'
        text_question         = '>>> DEBUG MODE will be activated <<< Auth checks and PRD restrictions are BYPASSED. Choose: Continue with Audit, Continue without Audit, or Abort (Cancel).'
        text_button_1         = 'With Audit'
        text_button_2         = 'No Audit'
        default_button        = '1'
        display_cancel_button = 'X'
      IMPORTING
        answer                = lv_debug_ans
      EXCEPTIONS
        OTHERS                = 1.

    " Abort (Cancel button -> 'A', Esc -> 'A', or FM error)
    IF lv_debug_ans = 'A' OR lv_debug_ans IS INITIAL OR sy-subrc <> 0.
      LEAVE PROGRAM.
    ENDIF.

    " Option 1: Continue with Audit -> probe ZBAS_TOOL_LOG, enable audit, log start
    IF lv_debug_ans = '1'.
      TRY.
          DATA lr_probe_log TYPE REF TO data.
          CREATE DATA lr_probe_log TYPE ('ZBAS_TOOL_LOG').
          lv_log_missing = abap_false.
        CATCH cx_root.
          lv_log_missing = abap_true.
      ENDTRY.
      IF lv_log_missing = abap_true.
        MESSAGE 'ZBAS_TOOL_LOG not activated - "with Audit" is impossible on this system. Create the table or use "no Audit".' TYPE 'S' DISPLAY LIKE 'E'.
        LEAVE PROGRAM.
      ENDIF.
      gv_debug_audit = abap_true.
      IF c_debug_mode = abap_true.
        lv_dbg_origin = 'Origin=c_debug_mode flag'.
      ELSE.
        lv_dbg_origin = 'Origin=Z_BASTOOL ACTN=99 role'.
      ENDIF.
      PERFORM write_audit_log USING c_mod_sys 'DEBUG_MODE_START' sy-uname lv_dbg_origin 'C'.
    ENDIF.

    " Option 2: Continue no Audit -> require explicit second confirmation
    IF lv_debug_ans = '2'.
      CALL FUNCTION 'POPUP_TO_CONFIRM'
        EXPORTING
          titlebar              = 'Disable audit - are you really sure?'
          text_question         = 'ALL audit logging will be disabled, including deletes on PRD. This action itself will not be recorded. Continue?'
          text_button_1         = 'Yes, disable audit'
          text_button_2         = 'No, go back'
          default_button        = '2'
          display_cancel_button = abap_false
        IMPORTING
          answer                = lv_confirm_noau
        EXCEPTIONS
          OTHERS                = 1.
      IF lv_confirm_noau <> '1'.
        LEAVE PROGRAM.
      ENDIF.
      gv_debug_audit = abap_false.
    ENDIF.
  ENDIF.

  " Security: Detect if running on a productive system
  PERFORM detect_production_system.

  " Security: Verify required DDIC objects exist (skipped in debug mode)
  IF gv_debug_active = abap_false.
    PERFORM check_ddic_objects.
  ENDIF.

  " Security: Populate button -> module map (shared by INIT startup check and PBO graying)
  gt_btn_auth = VALUE #(
    ( btn = 'BTN_FM'  mod = c_mod_fm  )
    ( btn = 'BTN_ZUP' mod = c_mod_zup )
    ( btn = 'BTN_TRD' mod = c_mod_trd )
    ( btn = 'BTN_TRU' mod = c_mod_tru )
    ( btn = 'BTN_STM' mod = c_mod_stm )
    ( btn = 'BTN_GRP' mod = c_mod_grp )
    ( btn = 'BTN_NET' mod = c_mod_net )
    ( btn = 'BTN_CRT' mod = c_mod_crt )
    ( btn = 'BTN_PRF' mod = c_mod_prf )
    ( btn = 'BTN_SYS' mod = c_mod_sys ) ).

  " Security: Check basic authorization at program start (skipped in debug mode)
  " User needs Z_BASTOOL for at least one module to start the report
  IF gv_debug_active = abap_false.
    DATA: ls_btn_auth_i TYPE ty_btn_auth,
          lv_has_auth_i TYPE abap_bool.
    gv_auth_ok = abap_false.
    LOOP AT gt_btn_auth INTO ls_btn_auth_i.
      PERFORM has_module_auth USING ls_btn_auth_i-mod CHANGING lv_has_auth_i.
      IF lv_has_auth_i = abap_true.
        gv_auth_ok = abap_true.
        EXIT.
      ENDIF.
    ENDLOOP.
    IF gv_auth_ok = abap_false.
      MESSAGE 'No authorization for Z_BASIS_TOOLBOX.' TYPE 'S' DISPLAY LIKE 'E'.
      LEAVE PROGRAM.
    ENDIF.
  ELSE.
    gv_auth_ok = abap_true.
  ENDIF.

  " End of INITIALIZATION: transition from blank init mode to menu mode.
  " Up to this point gv_mode = c_mode_init so any popup (debug confirmation)
  " renders over an empty selection screen. From here on the first PBO
  " will draw the menu normally.
  gv_mode = c_mode_menu.

*----------------------------------------------------------------------*
* PBO
*----------------------------------------------------------------------*
AT SELECTION-SCREEN OUTPUT.
  LOOP AT SCREEN.
    " During init mode (popup phase) the whole screen stays blank — hide every group.
    IF gv_mode = c_mode_init.
      IF screen-group1 IS NOT INITIAL.
        screen-active = 0.
        MODIFY SCREEN.
        CONTINUE.
      ENDIF.
    ENDIF.
    IF screen-group1 = 'INF'.
      screen-input = 0.
    ENDIF.
    IF screen-group1 = 'MEN'.
      IF gv_mode = c_mode_menu.
        screen-active = 1.
        " Gray out buttons user has no authorization for
        DATA: ls_btn_auth_p TYPE ty_btn_auth,
              lv_has_auth_p TYPE abap_bool.
        READ TABLE gt_btn_auth INTO ls_btn_auth_p WITH KEY btn = screen-name.
        IF sy-subrc = 0.
          PERFORM has_module_auth USING ls_btn_auth_p-mod CHANGING lv_has_auth_p.
          IF lv_has_auth_p = abap_false.
            screen-input = 0.
          ENDIF.
        ENDIF.
      ELSE.
        screen-active = 0.
      ENDIF.
    ENDIF.
    IF screen-group1 = 'FM'.
      IF gv_mode = c_mode_fm.
        screen-active = 1.
      ELSE.
        screen-active = 0.
      ENDIF.
    ENDIF.
    IF screen-group1 = 'ZUP'.
      IF gv_mode = c_mode_zup. screen-active = 1. ELSE. screen-active = 0. ENDIF.
    ENDIF.
    IF screen-group1 = 'TRD'.
      IF gv_mode = c_mode_trd. screen-active = 1. ELSE. screen-active = 0. ENDIF.
    ENDIF.
    IF screen-group1 = 'TRU'.
      IF gv_mode = c_mode_tru. screen-active = 1. ELSE. screen-active = 0. ENDIF.
    ENDIF.
    IF screen-group1 = 'STM'.
      IF gv_mode = c_mode_stm. screen-active = 1. ELSE. screen-active = 0. ENDIF.
    ENDIF.
    IF screen-group1 = 'GRP'.
      IF gv_mode = c_mode_grp. screen-active = 1. ELSE. screen-active = 0. ENDIF.
    ENDIF.
    IF screen-group1 = 'NET'.
      IF gv_mode = c_mode_net. screen-active = 1. ELSE. screen-active = 0. ENDIF.
    ENDIF.
    IF screen-group1 = 'CRT'.
      IF gv_mode = c_mode_cert. screen-active = 1. ELSE. screen-active = 0. ENDIF.
    ENDIF.
    IF screen-group1 = 'PRF'.
      IF gv_mode = c_mode_prof. screen-active = 1. ELSE. screen-active = 0. ENDIF.
    ENDIF.
    MODIFY SCREEN.
  ENDLOOP.

*----------------------------------------------------------------------*
* PAI
*----------------------------------------------------------------------*
AT SELECTION-SCREEN ON EXIT-COMMAND.
  IF gv_mode NE c_mode_menu.
    gv_mode = c_mode_menu.
    CLEAR sscrfields-ucomm.
    IF go_container IS NOT INITIAL.
      CALL METHOD go_container->free.
      CLEAR: go_container, go_grid, go_event.
    ENDIF.
    LEAVE TO SCREEN 1000.
  ENDIF.

AT SELECTION-SCREEN.
  IF sscrfields-ucomm = 'FC03' OR sscrfields-ucomm = 'BACK'.
    IF gv_mode NE c_mode_menu.
      gv_mode = c_mode_menu.
      CLEAR sscrfields-ucomm.
      IF go_container IS NOT INITIAL.
        CALL METHOD go_container->free.
        CLEAR: go_container, go_grid, go_event.
      ENDIF.
      LEAVE TO SCREEN 1000.
      RETURN.
    ENDIF.
  ENDIF.

  " Hotspot/nav navigation: screen transport overwrites p_fm_dir with old value,
  " so we restore it from gv_current_dir which was set during the event handler.
  " IMPORTANT: Do NOT clear ucomm here, or it falls into the ONLI block below.
  IF sscrfields-ucomm = 'REFRESH_DIR'.
    p_fm_dir = gv_current_dir.
    sscrfields-ucomm = 'HANDLED'.
  ENDIF.

  DATA lv_log_detail TYPE string.

  IF sscrfields-ucomm = 'ONLI' OR sscrfields-ucomm IS INITIAL.
    IF gv_mode = c_mode_fm.
      PERFORM list_files_fm USING p_fm_dir.
      CLEAR sscrfields-ucomm.
    ELSEIF gv_mode = c_mode_zup.
      PERFORM execute_zip_upload.
      CLEAR sscrfields-ucomm.
    ELSEIF gv_mode = c_mode_grp.
      CONCATENATE p_g_msk ':' p_g_str INTO lv_log_detail SEPARATED BY space.
      PERFORM write_audit_log USING c_mod_grp 'GREP_EXECUTE' p_g_dir lv_log_detail 'I'.
      PERFORM execute_grep.
      CLEAR sscrfields-ucomm.
    ELSEIF gv_mode = c_mode_trd.
      PERFORM write_audit_log USING c_mod_trd 'TRANS_DL_START' p_tr_id p_tr_dir 'I'.
      PERFORM execute_trans_download.
      CLEAR sscrfields-ucomm.
    ELSEIF gv_mode = c_mode_tru.
      PERFORM write_audit_log USING c_mod_tru 'TRANS_UL_START' p_tru_td '' 'W'.
      PERFORM execute_trans_upload.
      CLEAR sscrfields-ucomm.
    ELSEIF gv_mode = c_mode_stm.
      PERFORM write_audit_log USING c_mod_stm 'STMS_BUFFER_START' p_stmsys p_stmcli 'W'.
      PERFORM execute_stms_buffer.
      CLEAR sscrfields-ucomm.
    ELSEIF gv_mode = c_mode_net.
      IF p_nc_pn = 'X'. lv_log_detail = 'Ping'.
      ELSEIF p_nc_ns = 'X'. lv_log_detail = 'NSLookup'.
      ELSEIF p_nc_tr = 'X'. lv_log_detail = 'Traceroute'.
      ELSEIF p_nc_cu = 'X'. lv_log_detail = 'Curl'.
      ENDIF.
      PERFORM write_audit_log USING c_mod_net 'NET_EXECUTE' p_n_hst lv_log_detail 'I'.
      PERFORM execute_network_diag.
      CLEAR sscrfields-ucomm.
    ELSEIF gv_mode = c_mode_cert.
      PERFORM write_audit_log USING c_mod_crt 'CERT_SCAN' '' '' 'I'.
      PERFORM execute_cert_checker.
      CLEAR sscrfields-ucomm.
    ELSEIF gv_mode = c_mode_prof.
      PERFORM write_audit_log USING c_mod_prf 'PROFILE_READ' p_pf_nm '' 'I'.
      PERFORM execute_profile_params.
      CLEAR sscrfields-ucomm.
    ENDIF.
  ENDIF.

  CASE sscrfields-ucomm.
    WHEN 'CMD_FM'.
      PERFORM check_authorization USING c_mod_fm c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        gv_mode = c_mode_fm.
        " Check if user has write access (Execute) for FM
        AUTHORITY-CHECK OBJECT 'Z_BASTOOL' ID 'ZBAS_MODL' FIELD 'FM' ID 'ZBAS_ACTN' FIELD '02'.
        IF sy-subrc = 0.
          gv_fm_write = abap_true.
        ELSE.
          gv_fm_write = abap_false.
        ENDIF.
        PERFORM write_audit_log USING c_mod_fm 'MODULE_ENTER' 'File Manager' '' 'I'.
        PERFORM list_files_fm USING p_fm_dir.
      ENDIF.
      CLEAR sscrfields-ucomm.
    WHEN 'CMD_ZUP'.
      PERFORM check_authorization USING c_mod_zup c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        gv_mode = c_mode_zup.
        PERFORM write_audit_log USING c_mod_zup 'MODULE_ENTER' 'ZIP Upload' '' 'I'.
      ENDIF.
      CLEAR sscrfields-ucomm.
    WHEN 'CMD_TRD'.
      PERFORM check_authorization USING c_mod_trd c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        gv_mode = c_mode_trd.
        PERFORM write_audit_log USING c_mod_trd 'MODULE_ENTER' 'Transport Download' '' 'I'.
      ENDIF.
      CLEAR sscrfields-ucomm.
    WHEN 'CMD_TRU'.
      PERFORM check_authorization USING c_mod_tru c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        gv_mode = c_mode_tru.
        PERFORM write_audit_log USING c_mod_tru 'MODULE_ENTER' 'Transport Upload' '' 'I'.
      ENDIF.
      CLEAR sscrfields-ucomm.
    WHEN 'CMD_STM'.
      PERFORM check_authorization USING c_mod_stm c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        gv_mode = c_mode_stm.
        PERFORM write_audit_log USING c_mod_stm 'MODULE_ENTER' 'STMS Buffer Add' '' 'I'.
      ENDIF.
      CLEAR sscrfields-ucomm.
    WHEN 'CMD_GRP'.
      PERFORM check_authorization USING c_mod_grp c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        gv_mode = c_mode_grp.
        PERFORM write_audit_log USING c_mod_grp 'MODULE_ENTER' 'Grep' '' 'I'.
      ENDIF.
      CLEAR sscrfields-ucomm.
    WHEN 'CMD_NET'.
      PERFORM check_authorization USING c_mod_net c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        gv_mode = c_mode_net.
        PERFORM write_audit_log USING c_mod_net 'MODULE_ENTER' 'Network Diagnostics' '' 'I'.
      ENDIF.
      CLEAR sscrfields-ucomm.
    WHEN 'CMD_CRT'.
      PERFORM check_authorization USING c_mod_crt c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        gv_mode = c_mode_cert.
        PERFORM write_audit_log USING c_mod_crt 'MODULE_ENTER' 'Certificate Checker' '' 'I'.
      ENDIF.
      CLEAR sscrfields-ucomm.
    WHEN 'CMD_PRF'.
      PERFORM check_authorization USING c_mod_prf c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        gv_mode = c_mode_prof.
        PERFORM write_audit_log USING c_mod_prf 'MODULE_ENTER' 'Profile Parameters' '' 'I'.
      ENDIF.
      CLEAR sscrfields-ucomm.
    WHEN 'CMD_SYS'.
      PERFORM check_authorization USING c_mod_sys c_actn_display CHANGING gv_auth_ok.
      IF gv_auth_ok = abap_true.
        PERFORM write_audit_log USING c_mod_sys 'SYSTEM_INFO' 'System Info popup' '' 'I'.
        PERFORM execute_system_info.
      ENDIF.
      CLEAR sscrfields-ucomm.
  ENDCASE.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_fm_dir.
  PERFORM f4_dir_open USING p_fm_dir.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_zu_fil.
  PERFORM f4_file_open USING p_zu_fil 'X'.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_tru_k1.
  PERFORM f4_tru_file USING 'P_TRU_K1' 'P_TRU_R1' CHANGING p_tru_k1 p_tru_r1.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_tru_r1.
  PERFORM f4_tru_file USING 'P_TRU_R1' 'P_TRU_K1' CHANGING p_tru_r1 p_tru_k1.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_tru_k2.
  PERFORM f4_tru_file USING 'P_TRU_K2' 'P_TRU_R2' CHANGING p_tru_k2 p_tru_r2.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_tru_r2.
  PERFORM f4_tru_file USING 'P_TRU_R2' 'P_TRU_K2' CHANGING p_tru_r2 p_tru_k2.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_tru_k3.
  PERFORM f4_tru_file USING 'P_TRU_K3' 'P_TRU_R3' CHANGING p_tru_k3 p_tru_r3.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_tru_r3.
  PERFORM f4_tru_file USING 'P_TRU_R3' 'P_TRU_K3' CHANGING p_tru_r3 p_tru_k3.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_tru_k4.
  PERFORM f4_tru_file USING 'P_TRU_K4' 'P_TRU_R4' CHANGING p_tru_k4 p_tru_r4.

AT SELECTION-SCREEN ON VALUE-REQUEST FOR p_tru_r4.
  PERFORM f4_tru_file USING 'P_TRU_R4' 'P_TRU_K4' CHANGING p_tru_r4 p_tru_k4.

" STMS Buffer: validate trkorr format (3-char SID + K + digits) for each input row.
" Only validates Includes/EQ entries; excludes/ranges are reported but not blocked here.
AT SELECTION-SCREEN ON s_stm_tr.
  DATA lv_stm_tr TYPE string.
  LOOP AT s_stm_tr.
    IF s_stm_tr-sign = 'I' AND s_stm_tr-option = 'EQ' AND s_stm_tr-low IS NOT INITIAL.
      lv_stm_tr = s_stm_tr-low.
      TRANSLATE lv_stm_tr TO UPPER CASE.
      IF NOT lv_stm_tr CO '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
      OR strlen( lv_stm_tr ) < 5
      OR lv_stm_tr+3(1) <> 'K'.
        MESSAGE |Invalid transport ID '{ s_stm_tr-low }' (expected: <SID>K<digits>)| TYPE 'E'.
      ENDIF.
    ENDIF.
  ENDLOOP.

START-OF-SELECTION.
  " Empty

*======================================================================*
* CLASS IMPLEMENTATION
*======================================================================*
CLASS lcl_event_receiver IMPLEMENTATION.
  METHOD handle_toolbar.
    DATA: ls_toolbar TYPE stb_button.

    " Separator
    CLEAR ls_toolbar.
    ls_toolbar-function = 'DUMMY'.
    ls_toolbar-butn_type = 3.
    APPEND ls_toolbar TO e_object->mt_toolbar.

    IF gv_mode = c_mode_fm.
      " Back
      CLEAR ls_toolbar.
      ls_toolbar-function = 'NAV_BACK'.
      ls_toolbar-icon = icon_previous_object.
      ls_toolbar-text = 'Back'.
      ls_toolbar-butn_type = 0.
      IF gv_nav_idx <= 1. ls_toolbar-disabled = 'X'. ENDIF.
      APPEND ls_toolbar TO e_object->mt_toolbar.

      " Forward
      CLEAR ls_toolbar.
      ls_toolbar-function = 'NAV_FORWARD'.
      ls_toolbar-icon = icon_next_object.
      ls_toolbar-text = 'Forward'.
      ls_toolbar-butn_type = 0.
      IF gv_nav_idx >= lines( gt_nav_history ). ls_toolbar-disabled = 'X'. ENDIF.
      APPEND ls_toolbar TO e_object->mt_toolbar.

      " Separator
      CLEAR ls_toolbar.
      ls_toolbar-function = 'DUMMY_NAV'.
      ls_toolbar-butn_type = 3.
      APPEND ls_toolbar TO e_object->mt_toolbar.

      " Download Selected
      CLEAR ls_toolbar.
      ls_toolbar-function = 'DOWNLOAD_SELECTED'.
      ls_toolbar-icon = icon_export.
      ls_toolbar-text = 'Download Selected'.
      ls_toolbar-butn_type = 0.
      APPEND ls_toolbar TO e_object->mt_toolbar.

      " Upload Files (write access required)
      IF gv_fm_write = abap_true.
        ls_toolbar-function = 'UPLOAD_FILES'.
        ls_toolbar-icon = icon_import.
        ls_toolbar-text = 'Upload Files'.
        ls_toolbar-butn_type = 0.
        APPEND ls_toolbar TO e_object->mt_toolbar.

        " Copy File
        ls_toolbar-function = 'COPY_FILE'.
        ls_toolbar-icon = icon_copy_object.
        ls_toolbar-text = 'Copy File'.
        ls_toolbar-butn_type = 0.
        APPEND ls_toolbar TO e_object->mt_toolbar.

        " Rename File
        ls_toolbar-function = 'RENAME_FILE'.
        ls_toolbar-icon = icon_change.
        ls_toolbar-text = 'Rename File'.
        ls_toolbar-butn_type = 0.
        APPEND ls_toolbar TO e_object->mt_toolbar.

        " Delete Selected
        ls_toolbar-function = 'DELETE_SELECTED'.
        ls_toolbar-icon = icon_delete.
        ls_toolbar-text = 'Delete Selected'.
        ls_toolbar-butn_type = 0.
        APPEND ls_toolbar TO e_object->mt_toolbar.

        " Separator before utility actions
        CLEAR ls_toolbar.
        ls_toolbar-function = 'DUMMY2'.
        ls_toolbar-butn_type = 3.
        APPEND ls_toolbar TO e_object->mt_toolbar.

        " Create Directory
        CLEAR ls_toolbar.
        ls_toolbar-function = 'CREATE_DIR'.
        ls_toolbar-icon = icon_create.
        ls_toolbar-text = 'Create Dir'.
        ls_toolbar-butn_type = 0.
        APPEND ls_toolbar TO e_object->mt_toolbar.
      ENDIF.

      " Refresh
      ls_toolbar-function = 'REFRESH'.
      ls_toolbar-icon = icon_refresh.
      ls_toolbar-text = 'Refresh'.
      ls_toolbar-butn_type = 0.
      APPEND ls_toolbar TO e_object->mt_toolbar.
    ENDIF.
  ENDMETHOD.

  METHOD handle_user_command.
    PERFORM handle_grid_command USING e_ucomm.
  ENDMETHOD.

  METHOD on_hotspot_click.
    DATA: lv_idx TYPE i,
          lv_col TYPE string.

    lv_idx = e_row_id-index.
    lv_col = e_column_id-fieldname.
    PERFORM handle_grid_hotspot USING lv_idx lv_col.
  ENDMETHOD.
ENDCLASS.

*======================================================================*
* FORMS
*======================================================================*
FORM set_icon USING iv_name TYPE string CHANGING cv_text TYPE any.
  CALL FUNCTION 'ICON_CREATE'
    EXPORTING
      name   = iv_name
      text   = cv_text
    IMPORTING
      result = cv_text
    EXCEPTIONS
      OTHERS = 0.
ENDFORM.

FORM get_system_info.
  lbl_sid = 'System ID:'.
  lbl_cli = 'Client:'.
  lbl_hst = 'Server Host:'.
  lbl_rel = 'SAP Release:'.
  lbl_dbs = 'Database ID:'.
  lbl_dbh = 'Database Host:'.
  lbl_dbv = 'DB Version:'.

  val_sid = sy-sysid.
  val_cli = sy-mandt.
  val_hst = sy-host.
  val_rel = sy-saprl.
  val_dbs = sy-dbsys.

  DATA: lo_sql             TYPE REF TO cl_sql_statement,
        lo_res             TYPE REF TO cl_sql_result_set,
        lv_sql             TYPE string,
        lv_db_version_long TYPE string,
        lv_db_host_long    TYPE string.

  DATA: lt_split_ver TYPE TABLE OF string,
        lv_p1        TYPE string,
        lv_p2        TYPE string,
        lv_p3        TYPE string.

  TRY.
      CREATE OBJECT lo_sql.

      " Get DB Host
      lv_sql = 'SELECT HOST FROM M_HOST_INFORMATION LIMIT 1'.
      lo_res = lo_sql->execute_query( lv_sql ).
      lo_res->set_param( REF #( lv_db_host_long ) ).
      lo_res->next( ).
      lo_res->close( ).
      val_dbh = lv_db_host_long.

      " Get DB Version
      lv_sql = 'SELECT VERSION FROM M_DATABASE LIMIT 1'.
      lo_res = lo_sql->execute_query( lv_sql ).
      lo_res->set_param( REF #( lv_db_version_long ) ).
      lo_res->next( ).
      lo_res->close( ).

      SPLIT lv_db_version_long AT '.' INTO TABLE lt_split_ver.
      IF lines( lt_split_ver ) >= 3.
        READ TABLE lt_split_ver INTO lv_p1 INDEX 1.
        READ TABLE lt_split_ver INTO lv_p2 INDEX 2.
        READ TABLE lt_split_ver INTO lv_p3 INDEX 3.
        CONCATENATE lv_p1 '.' lv_p2 '.' lv_p3 INTO val_dbv.
      ELSE.
        val_dbv = lv_db_version_long.
      ENDIF.
    CATCH cx_root.
      val_dbh = 'Unknown'.
      val_dbv = 'Unknown'.
  ENDTRY.
ENDFORM.

*--- LIST FILES (FILE MANAGER) ---*
FORM list_files_fm USING iv_dir TYPE string.
  IF iv_dir IS INITIAL.
    MESSAGE 'Please specify a directory path.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Normalize input directory
  gv_current_dir = iv_dir.
  CONDENSE gv_current_dir NO-GAPS.

  " Create container if not exists
  IF go_container IS INITIAL.
    CREATE OBJECT go_container
      EXPORTING
        side  = cl_gui_docking_container=>dock_at_bottom
        ratio = 65
      EXCEPTIONS
        OTHERS = 1.

    IF sy-subrc <> 0.
      MESSAGE 'Failed to create container.' TYPE 'S' DISPLAY LIKE 'E'.
      RETURN.
    ENDIF.
  ENDIF.

  " Refresh file list
  PERFORM refresh_file_list.

  " Keep input field in sync with actual directory
  p_fm_dir = gv_current_dir.

  " Push to navigation history (unless navigating via Back/Forward)
  IF gv_nav_no_push = abap_false.
    " Truncate forward history if we navigate to a new dir after going back
    IF gv_nav_idx < lines( gt_nav_history ).
      DATA lv_del_idx TYPE i.
      lv_del_idx = gv_nav_idx + 1.
      WHILE lv_del_idx <= lines( gt_nav_history ).
        DELETE gt_nav_history INDEX lv_del_idx.
      ENDWHILE.
    ENDIF.
    APPEND gv_current_dir TO gt_nav_history.
    gv_nav_idx = lines( gt_nav_history ).
  ENDIF.
  CLEAR gv_nav_no_push.

  " Show grid
  PERFORM show_grid_fm.
ENDFORM.

*--- REFRESH FILE LIST WITH CLEANUP ---*
FORM refresh_file_list.
  DATA: lv_dir_name  TYPE c LENGTH 255,
        lv_file_name TYPE c LENGTH 255,
        lv_errno(3)  TYPE c,
        lv_errmsg(40) TYPE c,
        lv_type(10)  TYPE c,
        lv_size_c(20) TYPE c,
        lv_mtime_p   TYPE p,
        lv_owner(20) TYPE c.

  DATA: ls_file TYPE ty_file_item,
        lv_len  TYPE i,
        lv_off  TYPE i,
        lv_cnt  TYPE i.

  " CRITICAL FIX: Always finish any previous directory read
  CALL 'C_DIR_READ_FINISH'
    ID 'ERRNO'  FIELD lv_errno
    ID 'ERRMSG' FIELD lv_errmsg.

  " Normalize directory path - remove all trailing slashes
  WHILE strlen( gv_current_dir ) > 1.
    lv_len = strlen( gv_current_dir ).
    lv_off = lv_len - 1.
    IF gv_current_dir+lv_off(1) = '/' OR gv_current_dir+lv_off(1) = '\'.
      gv_current_dir = gv_current_dir(lv_off).
    ELSE.
      EXIT.
    ENDIF.
  ENDWHILE.

  " Handle root directory
  IF gv_current_dir IS INITIAL OR gv_current_dir = '/'.
    gv_current_dir = '/'.
  ELSE.
    " Add single trailing slash
    CONCATENATE gv_current_dir '/' INTO gv_current_dir.
  ENDIF.

  lv_dir_name = gv_current_dir.
  CLEAR gt_file_list.

  " Start directory read
  CALL 'C_DIR_READ_START'
    ID 'DIR'    FIELD lv_dir_name
    ID 'FILE'   FIELD '*'
    ID 'ERRNO'  FIELD lv_errno
    ID 'ERRMSG' FIELD lv_errmsg.

  IF sy-subrc <> 0.
    MESSAGE |Directory read failed: { lv_errmsg } (errno: { lv_errno })| TYPE 'I'.

    " Add error entry
    CLEAR ls_file.
    ls_file-name = '(Error reading directory)'.
    ls_file-type = 'ERROR'.
    ls_file-icon = '@0A@'.
    ls_file-sort_type = '9'.
    APPEND ls_file TO gt_file_list.

    IF go_grid IS BOUND.
      CALL METHOD go_grid->refresh_table_display.
    ENDIF.
    RETURN.
  ENDIF.

  " Add parent directory navigation
  IF gv_current_dir <> '/' AND gv_current_dir <> '\'.
    CLEAR ls_file.
    ls_file-name = '[..]  Parent Directory'.
    ls_file-type = 'UP'.
    ls_file-icon = '@38@'.
    ls_file-sort_type = '1'.

    " Calculate parent path
    PERFORM get_parent_path USING gv_current_dir CHANGING ls_file-abspath.
    APPEND ls_file TO gt_file_list.
  ENDIF.

  " Read directory entries
  DO.
    CALL 'C_DIR_READ_NEXT'
      ID 'TYPE'   FIELD lv_type
      ID 'NAME'   FIELD lv_file_name
      ID 'LEN'    FIELD lv_size_c
      ID 'MTIME'  FIELD lv_mtime_p
      ID 'OWNER'  FIELD lv_owner
      ID 'ERRNO'  FIELD lv_errno
      ID 'ERRMSG' FIELD lv_errmsg.

    IF sy-subrc <> 0.
      EXIT.
    ENDIF.

    " Skip . and ..
    IF lv_file_name = '.' OR lv_file_name = '..'.
      CONTINUE.
    ENDIF.

    " Build file item
    CLEAR ls_file.
    ls_file-name = lv_file_name.
    ls_file-size = lv_size_c.
    ls_file-owner = lv_owner.

    " Format human-readable size
    PERFORM format_size USING ls_file-size CHANGING ls_file-size_fmt.

    " Convert timestamp
    PERFORM convert_timestamp USING lv_mtime_p
                               CHANGING ls_file-date
                                        ls_file-time.

    " Format datetime
    PERFORM format_datetime USING ls_file-date
                                  ls_file-time
                            CHANGING ls_file-datetime.

    " Build absolute path
    CONCATENATE gv_current_dir lv_file_name INTO ls_file-abspath.

    " Determine type and icon
    IF lv_type CP 'dir*'.
      ls_file-type = 'DIR'.
      ls_file-sort_type = '2'.
      ls_file-icon = icon_open_folder.
    ELSE.
      ls_file-type = 'FILE'.
      ls_file-sort_type = '3'.
      ls_file-icon = icon_xls.
    ENDIF.

    APPEND ls_file TO gt_file_list.
    ADD 1 TO lv_cnt.
  ENDDO.

  " Finish directory read
  CALL 'C_DIR_READ_FINISH'
    ID 'ERRNO'  FIELD lv_errno
    ID 'ERRMSG' FIELD lv_errmsg.

  " Sort: Up -> Directories -> Files
  SORT gt_file_list BY sort_type ASCENDING name ASCENDING.

  " Debug message
  MESSAGE |Found { lv_cnt } entries in { gv_current_dir }| TYPE 'S'.
ENDFORM.

*--- GET PARENT PATH ---*
FORM get_parent_path USING iv_path TYPE string
                     CHANGING cv_parent TYPE string.
  DATA: lv_temp_path TYPE string,
        lt_split     TYPE TABLE OF string,
        lv_cnt       TYPE i,
        lv_part      TYPE string,
        lv_len       TYPE i.

  lv_temp_path = iv_path.

  " Remove trailing slash
  lv_len = strlen( lv_temp_path ).
  IF lv_len > 1.
    lv_len = lv_len - 1.
    lv_temp_path = lv_temp_path(lv_len).
  ENDIF.

  " Split path
  SPLIT lv_temp_path AT '/' INTO TABLE lt_split.
  lv_cnt = lines( lt_split ).

  " Remove last element
  IF lv_cnt > 0.
    DELETE lt_split INDEX lv_cnt.
  ENDIF.

  " Rebuild path
  CLEAR cv_parent.
  IF lines( lt_split ) = 0.
    cv_parent = '/'.
  ELSE.
    LOOP AT lt_split INTO lv_part.
      IF sy-tabix = 1 AND lv_part IS INITIAL.
        cv_parent = '/'.
      ELSE.
        IF cv_parent = '/'.
          CONCATENATE cv_parent lv_part INTO cv_parent.
        ELSE.
          CONCATENATE cv_parent '/' lv_part INTO cv_parent.
        ENDIF.
      ENDIF.
    ENDLOOP.

    " Safety check before accessing string
    lv_len = strlen( cv_parent ).
    IF lv_len >= 2 AND cv_parent(2) = '//'.
      cv_parent = cv_parent+1.
    ENDIF.

    IF cv_parent IS INITIAL.
      cv_parent = '/'.
    ENDIF.
  ENDIF.
ENDFORM.

*--- CONVERT TIMESTAMP ---*
FORM convert_timestamp USING iv_sec TYPE p
                       CHANGING cv_date TYPE d
                                cv_time TYPE t.
  DATA: lv_days TYPE i,
        lv_secs TYPE i,
        lv_h    TYPE i,
        lv_m    TYPE i,
        lv_s    TYPE i,
        lv_time_str(6) TYPE c,
        lv_h_c(2)      TYPE n,
        lv_m_c(2)      TYPE n,
        lv_s_c(2)      TYPE n.

  " Calculate days and seconds
  lv_days = iv_sec DIV 86400.
  lv_secs = iv_sec MOD 86400.

  " Calculate date
  cv_date = '19700101'.
  cv_date = cv_date + lv_days.

  " Calculate time
  lv_h = lv_secs DIV 3600.
  lv_secs = lv_secs MOD 3600.
  lv_m = lv_secs DIV 60.
  lv_s = lv_secs MOD 60.

  " Format time
  lv_h_c = lv_h.
  lv_m_c = lv_m.
  lv_s_c = lv_s.
  CONCATENATE lv_h_c lv_m_c lv_s_c INTO lv_time_str.
  cv_time = lv_time_str.
ENDFORM.

*--- FORMAT DATETIME ---*
FORM format_datetime USING iv_date TYPE d
                           iv_time TYPE t
                     CHANGING cv_datetime TYPE c.
  DATA: lv_date_c(10) TYPE c,
        lv_time_c(8)  TYPE c.

  " Format: YYYY-MM-DD HH:MM:SS
  CONCATENATE iv_date(4) '-' iv_date+4(2) '-' iv_date+6(2) INTO lv_date_c.
  CONCATENATE iv_time(2) ':' iv_time+2(2) ':' iv_time+4(2) INTO lv_time_c.
  CONCATENATE lv_date_c lv_time_c INTO cv_datetime SEPARATED BY space.
ENDFORM.

*--- FORMAT SIZE (human-readable) ---*
FORM format_size USING iv_size TYPE i
                 CHANGING cv_fmt TYPE c.
  DATA: lv_size_p TYPE p DECIMALS 1,
        lv_val(12) TYPE c.

  IF iv_size < 1024.
    WRITE iv_size TO lv_val LEFT-JUSTIFIED.
    CONDENSE lv_val NO-GAPS.
    CONCATENATE lv_val 'B' INTO cv_fmt SEPARATED BY space.
  ELSEIF iv_size < 1048576.  " < 1 MB
    lv_size_p = iv_size / 1024.
    WRITE lv_size_p TO lv_val LEFT-JUSTIFIED.
    CONDENSE lv_val NO-GAPS.
    CONCATENATE lv_val 'KB' INTO cv_fmt SEPARATED BY space.
  ELSEIF iv_size < 1073741824.  " < 1 GB
    lv_size_p = iv_size / 1048576.
    WRITE lv_size_p TO lv_val LEFT-JUSTIFIED.
    CONDENSE lv_val NO-GAPS.
    CONCATENATE lv_val 'MB' INTO cv_fmt SEPARATED BY space.
  ELSE.
    lv_size_p = iv_size / 1073741824.
    WRITE lv_size_p TO lv_val DECIMALS 2 LEFT-JUSTIFIED.
    CONDENSE lv_val NO-GAPS.
    CONCATENATE lv_val 'GB' INTO cv_fmt SEPARATED BY space.
  ENDIF.
ENDFORM.

*--- NAVIGATE BACK ---*
FORM navigate_back.
  DATA: lv_dir TYPE string.

  IF gv_nav_idx <= 1.
    MESSAGE 'No previous directory.' TYPE 'S'.
    RETURN.
  ENDIF.

  gv_nav_idx = gv_nav_idx - 1.
  READ TABLE gt_nav_history INTO lv_dir INDEX gv_nav_idx.

  gv_nav_no_push = abap_true.
  PERFORM list_files_fm USING lv_dir.
  cl_gui_cfw=>set_new_ok_code( 'REFRESH_DIR' ).
ENDFORM.

*--- NAVIGATE FORWARD ---*
FORM navigate_forward.
  DATA: lv_dir TYPE string.

  IF gv_nav_idx >= lines( gt_nav_history ).
    MESSAGE 'No next directory.' TYPE 'S'.
    RETURN.
  ENDIF.

  gv_nav_idx = gv_nav_idx + 1.
  READ TABLE gt_nav_history INTO lv_dir INDEX gv_nav_idx.

  gv_nav_no_push = abap_true.
  PERFORM list_files_fm USING lv_dir.
  cl_gui_cfw=>set_new_ok_code( 'REFRESH_DIR' ).
ENDFORM.

*--- SHOW GRID ---*
FORM show_grid_fm.
  DATA: lt_fcat   TYPE lvc_t_fcat,
        ls_fcat   TYPE lvc_s_fcat,
        ls_layout TYPE lvc_s_layo,
        lt_sort   TYPE lvc_t_sort,
        ls_sort   TYPE lvc_s_sort.

  IF go_grid IS INITIAL.
    " Create grid
    CREATE OBJECT go_grid
      EXPORTING
        i_parent = go_container
      EXCEPTIONS
        OTHERS   = 1.

    IF sy-subrc <> 0.
      MESSAGE 'Failed to create ALV grid.' TYPE 'S' DISPLAY LIKE 'E'.
      RETURN.
    ENDIF.

    " Build field catalog
    CLEAR ls_fcat.
    ls_fcat-fieldname = 'SORT_TYPE'.
    ls_fcat-no_out = 'X'.
    ls_fcat-tech = 'X'.
    APPEND ls_fcat TO lt_fcat.

    CLEAR ls_fcat.
    ls_fcat-fieldname = 'ICON'.
    ls_fcat-coltext = 'Type'.
    ls_fcat-outputlen = 4.
    ls_fcat-icon = 'X'.
    ls_fcat-hotspot = 'X'.
    APPEND ls_fcat TO lt_fcat.

    CLEAR ls_fcat.
    ls_fcat-fieldname = 'NAME'.
    ls_fcat-coltext = 'Filename'.
    ls_fcat-outputlen = 60.
    ls_fcat-hotspot = 'X'.
    APPEND ls_fcat TO lt_fcat.

    CLEAR ls_fcat.
    ls_fcat-fieldname = 'SIZE'.
    ls_fcat-no_out = 'X'.
    ls_fcat-tech = 'X'.
    APPEND ls_fcat TO lt_fcat.

    CLEAR ls_fcat.
    ls_fcat-fieldname = 'SIZE_FMT'.
    ls_fcat-coltext = 'Size'.
    ls_fcat-outputlen = 10.
    ls_fcat-just = 'R'.
    APPEND ls_fcat TO lt_fcat.

    CLEAR ls_fcat.
    ls_fcat-fieldname = 'OWNER'.
    ls_fcat-coltext = 'Owner'.
    ls_fcat-outputlen = 12.
    APPEND ls_fcat TO lt_fcat.

    CLEAR ls_fcat.
    ls_fcat-fieldname = 'DATETIME'.
    ls_fcat-coltext = 'Last Modified'.
    ls_fcat-outputlen = 19.
    APPEND ls_fcat TO lt_fcat.

    " Layout
    ls_layout-sel_mode = 'A'.
    ls_layout-cwidth_opt = 'X'.
    ls_layout-zebra = 'X'.

    " Sort order
    CLEAR ls_sort.
    ls_sort-fieldname = 'SORT_TYPE'.
    ls_sort-up = 'X'.
    APPEND ls_sort TO lt_sort.

    CLEAR ls_sort.
    ls_sort-fieldname = 'NAME'.
    ls_sort-up = 'X'.
    APPEND ls_sort TO lt_sort.

    " Create event handler
    CREATE OBJECT go_event.
    SET HANDLER go_event->handle_toolbar FOR go_grid.
    SET HANDLER go_event->handle_user_command FOR go_grid.
    SET HANDLER go_event->on_hotspot_click FOR go_grid.

    " Display ALV
    CALL METHOD go_grid->set_table_for_first_display
      EXPORTING
        is_layout       = ls_layout
      CHANGING
        it_outtab       = gt_file_list
        it_fieldcatalog = lt_fcat
        it_sort         = lt_sort
      EXCEPTIONS
        OTHERS          = 1.

    IF sy-subrc <> 0.
      MESSAGE 'Failed to display ALV grid.' TYPE 'S' DISPLAY LIKE 'E'.
      RETURN.
    ENDIF.

    " Enable toolbar
    CALL METHOD go_grid->set_toolbar_interactive.
  ELSE.
    " Refresh existing grid
    CALL METHOD go_grid->refresh_table_display
      EXCEPTIONS
        OTHERS = 1.
  ENDIF.

  " Flush to display
  CALL METHOD cl_gui_cfw=>flush
    EXCEPTIONS
      OTHERS = 1.
ENDFORM.

*--- HANDLE GRID COMMAND ---*
FORM handle_grid_command USING iv_ucomm TYPE sy-ucomm.
  CASE iv_ucomm.
    WHEN 'NAV_BACK'.
      PERFORM navigate_back.

    WHEN 'NAV_FORWARD'.
      PERFORM navigate_forward.

    WHEN 'UPLOAD_FILES'.
      PERFORM upload_files_fm.

    WHEN 'DOWNLOAD_SELECTED'.
      PERFORM download_selected.

    WHEN 'COPY_FILE'.
      PERFORM copy_file.

    WHEN 'RENAME_FILE'.
      PERFORM rename_file.

    WHEN 'DELETE_SELECTED'.
      PERFORM delete_selected.

    WHEN 'CREATE_DIR'.
      PERFORM create_directory.

    WHEN 'REFRESH'.
      PERFORM list_files_fm USING gv_current_dir.
  ENDCASE.
ENDFORM.

*--- HANDLE GRID HOTSPOT ---*
FORM handle_grid_hotspot USING iv_row TYPE any
                               iv_col TYPE any.
  DATA: ls_file TYPE ty_file_item,
        lv_idx  TYPE i.

  lv_idx = iv_row.

  " Allow click on Icon or Name
  IF iv_col = 'ICON' OR iv_col = 'NAME'.
    READ TABLE gt_file_list INTO ls_file INDEX lv_idx.

    IF sy-subrc = 0.
      " Navigate to directory or parent
      IF ls_file-type = 'DIR' OR ls_file-type = 'UP'.
        p_fm_dir = ls_file-abspath.
        PERFORM list_files_fm USING ls_file-abspath.
        " Force selection screen repaint so p_fm_dir field shows new path
        cl_gui_cfw=>set_new_ok_code( 'REFRESH_DIR' ).

      " Download file
      ELSEIF ls_file-type = 'FILE'.
        PERFORM download_single_file USING ls_file-abspath ls_file-name.
      ENDIF.
    ENDIF.
  ENDIF.
ENDFORM.

*--- DOWNLOAD SELECTED ---*
FORM download_selected.
  DATA: lt_rows         TYPE lvc_t_row,
        ls_row          TYPE lvc_s_row,
        ls_file         TYPE ty_file_item,
        lv_target_folder TYPE string,
        lv_pc_path      TYPE string,
        lv_count        TYPE i,
        lv_folder_count TYPE i,
        lv_ans          TYPE c.

  " Get selected rows
  CALL METHOD go_grid->get_selected_rows
    IMPORTING
      et_index_rows = lt_rows.

  IF lines( lt_rows ) = 0.
    MESSAGE 'Please select at least one item.' TYPE 'S'.
    RETURN.
  ENDIF.

  " Check if any folders are selected
  LOOP AT lt_rows INTO ls_row.
    READ TABLE gt_file_list INTO ls_file INDEX ls_row-index.
    IF sy-subrc = 0 AND ls_file-type = 'DIR'.
      ADD 1 TO lv_folder_count.
    ENDIF.
  ENDLOOP.

  " If folders are selected, ask for confirmation
  IF lv_folder_count > 0.
    DATA: lv_question TYPE string.
    IF lv_folder_count = 1.
      lv_question = 'Download selected folder as ZIP file?'.
    ELSE.
      lv_question = |Download { lv_folder_count } folders as ZIP files?|.
    ENDIF.

    CALL FUNCTION 'POPUP_TO_CONFIRM'
      EXPORTING
        titlebar       = 'Download Folders'
        text_question  = lv_question
        text_button_1  = 'Yes'
        text_button_2  = 'Cancel'
        icon_button_1  = 'ICON_EXPORT'
      IMPORTING
        answer         = lv_ans
      EXCEPTIONS
        OTHERS         = 1.

    IF lv_ans <> '1'.
      RETURN.
    ENDIF.
  ENDIF.

  " Select target folder
  CALL METHOD cl_gui_frontend_services=>directory_browse
    EXPORTING
      window_title    = 'Select Target Folder'
    CHANGING
      selected_folder = lv_target_folder
    EXCEPTIONS
      OTHERS          = 1.

  IF lv_target_folder IS INITIAL.
    RETURN.
  ENDIF.

  " Process selected items
  LOOP AT lt_rows INTO ls_row.
    READ TABLE gt_file_list INTO ls_file INDEX ls_row-index.

    IF sy-subrc = 0.
      IF ls_file-type = 'FILE'.
        " Normal File Download
        CONCATENATE lv_target_folder '\' ls_file-name INTO lv_pc_path.
        PERFORM download_file USING ls_file-abspath lv_pc_path.
        ADD 1 TO lv_count.

      ELSEIF ls_file-type = 'DIR'.
        " Folder to ZIP Download
        CONCATENATE lv_target_folder '\' ls_file-name '.zip' INTO lv_pc_path.
        PERFORM zip_and_download_folder USING ls_file-abspath lv_pc_path.
        ADD 1 TO lv_count.
      ENDIF.
    ENDIF.
  ENDLOOP.

  MESSAGE |Processed { lv_count } item(s).| TYPE 'S'.
  PERFORM write_audit_log USING c_mod_fm 'FILE_DOWNLOAD' gv_current_dir 'batch' 'I'.
ENDFORM.

*--- DELETE SELECTED ---*
FORM delete_selected.
  " Note: File deletion on PRD is blocked per-item below;
  " empty directory deletion remains allowed on PRD.
  IF gv_fm_write = abap_false.
    MESSAGE 'No write authorization for File Manager.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  DATA: lt_rows TYPE lvc_t_row,
        ls_row  TYPE lvc_s_row,
        ls_file TYPE ty_file_item,
        lv_ans  TYPE c,
        lv_count TYPE i,
        lv_count_before TYPE i,
        lv_error_count TYPE i,
        lv_prd_blocked TYPE i.

  " Get selected rows
  CALL METHOD go_grid->get_selected_rows
    IMPORTING
      et_index_rows = lt_rows.

  IF lines( lt_rows ) = 0.
    MESSAGE 'Please select at least one item.' TYPE 'S'.
    RETURN.
  ENDIF.

  " Confirm deletion
  CALL FUNCTION 'POPUP_TO_CONFIRM'
    EXPORTING
      titlebar       = 'Confirm Deletion'
      text_question  = 'Delete selected items? (Folders must be empty!)'
      icon_button_1  = 'ICON_DELETE'
    IMPORTING
      answer         = lv_ans.

  IF lv_ans <> '1'.
    RETURN.
  ENDIF.

  " Delete selected items
  LOOP AT lt_rows INTO ls_row.
    READ TABLE gt_file_list INTO ls_file INDEX ls_row-index.

    IF sy-subrc = 0.
      IF ls_file-type = 'FILE'.
        " Security: Block file deletion on PRD (empty-dir delete still allowed below)
        IF gv_is_prd = abap_true AND gv_debug_active = abap_false.
          ADD 1 TO lv_prd_blocked.
          PERFORM write_audit_log USING c_mod_fm 'FILE_DELETE_BLOCKED_PRD' ls_file-abspath ls_file-name 'C'.
          CONTINUE.
        ENDIF.
        " Delete file
        DELETE DATASET ls_file-abspath.
        IF sy-subrc = 0.
          ADD 1 TO lv_count.
          PERFORM write_audit_log USING c_mod_fm 'FILE_DELETE' ls_file-abspath ls_file-name 'C'.
        ELSE.
          ADD 1 TO lv_error_count.
        ENDIF.

      ELSEIF ls_file-type = 'DIR'.
        " Delete folder (only if empty!)
        lv_count_before = lv_count.
        PERFORM delete_folder_safe USING ls_file-abspath
                                    CHANGING lv_count
                                             lv_error_count.
        IF lv_count > lv_count_before.
          PERFORM write_audit_log USING c_mod_fm 'DIR_DELETE' ls_file-abspath ls_file-name 'C'.
        ENDIF.
      ENDIF.
    ENDIF.
  ENDLOOP.

  IF lv_prd_blocked > 0 AND lv_error_count > 0.
    MESSAGE |Deleted { lv_count } item(s). { lv_prd_blocked } blocked on productive system. { lv_error_count } other failure(s) (folders must be empty).| TYPE 'S' DISPLAY LIKE 'W'.
  ELSEIF lv_prd_blocked > 0.
    MESSAGE |Deleted { lv_count } item(s). { lv_prd_blocked } file(s) blocked on productive system.| TYPE 'S' DISPLAY LIKE 'W'.
  ELSEIF lv_error_count > 0.
    MESSAGE |Deleted { lv_count } item(s). { lv_error_count } failed (folders must be empty).| TYPE 'S' DISPLAY LIKE 'W'.
  ELSE.
    MESSAGE |Deleted { lv_count } item(s).| TYPE 'S'.
  ENDIF.

  " Refresh display
  PERFORM list_files_fm USING gv_current_dir.
ENDFORM.


*--- ZIP AND DOWNLOAD FOLDER ---*
FORM zip_and_download_folder USING iv_srv_dir TYPE string
                                   iv_pc_zip TYPE string.
  DATA: lo_zip TYPE REF TO cl_abap_zip,
        lv_zip_xstr TYPE xstring,
        lt_bin TYPE solix_tab,
        lv_len TYPE i.

  DATA: lt_all_files TYPE TABLE OF ty_file_item,
        ls_file TYPE ty_file_item,
        lv_rel_path TYPE string,
        lv_bin_content TYPE xstring,
        lv_base_len TYPE i.

  CREATE OBJECT lo_zip.

  " Get base directory length for relative paths
  lv_base_len = strlen( iv_srv_dir ).

  " Recursively collect all files in folder
  PERFORM collect_folder_files USING iv_srv_dir
                                CHANGING lt_all_files.

  " Add each file to ZIP
  LOOP AT lt_all_files INTO ls_file.
    " Create relative path (remove base directory)
    lv_rel_path = ls_file-abspath+lv_base_len.

    " Remove leading slash if present
    IF strlen( lv_rel_path ) > 0.
      IF lv_rel_path(1) = '/' OR lv_rel_path(1) = '\'.
        lv_rel_path = lv_rel_path+1.
      ENDIF.
    ENDIF.

    " Read file content
    OPEN DATASET ls_file-abspath FOR INPUT IN BINARY MODE.
    IF sy-subrc = 0.
      READ DATASET ls_file-abspath INTO lv_bin_content.
      CLOSE DATASET ls_file-abspath.

      " Add to ZIP with relative path
      TRY.
          lo_zip->add( name = lv_rel_path content = lv_bin_content ).
        CATCH cx_root.
          " Skip files that can't be added
          CONTINUE.
      ENDTRY.
    ENDIF.
  ENDLOOP.

  " Save ZIP
  lv_zip_xstr = lo_zip->save( ).
  lv_len = xstrlen( lv_zip_xstr ).

  " Convert to binary table
  CALL FUNCTION 'SCMS_XSTRING_TO_BINARY'
    EXPORTING
      buffer        = lv_zip_xstr
    IMPORTING
      output_length = lv_len
    TABLES
      binary_tab    = lt_bin.

  " Download to PC
  CALL METHOD cl_gui_frontend_services=>gui_download
    EXPORTING
      filename     = iv_pc_zip
      filetype     = 'BIN'
      bin_filesize = lv_len
    CHANGING
      data_tab     = lt_bin
    EXCEPTIONS
      OTHERS       = 1.

  IF sy-subrc = 0.
    MESSAGE |Folder downloaded as ZIP: { iv_pc_zip }| TYPE 'S'.
      PERFORM write_audit_log USING c_mod_fm 'FOLDER_ZIP_DL' iv_srv_dir iv_pc_zip 'I'.
  ELSE.
    MESSAGE 'Error downloading ZIP file.' TYPE 'S' DISPLAY LIKE 'E'.
  ENDIF.
ENDFORM.

*--- COLLECT ALL FILES IN FOLDER (RECURSIVE) ---*
FORM collect_folder_files USING iv_dir TYPE string
                          CHANGING ct_files TYPE STANDARD TABLE.
  DATA: lv_dir_name TYPE c LENGTH 255,
        lv_file_name TYPE c LENGTH 255,
        lv_errno(3) TYPE c,
        lv_errmsg(40) TYPE c,
        lv_type(10) TYPE c,
        lv_size_c(20) TYPE c,
        lv_mtime_p TYPE p,
        lv_owner(20) TYPE c.

  DATA: ls_item TYPE ty_file_item,
        lv_subdir TYPE string,
        lv_len TYPE i,
        lv_off TYPE i.

  " Ensure trailing slash
  lv_len = strlen( iv_dir ).
  IF lv_len > 0.
    lv_off = lv_len - 1.
    IF iv_dir+lv_off(1) <> '/' AND iv_dir+lv_off(1) <> '\'.
      CONCATENATE iv_dir '/' INTO lv_dir_name.
    ELSE.
      lv_dir_name = iv_dir.
    ENDIF.
  ELSE.
    lv_dir_name = iv_dir.
  ENDIF.

  " Read directory
  CALL 'C_DIR_READ_START'
    ID 'DIR'    FIELD lv_dir_name
    ID 'FILE'   FIELD '*'
    ID 'ERRNO'  FIELD lv_errno
    ID 'ERRMSG' FIELD lv_errmsg.

  IF sy-subrc <> 0.
    RETURN.
  ENDIF.

  DO.
    CALL 'C_DIR_READ_NEXT'
      ID 'TYPE'   FIELD lv_type
      ID 'NAME'   FIELD lv_file_name
      ID 'LEN'    FIELD lv_size_c
      ID 'MTIME'  FIELD lv_mtime_p
      ID 'OWNER'  FIELD lv_owner
      ID 'ERRNO'  FIELD lv_errno
      ID 'ERRMSG' FIELD lv_errmsg.

    IF sy-subrc <> 0.
      EXIT.
    ENDIF.

    " Skip . and ..
    IF lv_file_name = '.' OR lv_file_name = '..'.
      CONTINUE.
    ENDIF.

    " Build full path
    CLEAR ls_item.
    ls_item-name = lv_file_name.
    CONCATENATE lv_dir_name lv_file_name INTO ls_item-abspath.

    IF lv_type CP 'dir*'.
      " It's a subdirectory - recurse into it
      ls_item-type = 'DIR'.
      CONCATENATE ls_item-abspath '/' INTO lv_subdir.
      PERFORM collect_folder_files USING lv_subdir CHANGING ct_files.
    ELSE.
      " It's a file - add to list
      ls_item-type = 'FILE'.
      ls_item-size = lv_size_c.
      APPEND ls_item TO ct_files.
    ENDIF.
  ENDDO.

  " Clean up
  CALL 'C_DIR_READ_FINISH'
    ID 'ERRNO'  FIELD lv_errno
    ID 'ERRMSG' FIELD lv_errmsg.
ENDFORM.

*--- DELETE FOLDER (SAFE - ONLY IF EMPTY) ---*
FORM delete_folder_safe USING iv_path TYPE string
                        CHANGING cv_success_count TYPE i
                                 cv_error_count TYPE i.
  DATA: lv_path_c TYPE c LENGTH 255,
        lv_is_empty TYPE abap_bool.

  " Check if folder is empty
  PERFORM check_folder_empty USING iv_path CHANGING lv_is_empty.

  IF lv_is_empty = abap_false.
    " Folder is not empty - cannot delete
    ADD 1 TO cv_error_count.
    RETURN.
  ENDIF.

  " Folder is empty - safe to delete via OS command (C_DIR_REMOVE does not exist)
  lv_path_c = iv_path.

  DATA: lv_command TYPE c LENGTH 255.
  DATA: BEGIN OF lt_systab OCCURS 0,
          line(200),
        END OF lt_systab.

  CONCATENATE 'rmdir' lv_path_c INTO lv_command SEPARATED BY space.

  CALL 'SYSTEM'
    ID 'COMMAND' FIELD lv_command
    ID 'TAB'     FIELD lt_systab-*sys*.

  " Verify deletion: try to read the directory again
  DATA: lv_dir_name_long TYPE salfile-longname,
        lt_dir_check     TYPE TABLE OF salfldir.
  lv_dir_name_long = iv_path.
  CONDENSE lv_dir_name_long.
  CALL FUNCTION 'RZL_READ_DIR_LOCAL'
    EXPORTING
      name     = lv_dir_name_long
    TABLES
      file_tbl = lt_dir_check
    EXCEPTIONS
      OTHERS   = 3.

  IF sy-subrc <> 0.
    " Directory no longer readable = successfully deleted
    ADD 1 TO cv_success_count.
  ELSE.
    ADD 1 TO cv_error_count.
  ENDIF.
ENDFORM.

*--- CHECK IF FOLDER IS EMPTY ---*
FORM check_folder_empty USING iv_path TYPE string
                        CHANGING cv_is_empty TYPE abap_bool.
  DATA: lv_dir_name TYPE c LENGTH 255,
        lv_file_name TYPE c LENGTH 255,
        lv_errno(3) TYPE c,
        lv_errmsg(40) TYPE c,
        lv_type(10) TYPE c,
        lv_file_count TYPE i.

  cv_is_empty = abap_true.
  lv_dir_name = iv_path.

  " Ensure trailing slash
  DATA: lv_len TYPE i, lv_off TYPE i.
  lv_len = strlen( iv_path ).
  IF lv_len > 0.
    lv_off = lv_len - 1.
    IF iv_path+lv_off(1) <> '/' AND iv_path+lv_off(1) <> '\'.
      CONCATENATE lv_dir_name '/' INTO lv_dir_name.
    ENDIF.
  ENDIF.

  " Read directory
  CALL 'C_DIR_READ_START'
    ID 'DIR'    FIELD lv_dir_name
    ID 'FILE'   FIELD '*'
    ID 'ERRNO'  FIELD lv_errno
    ID 'ERRMSG' FIELD lv_errmsg.

  IF sy-subrc <> 0.
    " Cannot read directory - assume not empty for safety
    cv_is_empty = abap_false.
    RETURN.
  ENDIF.

  " Check for files (skip . and ..)
  DO.
    CALL 'C_DIR_READ_NEXT'
      ID 'TYPE'   FIELD lv_type
      ID 'NAME'   FIELD lv_file_name
      ID 'ERRNO'  FIELD lv_errno
      ID 'ERRMSG' FIELD lv_errmsg.

    IF sy-subrc <> 0.
      EXIT.
    ENDIF.

    " Skip . and ..
    IF lv_file_name = '.' OR lv_file_name = '..'.
      CONTINUE.
    ENDIF.

    " Found a file or folder - directory is not empty
    cv_is_empty = abap_false.
    EXIT.
  ENDDO.

  " Clean up
  CALL 'C_DIR_READ_FINISH'
    ID 'ERRNO'  FIELD lv_errno
    ID 'ERRMSG' FIELD lv_errmsg.
ENDFORM.

*--- UPLOAD FILES ---*
FORM upload_files_fm.
  " Security: Block file upload on PRD (unless debug mode)
  IF gv_is_prd = abap_true AND gv_debug_active = abap_false.
    MESSAGE 'File upload is blocked on productive systems.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  " Security: Block file upload without write authorization
  IF gv_fm_write = abap_false.
    MESSAGE 'No write authorization for File Manager.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  DATA: lt_file_table TYPE filetable,
        ls_file       TYPE file_table,
        lv_rc         TYPE i,
        lv_full_file  TYPE string,
        lv_fname      TYPE string,
        lv_srv_path   TYPE string,
        lt_bin        TYPE solix_tab,
        lv_len        TYPE i,
        lv_bin        TYPE xstring,
        lv_cnt        TYPE i.

  " Select files
  CALL METHOD cl_gui_frontend_services=>file_open_dialog
    EXPORTING
      multiselection = 'X'
      window_title   = 'Select Files to Upload'
    CHANGING
      file_table     = lt_file_table
      rc             = lv_rc
    EXCEPTIONS
      OTHERS         = 1.

  IF lines( lt_file_table ) = 0.
    RETURN.
  ENDIF.

  " Upload each file
  LOOP AT lt_file_table INTO ls_file.
    lv_full_file = ls_file-filename.

    " Read file from PC
    CALL METHOD cl_gui_frontend_services=>gui_upload
      EXPORTING
        filename   = lv_full_file
        filetype   = 'BIN'
      IMPORTING
        filelength = lv_len
      CHANGING
        data_tab   = lt_bin
      EXCEPTIONS
        OTHERS     = 1.

    IF sy-subrc = 0.
      " Convert to xstring
      CALL FUNCTION 'SCMS_BINARY_TO_XSTRING'
        EXPORTING
          input_length = lv_len
        IMPORTING
          buffer       = lv_bin
        TABLES
          binary_tab   = lt_bin.

      " Extract filename
      CALL FUNCTION 'SO_SPLIT_FILE_AND_PATH'
        EXPORTING
          full_name    = lv_full_file
        IMPORTING
          stripped_name = lv_fname
        EXCEPTIONS
          OTHERS       = 1.

      " Build server path
      CONCATENATE gv_current_dir lv_fname INTO lv_srv_path.

      " Write to server
      OPEN DATASET lv_srv_path FOR OUTPUT IN BINARY MODE.
      IF sy-subrc = 0.
        TRANSFER lv_bin TO lv_srv_path.
        CLOSE DATASET lv_srv_path.
        ADD 1 TO lv_cnt.
        PERFORM write_audit_log USING c_mod_fm 'FILE_UPLOAD' lv_srv_path lv_fname 'W'.
      ENDIF.
    ENDIF.
  ENDLOOP.

  MESSAGE |Uploaded { lv_cnt } file(s).| TYPE 'S'.

  " Refresh display
  PERFORM list_files_fm USING gv_current_dir.
ENDFORM.

*--- COPY FILE ---*
FORM copy_file.
  " Security: Block file copy on PRD (unless debug mode)
  IF gv_is_prd = abap_true AND gv_debug_active = abap_false.
    MESSAGE 'File copy is blocked on productive systems.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  IF gv_fm_write = abap_false.
    MESSAGE 'No write authorization for File Manager.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  DATA: lt_rows TYPE lvc_t_row,
        ls_row  TYPE lvc_s_row,
        ls_file TYPE ty_file_item,
        lv_src_path TYPE string,
        lv_dst_path TYPE string,
        lv_content TYPE xstring.

  " Get selected rows
  CALL METHOD go_grid->get_selected_rows
    IMPORTING
      et_index_rows = lt_rows.

  " Validation: Exactly one file must be selected
  IF lines( lt_rows ) = 0.
    MESSAGE 'Please select exactly one file to copy.' TYPE 'S' DISPLAY LIKE 'W'.
    RETURN.
  ENDIF.

  IF lines( lt_rows ) > 1.
    MESSAGE 'Please select only ONE file to copy.' TYPE 'S' DISPLAY LIKE 'W'.
    RETURN.
  ENDIF.

  " Get the selected file
  READ TABLE lt_rows INTO ls_row INDEX 1.
  READ TABLE gt_file_list INTO ls_file INDEX ls_row-index.

  " Security: Only files, no directories
  IF ls_file-type <> 'FILE'.
    MESSAGE 'Copy is only allowed for files, not directories.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Build source and destination paths
  lv_src_path = ls_file-abspath.
  CONCATENATE ls_file-abspath ' (copy)' INTO lv_dst_path.

  " Read file content
  OPEN DATASET lv_src_path FOR INPUT IN BINARY MODE.
  IF sy-subrc <> 0.
    MESSAGE 'Error reading source file.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  READ DATASET lv_src_path INTO lv_content.
  CLOSE DATASET lv_src_path.

  " Write to destination
  OPEN DATASET lv_dst_path FOR OUTPUT IN BINARY MODE.
  IF sy-subrc <> 0.
    MESSAGE 'Error creating copy.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  TRANSFER lv_content TO lv_dst_path.
  CLOSE DATASET lv_dst_path.

  MESSAGE 'File copied successfully.' TYPE 'S'.
  PERFORM write_audit_log USING c_mod_fm 'FILE_COPY' lv_src_path lv_dst_path 'W'.

  " Refresh display
  PERFORM list_files_fm USING gv_current_dir.
ENDFORM.

*--- RENAME FILE ---*
FORM rename_file.
  " Security: Block file rename on PRD (unless debug mode)
  IF gv_is_prd = abap_true AND gv_debug_active = abap_false.
    MESSAGE 'File rename is blocked on productive systems.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  IF gv_fm_write = abap_false.
    MESSAGE 'No write authorization for File Manager.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  DATA: lt_rows TYPE lvc_t_row,
        ls_row  TYPE lvc_s_row,
        ls_file TYPE ty_file_item,
        lv_old_path TYPE string,
        lv_new_path TYPE string,
        lv_new_name TYPE string,
        lv_new_name_c(255) TYPE c,
        lv_content TYPE xstring,
        lv_rc TYPE c,
        lt_fields TYPE TABLE OF sval,
        ls_field TYPE sval.

  " Get selected rows
  CALL METHOD go_grid->get_selected_rows
    IMPORTING
      et_index_rows = lt_rows.

  " Validation: Exactly one file must be selected
  IF lines( lt_rows ) = 0.
    MESSAGE 'Please select exactly one file to rename.' TYPE 'S' DISPLAY LIKE 'W'.
    RETURN.
  ENDIF.

  IF lines( lt_rows ) > 1.
    MESSAGE 'Please select only ONE file to rename.' TYPE 'S' DISPLAY LIKE 'W'.
    RETURN.
  ENDIF.

  " Get the selected file
  READ TABLE lt_rows INTO ls_row INDEX 1.
  READ TABLE gt_file_list INTO ls_file INDEX ls_row-index.

  " Security: Only files, no directories
  IF ls_file-type <> 'FILE'.
    MESSAGE 'Rename is only allowed for files, not directories.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Ask for new filename
  lv_new_name_c = ls_file-name.
  
  CLEAR ls_field.
  ls_field-tabname = 'RLGRAP'.
  ls_field-fieldname = 'FILENAME'.
  ls_field-fieldtext = 'New filename:'.
  ls_field-value = lv_new_name_c.
  APPEND ls_field TO lt_fields.

  CALL FUNCTION 'POPUP_GET_VALUES'
    EXPORTING
      popup_title     = 'Rename File'
      start_column    = '10'
      start_row       = '5'
    IMPORTING
      returncode      = lv_rc
    TABLES
      fields          = lt_fields
    EXCEPTIONS
      OTHERS          = 1.

  IF sy-subrc <> 0 OR lv_rc = 'A'.
    MESSAGE 'Rename cancelled.' TYPE 'S'.
    RETURN.
  ENDIF.

  " Get new name from popup
  READ TABLE lt_fields INTO ls_field INDEX 1.
  lv_new_name = ls_field-value.
  CONDENSE lv_new_name.

  " Validate new name
  IF lv_new_name IS INITIAL.
    MESSAGE 'New filename cannot be empty.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Build paths
  lv_old_path = ls_file-abspath.
  CONCATENATE gv_current_dir lv_new_name INTO lv_new_path.

  " Check if target exists
  OPEN DATASET lv_new_path FOR INPUT IN BINARY MODE.
  IF sy-subrc = 0.
    CLOSE DATASET lv_new_path.
    MESSAGE 'A file with this name already exists.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Rename = Read + Write + Delete
  " 1. Read old file
  OPEN DATASET lv_old_path FOR INPUT IN BINARY MODE.
  IF sy-subrc <> 0.
    MESSAGE 'Error reading file.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  READ DATASET lv_old_path INTO lv_content.
  CLOSE DATASET lv_old_path.

  " 2. Write to new name
  OPEN DATASET lv_new_path FOR OUTPUT IN BINARY MODE.
  IF sy-subrc <> 0.
    MESSAGE 'Error creating new file.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  TRANSFER lv_content TO lv_new_path.
  CLOSE DATASET lv_new_path.

  " 3. Delete old file
  DELETE DATASET lv_old_path.

  MESSAGE |File renamed to { lv_new_name }.| TYPE 'S'.
  PERFORM write_audit_log USING c_mod_fm 'FILE_RENAME' lv_old_path lv_new_name 'W'.

  " Refresh display
  PERFORM list_files_fm USING gv_current_dir.
ENDFORM.

*--- CREATE DIRECTORY ---*
FORM create_directory.
  " Security: Block directory creation on PRD (unless debug mode)
  IF gv_is_prd = abap_true AND gv_debug_active = abap_false.
    MESSAGE 'Directory creation is blocked on productive systems.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  IF gv_fm_write = abap_false.
    MESSAGE 'No write authorization for File Manager.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  DATA: lv_new_name    TYPE string,
        lv_new_name_c(255) TYPE c,
        lv_full_path   TYPE string,
        lv_full_path_c TYPE c LENGTH 255,
        lv_rc          TYPE c,
        lt_fields      TYPE TABLE OF sval,
        ls_field       TYPE sval,
        lv_errno(3)    TYPE c,
        lv_errmsg(40)  TYPE c,
        lv_dir_name_long TYPE salfile-longname,
        lt_dir_check   TYPE TABLE OF salfldir.

  DATA: lv_command TYPE c LENGTH 255.

  " Ask for directory name via popup
  CLEAR ls_field.
  ls_field-tabname   = 'RLGRAP'.
  ls_field-fieldname = 'FILENAME'.
  ls_field-fieldtext = 'New folder name:'.
  ls_field-value     = ''.
  APPEND ls_field TO lt_fields.

  CALL FUNCTION 'POPUP_GET_VALUES'
    EXPORTING
      popup_title  = 'Create Directory'
      start_column = '10'
      start_row    = '5'
    IMPORTING
      returncode   = lv_rc
    TABLES
      fields       = lt_fields
    EXCEPTIONS
      OTHERS       = 1.

  IF sy-subrc <> 0 OR lv_rc = 'A'.
    MESSAGE 'Cancelled.' TYPE 'S'.
    RETURN.
  ENDIF.

  " Get the entered name
  READ TABLE lt_fields INTO ls_field INDEX 1.
  lv_new_name = ls_field-value.
  CONDENSE lv_new_name.

  IF lv_new_name IS INITIAL.
    MESSAGE 'Folder name cannot be empty.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Validate: no slashes, no shell-critical characters
  IF lv_new_name CA '/\;|&`$><"'''.
    MESSAGE 'Invalid characters in folder name.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Build full path
  CONCATENATE gv_current_dir lv_new_name INTO lv_full_path.

  " Check if directory already exists
  lv_dir_name_long = lv_full_path.
  CONDENSE lv_dir_name_long.
  CALL FUNCTION 'RZL_READ_DIR_LOCAL'
    EXPORTING
      name     = lv_dir_name_long
    TABLES
      file_tbl = lt_dir_check
    EXCEPTIONS
      OTHERS   = 3.

  IF sy-subrc = 0.
    MESSAGE 'Directory already exists.' TYPE 'S' DISPLAY LIKE 'W'.
    RETURN.
  ENDIF.

  " Create directory using mkdir (same technique as BRAN_DIR_CREATE)
  lv_full_path_c = lv_full_path.
  CONCATENATE 'mkdir' lv_full_path_c INTO lv_command SEPARATED BY space.

  DATA: BEGIN OF lt_systab OCCURS 0,
          line(200),
        END OF lt_systab.

  CALL 'SYSTEM'
    ID 'COMMAND' FIELD lv_command
    ID 'TAB'     FIELD lt_systab-*sys*.

  " Verify creation
  CLEAR lt_dir_check.
  CALL FUNCTION 'RZL_READ_DIR_LOCAL'
    EXPORTING
      name     = lv_dir_name_long
    TABLES
      file_tbl = lt_dir_check
    EXCEPTIONS
      OTHERS   = 3.

  IF sy-subrc = 0.
    MESSAGE |Directory '{ lv_new_name }' created.| TYPE 'S'.
      PERFORM write_audit_log USING c_mod_fm 'DIR_CREATE' gv_current_dir lv_new_name 'W'.
  ELSE.
    MESSAGE |Could not create directory '{ lv_new_name }'. Check permissions.| TYPE 'S' DISPLAY LIKE 'E'.
  ENDIF.

  " Refresh display
  PERFORM list_files_fm USING gv_current_dir.
ENDFORM.

*--- DOWNLOAD SINGLE FILE ---*
FORM download_single_file USING iv_path TYPE string
                                iv_name TYPE c.
  DATA: lv_content  TYPE xstring,
        lt_data     TYPE solix_tab,
        lv_len      TYPE i,
        lv_act      TYPE i,
        lv_filename TYPE string,
        lv_path     TYPE string,
        lv_fullpath TYPE string,
        lv_name_str TYPE string.

  " Convert name to string
  lv_name_str = iv_name.
  CONDENSE lv_name_str.

  " Read file from server
  OPEN DATASET iv_path FOR INPUT IN BINARY MODE.
  IF sy-subrc <> 0.
    MESSAGE 'Error reading file.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  READ DATASET iv_path INTO lv_content.
  CLOSE DATASET iv_path.

  " Convert to binary table
  lv_len = xstrlen( lv_content ).
  CALL FUNCTION 'SCMS_XSTRING_TO_BINARY'
    EXPORTING
      buffer        = lv_content
    IMPORTING
      output_length = lv_len
    TABLES
      binary_tab    = lt_data.

  " Save dialog
  CALL METHOD cl_gui_frontend_services=>file_save_dialog
    EXPORTING
      default_file_name = lv_name_str
    CHANGING
      filename          = lv_filename
      path              = lv_path
      fullpath          = lv_fullpath
      user_action       = lv_act
    EXCEPTIONS
      OTHERS            = 1.

  IF lv_act <> 9.
    " Download file
    CALL METHOD cl_gui_frontend_services=>gui_download
      EXPORTING
        filename     = lv_fullpath
        filetype     = 'BIN'
        bin_filesize = lv_len
      CHANGING
        data_tab     = lt_data
      EXCEPTIONS
        OTHERS       = 1.

    CALL METHOD cl_gui_cfw=>flush.
    MESSAGE 'File downloaded successfully.' TYPE 'S'.
    PERFORM write_audit_log USING c_mod_fm 'FILE_DOWNLOAD' iv_path '' 'I'.
  ENDIF.
ENDFORM.

*--- DOWNLOAD FILE (NO DIALOG) ---*
FORM download_file USING iv_srv_path TYPE string
                         iv_pc_path TYPE string.
  DATA: lv_content TYPE xstring,
        lt_data    TYPE solix_tab,
        lv_len     TYPE i.

  " Read from server
  OPEN DATASET iv_srv_path FOR INPUT IN BINARY MODE.
  IF sy-subrc = 0.
    READ DATASET iv_srv_path INTO lv_content.
    CLOSE DATASET iv_srv_path.

    " Convert and download
    lv_len = xstrlen( lv_content ).
    CALL FUNCTION 'SCMS_XSTRING_TO_BINARY'
      EXPORTING
        buffer        = lv_content
      IMPORTING
        output_length = lv_len
      TABLES
        binary_tab    = lt_data.

    CALL METHOD cl_gui_frontend_services=>gui_download
      EXPORTING
        filename     = iv_pc_path
        filetype     = 'BIN'
        bin_filesize = lv_len
      CHANGING
        data_tab     = lt_data
      EXCEPTIONS
        OTHERS       = 1.
  ENDIF.
ENDFORM.

*======================================================================*
* NEW FEATURES: ZIP UPLOAD, TRANSPORT DOWN/UP, GREP
*======================================================================*

*--- ZIP UPLOAD ---*
FORM execute_zip_upload.
  " Security: Block ZIP upload on PRD (unless debug mode)
  IF gv_is_prd = abap_true AND gv_debug_active = abap_false.
    MESSAGE 'ZIP upload is blocked on productive systems.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  DATA: lo_zip   TYPE REF TO cl_abap_zip,
        lt_data  TYPE solix_tab,
        lv_len   TYPE i,
        lv_xstr  TYPE xstring,
        lv_sep   TYPE c VALUE '/'.

  IF p_zu_fil IS INITIAL OR p_zu_dir IS INITIAL.
    MESSAGE 'Inputs missing.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  CALL METHOD cl_gui_frontend_services=>gui_upload
    EXPORTING
      filename   = p_zu_fil
      filetype   = 'BIN'
    IMPORTING
      filelength = lv_len
    CHANGING
      data_tab   = lt_data
    EXCEPTIONS
      OTHERS     = 1.

  IF sy-subrc <> 0.
    MESSAGE 'Upload failed.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  CALL FUNCTION 'SCMS_BINARY_TO_XSTRING'
    EXPORTING
      input_length = lv_len
    IMPORTING
      buffer       = lv_xstr
    TABLES
      binary_tab   = lt_data.

  CREATE OBJECT lo_zip.
  lo_zip->load( zip = lv_xstr ).

  IF p_zu_dir CA '\'.
    lv_sep = '\'.
  ENDIF.
  IF substring( val = p_zu_dir off = strlen( p_zu_dir ) - 1 ) <> lv_sep.
    CONCATENATE p_zu_dir lv_sep INTO p_zu_dir.
  ENDIF.

  DATA: lv_content     TYPE xstring,
        lv_name        TYPE string,
        lv_target_path TYPE string,
        lv_count       TYPE i.

  LOOP AT lo_zip->files INTO DATA(ls_zipfile).
    lo_zip->get( EXPORTING name = ls_zipfile-name IMPORTING content = lv_content ).
    lv_name = ls_zipfile-name.

    " Extract just the filename (strip directory separators)
    SPLIT lv_name AT '/' INTO TABLE gt_split_dummy.
    READ TABLE gt_split_dummy INDEX lines( gt_split_dummy ) INTO lv_name.
    IF lines( gt_split_dummy ) <= 1.
      SPLIT lv_name AT '\' INTO TABLE gt_split_dummy.
      READ TABLE gt_split_dummy INDEX lines( gt_split_dummy ) INTO lv_name.
    ENDIF.
    IF lv_name IS INITIAL.
      lv_name = ls_zipfile-name.
    ENDIF.

    CONCATENATE p_zu_dir lv_name INTO lv_target_path.
    OPEN DATASET lv_target_path FOR OUTPUT IN BINARY MODE.
    IF sy-subrc = 0.
      TRANSFER lv_content TO lv_target_path.
      CLOSE DATASET lv_target_path.
      ADD 1 TO lv_count.
      PERFORM write_audit_log USING c_mod_zup 'ZIP_EXTRACT' lv_target_path lv_name 'W'.
    ENDIF.
  ENDLOOP.

  MESSAGE |Extracted { lv_count } files.| TYPE 'S'.
ENDFORM.

*--- TRANSPORT DOWNLOAD ---*
FORM execute_trans_download.
  DATA: lv_sysid      TYPE string,
        lv_num        TYPE string,
        lv_k_name     TYPE string,
        lv_r_name     TYPE string,
        lv_k_path     TYPE string,
        lv_r_path     TYPE string,
        lv_target_dir TYPE string,
        lv_base       TYPE string.

  IF p_tr_id IS INITIAL.
    MESSAGE 'Transport Request ID missing.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  IF strlen( p_tr_id ) < 4.
    MESSAGE 'Invalid ID.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  lv_sysid = p_tr_id(3).
  lv_num   = p_tr_id+3.
  lv_k_name = |{ lv_num }.{ lv_sysid }|.

  IF lv_num(1) = 'K'.
    REPLACE SECTION OFFSET 0 LENGTH 1 OF lv_num WITH 'R'.
  ENDIF.
  lv_r_name = |{ lv_num }.{ lv_sysid }|.

  lv_base = p_tr_dir.
  IF substring( val = lv_base off = strlen( lv_base ) - 1 ) <> '/'.
    CONCATENATE lv_base '/' INTO lv_base.
  ENDIF.

  lv_k_path = |{ lv_base }cofiles/{ lv_k_name }|.
  lv_r_path = |{ lv_base }data/{ lv_r_name }|.

  CALL METHOD cl_gui_frontend_services=>directory_browse
    EXPORTING
      window_title    = 'Select Target Folder'
    CHANGING
      selected_folder = lv_target_dir
    EXCEPTIONS
      OTHERS          = 1.

  IF lv_target_dir IS INITIAL.
    RETURN.
  ENDIF.

  PERFORM download_transport_file USING lv_k_path lv_target_dir lv_k_name.
  PERFORM download_transport_file USING lv_r_path lv_target_dir lv_r_name.
  MESSAGE 'Transport Download finished.' TYPE 'S'.
  PERFORM write_audit_log USING c_mod_trd 'TRANS_DOWNLOAD' p_tr_id p_tr_dir 'I'.
ENDFORM.

FORM download_transport_file USING iv_server_path TYPE string
                                   iv_pc_dir TYPE string
                                   iv_fname TYPE string.
  DATA: lv_content TYPE xstring,
        lt_data    TYPE solix_tab,
        lv_len     TYPE i,
        lv_chunk   TYPE xstring,
        lv_pc_path TYPE string.

  CONCATENATE iv_pc_dir '\' iv_fname INTO lv_pc_path.

  OPEN DATASET iv_server_path FOR INPUT IN BINARY MODE.
  IF sy-subrc <> 0.
    MESSAGE |File not found: { iv_server_path }| TYPE 'S' DISPLAY LIKE 'W'.
    RETURN.
  ENDIF.

  DO.
    CLEAR lv_chunk.
    READ DATASET iv_server_path INTO lv_chunk.
    IF xstrlen( lv_chunk ) > 0.
      CONCATENATE lv_content lv_chunk INTO lv_content IN BYTE MODE.
    ENDIF.
    IF sy-subrc <> 0.
      EXIT.
    ENDIF.
  ENDDO.
  CLOSE DATASET iv_server_path.

  lv_len = xstrlen( lv_content ).
  CALL FUNCTION 'SCMS_XSTRING_TO_BINARY'
    EXPORTING
      buffer        = lv_content
    IMPORTING
      output_length = lv_len
    TABLES
      binary_tab    = lt_data.

  CALL METHOD cl_gui_frontend_services=>gui_download
    EXPORTING
      filename     = lv_pc_path
      filetype     = 'BIN'
      bin_filesize = lv_len
    CHANGING
      data_tab     = lt_data
    EXCEPTIONS
      OTHERS       = 1.
ENDFORM.

*--- TRANSPORT UPLOAD ---*
FORM execute_trans_upload.
  " Security: Block transport upload on PRD (unless debug mode)
  IF gv_is_prd = abap_true AND gv_debug_active = abap_false.
    MESSAGE 'Transport upload is blocked on productive systems. Use TMS/CTS.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  DATA: lv_base    TYPE string,
        lv_done    TYPE i,
        lt_k_paths TYPE STANDARD TABLE OF string,
        lt_trkorrs TYPE STANDARD TABLE OF string,
        lv_trkorr  TYPE string,
        lv_buf_ok  TYPE i,
        lv_buf_err TYPE i,
        lv_bmsg    TYPE string,
        lv_ok      TYPE abap_bool.

  lv_base = p_tru_td.
  IF substring( val = lv_base off = strlen( lv_base ) - 1 ) <> '/'.
    CONCATENATE lv_base '/' INTO lv_base.
  ENDIF.

  " Upload all non-empty file pairs; collect K-paths for optional buffer add
  IF p_tru_k1 IS NOT INITIAL. PERFORM upload_transport_file USING p_tru_k1 lv_base 'cofiles'. ADD 1 TO lv_done. PERFORM write_audit_log USING c_mod_tru 'TRANS_UPLOAD' p_tru_k1 'cofiles' 'W'. APPEND p_tru_k1 TO lt_k_paths. ENDIF.
  IF p_tru_r1 IS NOT INITIAL. PERFORM upload_transport_file USING p_tru_r1 lv_base 'data'. ADD 1 TO lv_done. PERFORM write_audit_log USING c_mod_tru 'TRANS_UPLOAD' p_tru_r1 'data' 'W'. ENDIF.
  IF p_tru_k2 IS NOT INITIAL. PERFORM upload_transport_file USING p_tru_k2 lv_base 'cofiles'. ADD 1 TO lv_done. PERFORM write_audit_log USING c_mod_tru 'TRANS_UPLOAD' p_tru_k2 'cofiles' 'W'. APPEND p_tru_k2 TO lt_k_paths. ENDIF.
  IF p_tru_r2 IS NOT INITIAL. PERFORM upload_transport_file USING p_tru_r2 lv_base 'data'. ADD 1 TO lv_done. PERFORM write_audit_log USING c_mod_tru 'TRANS_UPLOAD' p_tru_r2 'data' 'W'. ENDIF.
  IF p_tru_k3 IS NOT INITIAL. PERFORM upload_transport_file USING p_tru_k3 lv_base 'cofiles'. ADD 1 TO lv_done. PERFORM write_audit_log USING c_mod_tru 'TRANS_UPLOAD' p_tru_k3 'cofiles' 'W'. APPEND p_tru_k3 TO lt_k_paths. ENDIF.
  IF p_tru_r3 IS NOT INITIAL. PERFORM upload_transport_file USING p_tru_r3 lv_base 'data'. ADD 1 TO lv_done. PERFORM write_audit_log USING c_mod_tru 'TRANS_UPLOAD' p_tru_r3 'data' 'W'. ENDIF.
  IF p_tru_k4 IS NOT INITIAL. PERFORM upload_transport_file USING p_tru_k4 lv_base 'cofiles'. ADD 1 TO lv_done. PERFORM write_audit_log USING c_mod_tru 'TRANS_UPLOAD' p_tru_k4 'cofiles' 'W'. APPEND p_tru_k4 TO lt_k_paths. ENDIF.
  IF p_tru_r4 IS NOT INITIAL. PERFORM upload_transport_file USING p_tru_r4 lv_base 'data'. ADD 1 TO lv_done. PERFORM write_audit_log USING c_mod_tru 'TRANS_UPLOAD' p_tru_r4 'data' 'W'. ENDIF.

  " Add to STMS import buffer of current SID (plan B3)
  IF p_tru_bf = abap_true AND lv_done > 0.
    LOOP AT lt_k_paths INTO DATA(lv_kp).
      CLEAR lv_trkorr.
      PERFORM parse_trkorr_from_k USING lv_kp CHANGING lv_trkorr.
      IF lv_trkorr IS INITIAL.
        CONTINUE.
      ENDIF.
      READ TABLE lt_trkorrs TRANSPORTING NO FIELDS WITH KEY table_line = lv_trkorr.
      IF sy-subrc = 0.
        CONTINUE.
      ENDIF.
      APPEND lv_trkorr TO lt_trkorrs.
      CLEAR: lv_ok, lv_bmsg.
      PERFORM add_to_stms_buffer USING lv_trkorr sy-sysid sy-mandt CHANGING lv_ok lv_bmsg.
      IF lv_ok = abap_true.
        ADD 1 TO lv_buf_ok.
        PERFORM write_audit_log USING c_mod_tru 'STMS_BUFFER_ADD' lv_trkorr sy-sysid 'W'.
      ELSE.
        ADD 1 TO lv_buf_err.
        PERFORM write_audit_log USING c_mod_tru 'STMS_BUFFER_ADD' lv_trkorr lv_bmsg 'W'.
      ENDIF.
    ENDLOOP.
  ENDIF.

  IF lv_done = 0.
    MESSAGE 'No files selected for upload.' TYPE 'S' DISPLAY LIKE 'W'.
  ELSEIF p_tru_bf = abap_true.
    IF lv_buf_err > 0 AND lv_buf_ok > 0.
      MESSAGE |Upload: { lv_done } files. STMS buffer: { lv_buf_ok } added, { lv_buf_err } failed (check audit log).| TYPE 'S' DISPLAY LIKE 'W'.
    ELSEIF lv_buf_err > 0.
      MESSAGE |Upload: { lv_done } files. STMS buffer add FAILED for all transports (check audit log / S_CTS_ADMI).| TYPE 'S' DISPLAY LIKE 'W'.
    ELSEIF lv_buf_ok > 0.
      MESSAGE |Upload: { lv_done } files. { lv_buf_ok } transport(s) added to STMS buffer of { sy-sysid }.| TYPE 'S'.
    ELSE.
      MESSAGE |Upload: { lv_done } files. No K-files detected for buffer add.| TYPE 'S' DISPLAY LIKE 'W'.
    ENDIF.
  ELSE.
    MESSAGE |Transport Upload finished ({ lv_done } files).| TYPE 'S'.
  ENDIF.
ENDFORM.

*--- PARSE TRANSPORT ID FROM K-FILENAME ---*
* Input:  /path/to/K902985.EW3 (or plain K902985.EW3)
* Output: EW3K902985
FORM parse_trkorr_from_k USING iv_path TYPE string
                      CHANGING cv_trkorr TYPE string.
  DATA: lv_name    TYPE string,
        lv_sep     TYPE c LENGTH 1,
        lv_pos     TYPE i,
        lv_dot     TYPE i,
        lv_num     TYPE string,
        lv_sid     TYPE string,
        lv_len     TYPE i,
        lv_num_len TYPE i,
        lt_match   TYPE match_result_tab.

  CLEAR cv_trkorr.
  IF iv_path CS '\'.
    lv_sep = '\'.
  ELSE.
    lv_sep = '/'.
  ENDIF.

  " Get offset of LAST separator (no FIND LAST OCCURRENCE in classic ABAP)
  FIND ALL OCCURRENCES OF lv_sep IN iv_path RESULTS lt_match.
  IF lt_match IS NOT INITIAL.
    lv_pos = lt_match[ lines( lt_match ) ]-offset + 1.
    lv_name = iv_path+lv_pos.
  ELSE.
    lv_name = iv_path.
  ENDIF.

  TRANSLATE lv_name TO UPPER CASE.
  lv_len = strlen( lv_name ).

  " Strict format: K<digits>.<3-char-SID>  (e.g. K902985.EW3)
  " Anything else (custom names, duplicate transports, no extension) is rejected
  " so we never feed garbage like "D66K_TRANSPORT1@2A1A" into TMS_MGR_FORWARD.
  IF lv_len < 5 OR lv_name(1) <> 'K'.
    RETURN.
  ENDIF.

  lv_dot = 0.
  FIND '.' IN lv_name MATCH OFFSET lv_dot.
  IF sy-subrc <> 0 OR lv_dot < 2.
    RETURN.
  ENDIF.

  " Substring length must be a single variable, not an expression.
  lv_num_len = lv_dot - 1.
  lv_num = lv_name+1(lv_num_len).
  lv_dot = lv_dot + 1.
  lv_sid = lv_name+lv_dot.

  " Validate: number part is purely digits, SID is exactly 3 alphanumeric chars
  IF strlen( lv_sid ) <> 3.
    RETURN.
  ENDIF.
  IF lv_num IS INITIAL OR NOT lv_num CO '0123456789'.
    RETURN.
  ENDIF.
  IF NOT lv_sid CO 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.
    RETURN.
  ENDIF.

  " Final length check (TRKORR is CHAR 20)
  IF strlen( lv_sid ) + 1 + strlen( lv_num ) > 20.
    RETURN.
  ENDIF.

  cv_trkorr = |{ lv_sid }K{ lv_num }|.
ENDFORM.

*--- ADD TRKORR TO STMS IMPORT BUFFER ---*
* Requires S_CTS_ADMI with CTS_ADMFCT = IMPS at runtime.
* Strategy: try TMS_MGR_IMPORT_TR_REQUEST first (matches the working pattern
* from sapabapcentral.blogspot.com/2017/09 - parameters iv_system / iv_tr_request /
* iv_client). Fall back to TMS_MGR_FORWARD_TR_REQUEST when IMPORT is not present
* or signals an unsupported parameter (older NW releases).
FORM add_to_stms_buffer USING iv_trkorr  TYPE clike
                              iv_tgt_sys TYPE clike
                              iv_tgt_cli TYPE clike
                     CHANGING cv_ok      TYPE abap_bool
                              cv_msg     TYPE string.
  DATA: lv_trkorr  TYPE trkorr,
        lv_target  TYPE tmssysnam,
        lv_client  TYPE mandt,
        lv_done    TYPE abap_bool VALUE abap_false,
        lv_import_msg TYPE string.

  cv_ok  = abap_false.
  cv_msg = ''.
  lv_trkorr = iv_trkorr.
  lv_target = iv_tgt_sys.
  IF lv_target IS INITIAL.
    lv_target = sy-sysid.
  ENDIF.
  lv_client = iv_tgt_cli.
  IF lv_client IS INITIAL.
    lv_client = sy-mandt.
  ENDIF.

  " --- Attempt 1: TMS_MGR_IMPORT_TR_REQUEST ---
  CALL FUNCTION 'FUNCTION_EXISTS'
    EXPORTING
      funcname           = 'TMS_MGR_IMPORT_TR_REQUEST'
    EXCEPTIONS
      function_not_exist = 1
      OTHERS             = 2.
  IF sy-subrc = 0.
    TRY.
        CALL FUNCTION 'TMS_MGR_IMPORT_TR_REQUEST'
          EXPORTING
            iv_system     = lv_target
            iv_tr_request = lv_trkorr
            iv_client     = lv_client
            iv_monitor    = abap_false
          EXCEPTIONS
            OTHERS        = 99.
        IF sy-subrc = 0.
          cv_ok   = abap_true.
          cv_msg  = |Added { lv_trkorr } to buffer of { lv_target }/{ lv_client }|.
          lv_done = abap_true.
        ELSE.
          lv_import_msg = |IMPORT rc={ sy-subrc }|.
        ENDIF.
      CATCH cx_sy_dyn_call_error INTO DATA(lx_imp_dyn).
        lv_import_msg = |IMPORT param mismatch: { lx_imp_dyn->get_text( ) }|.
      CATCH cx_root INTO DATA(lx_imp).
        lv_import_msg = |IMPORT exception: { lx_imp->get_text( ) }|.
    ENDTRY.
  ELSE.
    lv_import_msg = 'IMPORT FM not present'.
  ENDIF.

  IF lv_done = abap_true.
    RETURN.
  ENDIF.

  " --- Attempt 2 (fallback): TMS_MGR_FORWARD_TR_REQUEST ---
  CALL FUNCTION 'FUNCTION_EXISTS'
    EXPORTING
      funcname           = 'TMS_MGR_FORWARD_TR_REQUEST'
    EXCEPTIONS
      function_not_exist = 1
      OTHERS             = 2.
  IF sy-subrc <> 0.
    cv_msg = |Neither TMS_MGR_IMPORT_TR_REQUEST nor TMS_MGR_FORWARD_TR_REQUEST is available. ({ lv_import_msg })|.
    RETURN.
  ENDIF.

  TRY.
      CALL FUNCTION 'TMS_MGR_FORWARD_TR_REQUEST'
        EXPORTING
          iv_request       = lv_trkorr
          iv_target_system = lv_target
        EXCEPTIONS
          OTHERS           = 99.
      IF sy-subrc = 0.
        cv_ok  = abap_true.
        cv_msg = |Added { lv_trkorr } to buffer of { lv_target } (via FORWARD fallback)|.
      ELSE.
        cv_msg = |Both IMPORT and FORWARD failed for { lv_trkorr } (FORWARD rc={ sy-subrc }; { lv_import_msg }). Check S_CTS_ADMI/IMPS and TMS configuration.|.
      ENDIF.
    CATCH cx_sy_dyn_call_error INTO DATA(lx_fwd_dyn).
      cv_msg = |FORWARD param mismatch: { lx_fwd_dyn->get_text( ) }; { lv_import_msg }|.
    CATCH cx_root INTO DATA(lx_fwd).
      cv_msg = |FORWARD exception: { lx_fwd->get_text( ) }; { lv_import_msg }|.
  ENDTRY.
ENDFORM.

*--- EXECUTE STMS BUFFER ADD (multiple transports) ---*
* Module STM: collect trkorrs from s_stm_tr (Includes/EQ only), forward each
* to add_to_stms_buffer for the target sys/client (p_stmsys/p_stmcli),
* then show an ALV popup with per-transport result.
*
* No PRD block: STMS Buffer Add does not change PRD data. The actual import
* is owned by CTS (S_CTS_ADMI/IMPS). USER + ADMIN may run this on any system.
FORM execute_stms_buffer.
  TYPES: BEGIN OF ty_res,
           trkorr TYPE trkorr,
           result TYPE string,    " 'OK' or 'ERROR'
           message TYPE string,
         END OF ty_res.
  DATA: lt_res TYPE STANDARD TABLE OF ty_res,
        ls_res TYPE ty_res,
        lv_ok  TYPE abap_bool,
        lv_msg TYPE string,
        lv_count_ok TYPE i,
        lv_count_err TYPE i,
        lv_total TYPE i.
  DATA: lo_alv TYPE REF TO cl_salv_table,
        lo_cols TYPE REF TO cl_salv_columns_table,
        lo_col TYPE REF TO cl_salv_column_table,
        lx_salv TYPE REF TO cx_salv_msg.
  DATA: lv_severity TYPE c LENGTH 1,
        lv_detail2  TYPE string.
  FIELD-SYMBOLS <fs_tr> LIKE LINE OF s_stm_tr.
  DATA lv_trkorr TYPE trkorr.
  DATA lv_low TYPE string.

  " Auth check (display action — actual buffer add is gated by S_CTS_ADMI/IMPS)
  PERFORM check_authorization USING c_mod_stm c_actn_display CHANGING gv_auth_ok.
  IF gv_auth_ok = abap_false.
    RETURN.
  ENDIF.

  " Collect Includes/EQ
  LOOP AT s_stm_tr ASSIGNING <fs_tr>
       WHERE sign = 'I' AND option = 'EQ' AND low IS NOT INITIAL.
    lv_low = <fs_tr>-low.
    TRANSLATE lv_low TO UPPER CASE.
    lv_trkorr = lv_low.

    CLEAR: lv_ok, lv_msg.
    PERFORM add_to_stms_buffer USING lv_trkorr p_stmsys p_stmcli
                            CHANGING lv_ok lv_msg.

    CLEAR ls_res.
    ls_res-trkorr  = lv_trkorr.
    IF lv_ok = abap_true.
      ls_res-result  = 'OK'.
      ls_res-message = lv_msg.
      lv_count_ok = lv_count_ok + 1.
      lv_severity = 'W'.
    ELSE.
      ls_res-result  = 'ERROR'.
      ls_res-message = lv_msg.
      lv_count_err = lv_count_err + 1.
      lv_severity = 'E'.
    ENDIF.
    APPEND ls_res TO lt_res.

    " Audit log per transport
    lv_detail2 = |{ p_stmsys }/{ p_stmcli }|.
    PERFORM write_audit_log USING c_mod_stm 'STMS_BUFFER_ADD'
                                  lv_trkorr lv_detail2 lv_severity.
  ENDLOOP.

  lv_total = lv_count_ok + lv_count_err.
  IF lv_total = 0.
    MESSAGE 'No transports specified. Enter at least one Trkorr (Single value).' TYPE 'W'.
    RETURN.
  ENDIF.

  " ALV popup
  TRY.
      cl_salv_table=>factory(
        IMPORTING r_salv_table = lo_alv
        CHANGING  t_table      = lt_res ).

      lo_alv->get_columns( )->set_optimize( abap_true ).
      lo_cols = lo_alv->get_columns( ).

      TRY.
          lo_col ?= lo_cols->get_column( 'TRKORR' ).
          lo_col->set_short_text( 'Transport' ).
          lo_col->set_medium_text( 'Transport ID' ).
          lo_col->set_long_text( 'Transport ID' ).
        CATCH cx_salv_not_found.
      ENDTRY.
      TRY.
          lo_col ?= lo_cols->get_column( 'RESULT' ).
          lo_col->set_short_text( 'Result' ).
          lo_col->set_medium_text( 'Result' ).
          lo_col->set_long_text( 'Result' ).
        CATCH cx_salv_not_found.
      ENDTRY.
      TRY.
          lo_col ?= lo_cols->get_column( 'MESSAGE' ).
          lo_col->set_short_text( 'Message' ).
          lo_col->set_medium_text( 'Message' ).
          lo_col->set_long_text( 'Message' ).
        CATCH cx_salv_not_found.
      ENDTRY.

      lo_alv->get_display_settings( )->set_list_header(
        |STMS Buffer Add — Target { p_stmsys }/{ p_stmcli } — | &&
        |OK: { lv_count_ok } / Errors: { lv_count_err }| ).

      lo_alv->display( ).
    CATCH cx_salv_msg INTO lx_salv.
      MESSAGE lx_salv->get_text( ) TYPE 'E'.
  ENDTRY.

  " Summary message after popup closes
  IF lv_count_err = 0.
    MESSAGE |STMS buffer: { lv_count_ok } transport(s) added to { p_stmsys }/{ p_stmcli }.| TYPE 'S'.
  ELSE.
    MESSAGE |STMS buffer: { lv_count_ok } added, { lv_count_err } failed (target { p_stmsys }/{ p_stmcli }).| TYPE 'S' DISPLAY LIKE 'W'.
  ENDIF.
ENDFORM.

FORM upload_transport_file USING iv_pc_path TYPE string
                                 iv_base TYPE string
                                 iv_subdir TYPE string.
  DATA: lt_bin       TYPE solix_tab,
        lv_len       TYPE i,
        lv_fname     TYPE string,
        lv_server_path TYPE string.

  CALL FUNCTION 'SO_SPLIT_FILE_AND_PATH'
    EXPORTING
      full_name     = iv_pc_path
    IMPORTING
      stripped_name = lv_fname
    EXCEPTIONS
      OTHERS        = 1.

  lv_server_path = |{ iv_base }{ iv_subdir }/{ lv_fname }|.

  CALL METHOD cl_gui_frontend_services=>gui_upload
    EXPORTING
      filename   = iv_pc_path
      filetype   = 'BIN'
    IMPORTING
      filelength = lv_len
    CHANGING
      data_tab   = lt_bin
    EXCEPTIONS
      OTHERS     = 1.

  IF sy-subrc = 0.
    OPEN DATASET lv_server_path FOR OUTPUT IN BINARY MODE.
    IF sy-subrc = 0.
      LOOP AT lt_bin INTO DATA(ls_bin).
        TRANSFER ls_bin TO lv_server_path.
      ENDLOOP.
      CLOSE DATASET lv_server_path.
      MESSAGE |Uploaded: { lv_server_path }| TYPE 'S'.
    ELSE.
      MESSAGE |Write Error: { lv_server_path }| TYPE 'S' DISPLAY LIKE 'E'.
    ENDIF.
  ELSE.
    MESSAGE |PC Read Error: { iv_pc_path }| TYPE 'S' DISPLAY LIKE 'E'.
  ENDIF.
ENDFORM.

*--- GREP ---*
FORM execute_grep.
  DATA: lv_dir_name_long TYPE salfile-longname,
        lt_dir_list      TYPE TABLE OF salfldir,
        ls_dir_list      TYPE salfldir.
  DATA: lv_sep          TYPE c VALUE '/',
        lv_full_path    TYPE string,
        lv_line_content TYPE string.
  DATA: lt_results TYPE TABLE OF ty_grep_result,
        ls_result  TYPE ty_grep_result,
        lv_hit_count TYPE i,
        lv_line_no   TYPE i,
        lo_alv       TYPE REF TO cl_salv_table.
  DATA: lo_cols  TYPE REF TO cl_salv_columns_table,
        lo_funcs TYPE REF TO cl_salv_functions_list.

  IF p_g_dir IS INITIAL OR p_g_str IS INITIAL.
    MESSAGE 'Directory and Search Term are mandatory.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  IF p_g_dir CA '\'.
    lv_sep = '\'.
  ENDIF.
  IF substring( val = p_g_dir off = strlen( p_g_dir ) - 1 ) <> lv_sep.
    CONCATENATE p_g_dir lv_sep INTO p_g_dir.
  ENDIF.

  lv_dir_name_long = p_g_dir.
  CONDENSE lv_dir_name_long.

  CALL FUNCTION 'RZL_READ_DIR_LOCAL'
    EXPORTING
      name     = lv_dir_name_long
    TABLES
      file_tbl = lt_dir_list
    EXCEPTIONS
      OTHERS   = 3.

  IF sy-subrc <> 0 OR lines( lt_dir_list ) = 0.
    MESSAGE 'Directory empty or unreadable.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  MESSAGE 'Searching... This might take a moment.' TYPE 'S'.

  LOOP AT lt_dir_list INTO ls_dir_list.
    IF ls_dir_list-name = '.' OR ls_dir_list-name = '..'.
      CONTINUE.
    ENDIF.
    IF p_g_msk IS NOT INITIAL AND p_g_msk <> '*'.
      IF NOT ls_dir_list-name CP p_g_msk.
        CONTINUE.
      ENDIF.
    ENDIF.
    CONCATENATE p_g_dir ls_dir_list-name INTO lv_full_path.
    TRY.
      OPEN DATASET lv_full_path FOR INPUT IN TEXT MODE ENCODING DEFAULT
        WITH SMART LINEFEED IGNORING CONVERSION ERRORS.
      IF sy-subrc = 0.
        lv_line_no = 0.
        DO.
          READ DATASET lv_full_path INTO lv_line_content.
          IF sy-subrc <> 0.
            EXIT.
          ENDIF.
          ADD 1 TO lv_line_no.
          FIND p_g_str IN lv_line_content IGNORING CASE.
          IF sy-subrc = 0.
            ls_result-filename = ls_dir_list-name.
            ls_result-line_no  = lv_line_no.
            ls_result-content  = lv_line_content.
            APPEND ls_result TO lt_results.
            ADD 1 TO lv_hit_count.
          ENDIF.
        ENDDO.
        CLOSE DATASET lv_full_path.
      ENDIF.
    CATCH cx_root.
      TRY.
          CLOSE DATASET lv_full_path.
        CATCH cx_root.
      ENDTRY.
      CONTINUE.
    ENDTRY.
  ENDLOOP.

  IF lv_hit_count = 0.
    MESSAGE 'No matches found.' TYPE 'S'.
  ELSE.
    TRY.
        CALL METHOD cl_salv_table=>factory
          IMPORTING
            r_salv_table = lo_alv
          CHANGING
            t_table      = lt_results.

        CALL METHOD lo_alv->get_columns RECEIVING value = lo_cols.
        CALL METHOD lo_cols->set_optimize EXPORTING value = 'X'.
        CALL METHOD lo_alv->get_functions RECEIVING value = lo_funcs.
        CALL METHOD lo_funcs->set_all EXPORTING value = 'X'.
        CALL METHOD lo_alv->display.
      CATCH cx_salv_msg.
        MESSAGE 'Error displaying results.' TYPE 'S' DISPLAY LIKE 'E'.
    ENDTRY.
  ENDIF.
ENDFORM.

*--- NETWORK DIAGNOSTICS ---*
FORM execute_network_diag.
  DATA: lt_result  TYPE TABLE OF ty_net_result,
        ls_result  TYPE ty_net_result,
        lv_command TYPE c LENGTH 255,
        lv_host    TYPE string,
        lv_line_no TYPE i,
        lo_alv     TYPE REF TO cl_salv_table,
        lo_cols    TYPE REF TO cl_salv_columns_table,
        lo_col     TYPE REF TO cl_salv_column,
        lo_funcs   TYPE REF TO cl_salv_functions_list.

  DATA: BEGIN OF lt_systab OCCURS 0,
          line(250),
        END OF lt_systab.

  lv_host = p_n_hst.
  CONDENSE lv_host.

  IF lv_host IS INITIAL.
    MESSAGE 'Please enter a hostname or IP address.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Validate input:
  "  - Reject shell metacharacters and control chars (newline, CR, tab) for ALL variants.
  "  - For ping/nslookup/traceroute, enforce a strict hostname/IP whitelist on top.
  "  - Curl still needs :/?=&% etc., so it keeps the relaxed blacklist check only.
  DATA: lv_valid TYPE abap_bool VALUE abap_true.
  IF lv_host CA ';|&`$><"''\'.
    lv_valid = abap_false.
  ENDIF.
  IF lv_host CA cl_abap_char_utilities=>cr_lf OR
     lv_host CA cl_abap_char_utilities=>newline OR
     lv_host CA cl_abap_char_utilities=>horizontal_tab.
    lv_valid = abap_false.
  ENDIF.
  IF p_nc_cu <> 'X'.
    " Hostname / IPv4 / IPv6: letters, digits, dot, dash, colon
    IF NOT lv_host CO 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-:'.
      lv_valid = abap_false.
    ENDIF.
  ENDIF.
  IF lv_valid = abap_false.
    MESSAGE 'Invalid characters in hostname/URL.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Curl requires execute authorization (ACTN=02) on module NET
  IF p_nc_cu = 'X' AND gv_debug_active = abap_false.
    AUTHORITY-CHECK OBJECT 'Z_BASTOOL'
      ID 'ZBAS_MODL' FIELD c_mod_net
      ID 'ZBAS_ACTN' FIELD c_actn_execute.
    IF sy-subrc <> 0.
      MESSAGE 'Curl requires execute authorization (ACTN=02) on module NET.' TYPE 'S' DISPLAY LIKE 'E'.
      RETURN.
    ENDIF.
  ENDIF.

  " Build command based on radio button selection
  IF p_nc_pn = 'X'.
    CONCATENATE 'ping -c 4' lv_host '2>&1' INTO lv_command SEPARATED BY space.
  ELSEIF p_nc_ns = 'X'.
    CONCATENATE 'nslookup' lv_host '2>&1' INTO lv_command SEPARATED BY space.
  ELSEIF p_nc_tr = 'X'.
    CONCATENATE 'traceroute -n -m 10 -w 2' lv_host '2>&1' INTO lv_command SEPARATED BY space.
  ELSEIF p_nc_cu = 'X'.
    CONCATENATE 'curl -sS -o /dev/null -w "HTTP Code: %{http_code}\nTime Total: %{time_total}s\nTime Connect: %{time_connect}s\nTime DNS: %{time_namelookup}s\nRemote IP: %{remote_ip}\nSize: %{size_download} bytes\n" -m 10' lv_host INTO lv_command SEPARATED BY space.
  ENDIF.

  " Execute
  CALL 'SYSTEM'
    ID 'COMMAND' FIELD lv_command
    ID 'TAB'     FIELD lt_systab-*sys*.

  " Convert to result table
  LOOP AT lt_systab.
    ADD 1 TO lv_line_no.
    CLEAR ls_result.
    ls_result-line_no = lv_line_no.
    ls_result-content = lt_systab-line.
    APPEND ls_result TO lt_result.
  ENDLOOP.

  IF lt_result IS INITIAL.
    CLEAR ls_result.
    ls_result-line_no = 1.
    ls_result-content = 'No output returned. Command may have timed out.'.
    APPEND ls_result TO lt_result.
  ENDIF.

  " Display as ALV Popup
  TRY.
      CALL METHOD cl_salv_table=>factory
        IMPORTING
          r_salv_table = lo_alv
        CHANGING
          t_table      = lt_result.

      lo_cols = lo_alv->get_columns( ).
      lo_cols->set_optimize( 'X' ).

      TRY.
          lo_col = lo_cols->get_column( 'LINE_NO' ).
          lo_col->set_short_text( '#' ).
          lo_col->set_medium_text( 'Line' ).
          lo_col->set_long_text( 'Line No' ).
        CATCH cx_salv_not_found.
      ENDTRY.
      TRY.
          lo_col = lo_cols->get_column( 'CONTENT' ).
          lo_col->set_short_text( 'Output' ).
          lo_col->set_medium_text( 'Output' ).
          lo_col->set_long_text( 'Command Output' ).
        CATCH cx_salv_not_found.
      ENDTRY.

      lo_funcs = lo_alv->get_functions( ).
      lo_funcs->set_all( 'X' ).

      DATA lv_title TYPE lvc_title.
      IF p_nc_pn = 'X'. lv_title = |Ping: { lv_host }|.
      ELSEIF p_nc_ns = 'X'. lv_title = |NSLookup: { lv_host }|.
      ELSEIF p_nc_tr = 'X'. lv_title = |Traceroute: { lv_host }|.
      ELSEIF p_nc_cu = 'X'. lv_title = |Curl: { lv_host }|.
      ENDIF.

      lo_alv->get_display_settings( )->set_list_header( lv_title ).
      lo_alv->set_screen_popup( start_column = 5 end_column = 130 start_line = 3 end_line = 25 ).
      lo_alv->display( ).
    CATCH cx_salv_msg.
      MESSAGE 'Error displaying results.' TYPE 'S' DISPLAY LIKE 'E'.
  ENDTRY.
ENDFORM.

*--- CERTIFICATE CHECKER ---*
FORM execute_cert_checker.
  DATA: lt_certs   TYPE TABLE OF ty_cert_info,
        lo_alv     TYPE REF TO cl_salv_table,
        lo_cols    TYPE REF TO cl_salv_columns_table,
        lo_col     TYPE REF TO cl_salv_column,
        lo_funcs   TYPE REF TO cl_salv_functions_list.

  DATA: lv_today    TYPE d,
        lv_db_tried TYPE i,
        lv_db_ok    TYPE i,
        lv_fs_tried TYPE i,
        lv_fs_ok    TYPE i.

  lv_today = sy-datum.

  " === Step 1: STRUST DB-based scan (SSFP_GET_PSEINFO over standard contexts) ===
  " Inspired by SSF_ALERT_CERTEXPIRE; works even if PSEs live only in DB.
  PERFORM scan_pses_db USING lv_today
                    CHANGING lt_certs lv_db_tried lv_db_ok.

  " === Step 2: Filesystem fallback when DB scan returned nothing ===
  IF lt_certs IS INITIAL.
    PERFORM scan_pses_fs USING lv_today
                      CHANGING lt_certs lv_fs_tried lv_fs_ok.
  ENDIF.

  " === Step 3: Differentiated end message when nothing was found ===
  IF lt_certs IS INITIAL.
    IF lv_db_ok = 0 AND lv_fs_ok = 0.
      MESSAGE |No certificates found. Tried { lv_db_tried } STRUST contexts via SSFP_GET_PSEINFO and { lv_fs_tried } PSE file(s) in DIR_INSTANCE/sec. Check S_RZL_ADM / SAPSECULIB / STRUST configuration.| TYPE 'S' DISPLAY LIKE 'W'.
    ELSE.
      MESSAGE |PSE access succeeded but no certificates were returned (PSEs may be empty).| TYPE 'S' DISPLAY LIKE 'W'.
    ENDIF.
    RETURN.
  ENDIF.

  " Sort: expired/critical first
  SORT lt_certs BY days_left ASCENDING.

  " Display as ALV
  TRY.
      CALL METHOD cl_salv_table=>factory
        IMPORTING
          r_salv_table = lo_alv
        CHANGING
          t_table      = lt_certs.

      lo_cols = lo_alv->get_columns( ).
      lo_cols->set_optimize( 'X' ).

      TRY. lo_col = lo_cols->get_column( 'ICON' ). lo_col->set_short_text( 'Status' ). lo_col->set_medium_text( 'Status' ). CATCH cx_salv_not_found. ENDTRY.
      TRY. lo_col = lo_cols->get_column( 'CONTEXT' ). lo_col->set_short_text( 'PSE' ). lo_col->set_medium_text( 'PSE Context' ). CATCH cx_salv_not_found. ENDTRY.
      TRY. lo_col = lo_cols->get_column( 'SUBJECT' ). lo_col->set_short_text( 'Subject' ). lo_col->set_medium_text( 'Subject' ). CATCH cx_salv_not_found. ENDTRY.
      TRY. lo_col = lo_cols->get_column( 'ISSUER' ). lo_col->set_short_text( 'Issuer' ). lo_col->set_medium_text( 'Issuer' ). CATCH cx_salv_not_found. ENDTRY.
      TRY. lo_col = lo_cols->get_column( 'VALID_FROM' ). lo_col->set_short_text( 'From' ). lo_col->set_medium_text( 'Valid From' ). CATCH cx_salv_not_found. ENDTRY.
      TRY. lo_col = lo_cols->get_column( 'VALID_TO' ). lo_col->set_short_text( 'Until' ). lo_col->set_medium_text( 'Valid Until' ). CATCH cx_salv_not_found. ENDTRY.
      TRY. lo_col = lo_cols->get_column( 'DAYS_LEFT' ). lo_col->set_short_text( 'Days' ). lo_col->set_medium_text( 'Days Left' ). CATCH cx_salv_not_found. ENDTRY.
      TRY. lo_col = lo_cols->get_column( 'SERIAL' ). lo_col->set_short_text( 'Serial' ). lo_col->set_medium_text( 'Serial No' ). CATCH cx_salv_not_found. ENDTRY.

      lo_funcs = lo_alv->get_functions( ).
      lo_funcs->set_all( 'X' ).

      lo_alv->get_display_settings( )->set_list_header( |SSL Certificates - { lines( lt_certs ) } found| ).
      lo_alv->set_screen_popup( start_column = 2 end_column = 170 start_line = 3 end_line = 30 ).
      lo_alv->display( ).
    CATCH cx_salv_msg.
      MESSAGE 'Error displaying certificates.' TYPE 'S' DISPLAY LIKE 'E'.
  ENDTRY.
ENDFORM.

*--- CERT SCAN: STRUST DB-based via SSFP_GET_PSEINFO ---*
FORM scan_pses_db USING iv_today TYPE d
               CHANGING ct_certs TYPE ANY TABLE
                        cv_tried TYPE i
                        cv_ok    TYPE i.
  TYPES: BEGIN OF lty_pse_cand,
           context  TYPE c LENGTH 4,
           applic   TYPE c LENGTH 6,
           descript TYPE string,
         END OF lty_pse_cand.
  DATA: lt_pses     TYPE STANDARD TABLE OF lty_pse_cand,
        ls_pse      TYPE lty_pse_cand,
        lv_cert     TYPE xstring,
        lt_pklist   TYPE STANDARD TABLE OF xstring,
        ls_pkitem   TYPE xstring,
        ls_cert     TYPE ty_cert_info,
        lv_subject  TYPE string,
        lv_issuer   TYPE string,
        lv_serial   TYPE string,
        lv_from     TYPE d,
        lv_to       TYPE d,
        lv_label    TYPE string.

  " Standard STRUST contexts (cf. SSF_ALERT_CERTEXPIRE create_pse_list)
  ls_pse-context = 'SSLS'. ls_pse-applic = 'DFAULT'. ls_pse-descript = 'SSL Server (DFAULT)'.   APPEND ls_pse TO lt_pses.
  ls_pse-context = 'SSLC'. ls_pse-applic = 'ANONYM'. ls_pse-descript = 'SSL Client (Anonym)'.   APPEND ls_pse TO lt_pses.
  ls_pse-context = 'SSLC'. ls_pse-applic = 'DFAULT'. ls_pse-descript = 'SSL Client (DFAULT)'.   APPEND ls_pse TO lt_pses.
  ls_pse-context = 'SSO2'. ls_pse-applic = 'DFAULT'. ls_pse-descript = 'SAP Logon Tickets'.     APPEND ls_pse TO lt_pses.
  ls_pse-context = 'WSSE'. ls_pse-applic = 'DFAULT'. ls_pse-descript = 'WS-Security (DFAULT)'.  APPEND ls_pse TO lt_pses.

  LOOP AT lt_pses INTO ls_pse.
    ADD 1 TO cv_tried.
    CLEAR: lv_cert, lt_pklist.

    TRY.
        CALL FUNCTION 'SSFP_GET_PSEINFO'
          EXPORTING
            context         = ls_pse-context
            applic          = ls_pse-applic
            accept_no_cert  = 'X'
          IMPORTING
            certificate     = lv_cert
            certificatelist = lt_pklist
          EXCEPTIONS
            ssf_no_ssflib     = 1
            ssf_krn_error     = 2
            ssf_invalid_par   = 3   " PSE does not exist on this system - skip
            ssf_unknown_error = 4
            OTHERS            = 5.
      CATCH cx_root.
        sy-subrc = 99.
    ENDTRY.

    IF sy-subrc = 3 OR sy-subrc = 99.
      CONTINUE.    " PSE not present / FM unavailable - silent skip
    ENDIF.
    IF sy-subrc <> 0.
      CONTINUE.
    ENDIF.

    ADD 1 TO cv_ok.
    lv_label = |{ ls_pse-context }/{ ls_pse-applic } - { ls_pse-descript }|.

    " Own certificate
    IF lv_cert IS NOT INITIAL.
      PERFORM parse_cert_into_row USING lv_cert lv_label 'OWN' iv_today CHANGING ct_certs.
    ENDIF.

    " Trusted CA / partner certs
    LOOP AT lt_pklist INTO ls_pkitem.
      IF ls_pkitem IS INITIAL. CONTINUE. ENDIF.
      PERFORM parse_cert_into_row USING ls_pkitem lv_label 'TRUST' iv_today CHANGING ct_certs.
    ENDLOOP.
  ENDLOOP.
ENDFORM.

*--- CERT SCAN: filesystem fallback over <DIR_INSTANCE>/sec/*.pse ---*
FORM scan_pses_fs USING iv_today TYPE d
               CHANGING ct_certs TYPE ANY TABLE
                        cv_tried TYPE i
                        cv_ok    TYPE i.
  DATA: lv_inst_dir    TYPE c LENGTH 128,
        lv_sec_dir     TYPE c LENGTH 128,
        lv_dir_name    TYPE salfile-longname,
        lt_dir_list    TYPE TABLE OF salfldir,
        ls_dir_list    TYPE salfldir,
        lt_pse_names   TYPE TABLE OF string,
        lv_pse_name    TYPE string,
        lv_profile     TYPE c LENGTH 256,
        lv_pse_fname_l TYPE string,
        lv_dir_read_ok TYPE abap_bool VALUE abap_false,
        lt_certlist    TYPE TABLE OF xstring,
        ls_certdata    TYPE xstring,
        lv_label       TYPE string.

  CALL 'C_SAPGPARAM' ID 'NAME' FIELD 'DIR_INSTANCE' ID 'VALUE' FIELD lv_inst_dir.
  CONCATENATE lv_inst_dir '/sec/' INTO lv_sec_dir.

  lv_dir_name = lv_sec_dir.
  CONDENSE lv_dir_name.
  CALL FUNCTION 'RZL_READ_DIR_LOCAL'
    EXPORTING  name     = lv_dir_name
    TABLES     file_tbl = lt_dir_list
    EXCEPTIONS OTHERS   = 1.
  IF sy-subrc = 0.
    lv_dir_read_ok = abap_true.
    LOOP AT lt_dir_list INTO ls_dir_list.
      lv_pse_fname_l = ls_dir_list-name.
      TRANSLATE lv_pse_fname_l TO LOWER CASE.
      IF lv_pse_fname_l CP '*.pse'.
        APPEND CONV string( ls_dir_list-name ) TO lt_pse_names.
      ENDIF.
    ENDLOOP.
  ENDIF.

  " Last-resort fallback: blind probe of the standard 4 file names
  IF lt_pse_names IS INITIAL AND lv_dir_read_ok = abap_false.
    APPEND 'SAPSSLS.pse' TO lt_pse_names.
    APPEND 'SAPSSLC.pse' TO lt_pse_names.
    APPEND 'SAPSSLA.pse' TO lt_pse_names.
    APPEND 'WSSE.pse'    TO lt_pse_names.
  ENDIF.

  LOOP AT lt_pse_names INTO lv_pse_name.
    ADD 1 TO cv_tried.
    CONCATENATE lv_sec_dir lv_pse_name INTO lv_profile.

    TRY.
        CLEAR lt_certlist.
        CALL FUNCTION 'SSFC_GET_CERTIFICATELIST'
          EXPORTING  profile         = lv_profile
          TABLES     certificatelist = lt_certlist
          EXCEPTIONS OTHERS          = 6.
        IF sy-subrc <> 0. CONTINUE. ENDIF.
        ADD 1 TO cv_ok.

        lv_label = |file:{ lv_pse_name }|.
        LOOP AT lt_certlist INTO ls_certdata.
          IF ls_certdata IS INITIAL. CONTINUE. ENDIF.
          PERFORM parse_cert_into_row USING ls_certdata lv_label 'FILE' iv_today CHANGING ct_certs.
        ENDLOOP.
      CATCH cx_root.
        CONTINUE.
    ENDTRY.
  ENDLOOP.
ENDFORM.

*--- HELPER: parse one X.509 blob and append a row to lt_certs ---*
FORM parse_cert_into_row USING iv_blob   TYPE xstring
                               iv_label  TYPE string
                               iv_role   TYPE string
                               iv_today  TYPE d
                      CHANGING ct_certs  TYPE ANY TABLE.
  " SSFC_PARSE_CERTIFICATE returns VALIDFROM / VALIDTO as a CHAR 14
  " timestamp in format YYYYMMDDHHMMSS - NOT as TYPE d. Wrong type
  " causes CX_SY_DYN_CALL_ILLEGAL_TYPE dump. The dedicated DDIC type
  " SSFTIMESTMP is not present on every release, so we declare the
  " variables locally as plain CHAR 14, which is structurally identical.
  DATA: lv_subject TYPE string,
        lv_issuer  TYPE string,
        lv_serial  TYPE string,
        lv_from    TYPE c LENGTH 14,
        lv_to      TYPE c LENGTH 14,
        lv_from_d  TYPE d,
        lv_to_d    TYPE d,
        ls_cert    TYPE ty_cert_info.

  CLEAR: lv_subject, lv_issuer, lv_serial, lv_from, lv_to,
         lv_from_d, lv_to_d, ls_cert.

  CALL FUNCTION 'SSFC_PARSE_CERTIFICATE'
    EXPORTING  certificate = iv_blob
    IMPORTING  subject     = lv_subject
               issuer      = lv_issuer
               serialno    = lv_serial
               validfrom   = lv_from
               validto     = lv_to
    EXCEPTIONS OTHERS      = 6.
  IF sy-subrc <> 0.
    RETURN.
  ENDIF.

  " Extract date portion (first 8 chars = YYYYMMDD) from timestamp.
  IF lv_from IS NOT INITIAL.
    lv_from_d = lv_from(8).
  ENDIF.
  IF lv_to IS NOT INITIAL.
    lv_to_d = lv_to(8).
  ENDIF.

  ls_cert-context = |{ iv_label } [{ iv_role }]|.
  ls_cert-subject = lv_subject.
  ls_cert-issuer  = lv_issuer.
  ls_cert-serial  = lv_serial.

  IF lv_from_d IS NOT INITIAL.
    CONCATENATE lv_from_d(4) '-' lv_from_d+4(2) '-' lv_from_d+6(2) INTO ls_cert-valid_from.
  ENDIF.
  IF lv_to_d IS NOT INITIAL.
    CONCATENATE lv_to_d(4) '-' lv_to_d+4(2) '-' lv_to_d+6(2) INTO ls_cert-valid_to.
  ENDIF.

  IF lv_to_d IS NOT INITIAL.
    ls_cert-days_left = lv_to_d - iv_today.
  ENDIF.
  IF ls_cert-days_left < 0.
    ls_cert-icon = icon_red_light.
  ELSEIF ls_cert-days_left < 30.
    ls_cert-icon = icon_yellow_light.
  ELSE.
    ls_cert-icon = icon_green_light.
  ENDIF.

  INSERT ls_cert INTO TABLE ct_certs.
ENDFORM.

*--- PROFILE PARAMETERS ---*
FORM execute_profile_params.
  DATA: lt_params  TYPE TABLE OF ty_profile_param,
        ls_param   TYPE ty_profile_param,
        lo_alv     TYPE REF TO cl_salv_table,
        lo_cols    TYPE REF TO cl_salv_columns_table,
        lo_col     TYPE REF TO cl_salv_column,
        lo_funcs   TYPE REF TO cl_salv_functions_list.

  DATA: lv_filter    TYPE string,
        lv_prof_dir  TYPE epsf-epsdirnam,
        lv_sid       TYPE c LENGTH 3,
        lv_filepath  TYPE string,
        lv_filename  TYPE string,
        lv_line      TYPE string,
        lv_name      TYPE string,
        lv_value     TYPE string,
        lv_ok        TYPE abap_bool.

  " File list from profile directory
  DATA: lt_dir_list  TYPE TABLE OF epsfili,
        ls_dir_entry TYPE epsfili.

  lv_filter = p_pf_nm.
  CONDENSE lv_filter.
  lv_sid = sy-sysid.

  " Get profile directory
  CALL 'C_SAPGPARAM'
    ID 'NAME'  FIELD 'DIR_PROFILE'
    ID 'VALUE' FIELD lv_prof_dir.

  IF lv_prof_dir IS INITIAL.
    MESSAGE 'Could not determine profile directory.' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Read directory contents
  CALL FUNCTION 'EPS_GET_DIRECTORY_LISTING'
    EXPORTING
      dir_name = lv_prof_dir
    TABLES
      dir_list = lt_dir_list
    EXCEPTIONS
      OTHERS   = 4.

  IF sy-subrc <> 0.
    MESSAGE |Cannot read profile directory { lv_prof_dir }.| TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " Process each valid profile file
  LOOP AT lt_dir_list INTO ls_dir_entry.
    lv_filename = ls_dir_entry-name.
    CONDENSE lv_filename.

    " Skip directories, empty entries
    IF lv_filename IS INITIAL OR lv_filename = '.' OR lv_filename = '..'.
      CONTINUE.
    ENDIF.

    " Only process actual profile files, not versions/backups:
    " Accept: DEFAULT.PFL and <SID>_<INSTANCE>_<HOST> (no dot in name)
    " Skip: DEFAULT.1.PFL, DEFAULT.PFL.bak2, S4H_D00_vhcals4hci.1, INSTSTAT, dev_*, etc.
    lv_ok = abap_false.

    IF lv_filename = 'DEFAULT.PFL'.
      lv_ok = abap_true.
    ELSEIF lv_filename CP |{ lv_sid }_*|.
      " Instance profile: must not contain a dot (versioned have .1, .2 etc.)
      IF lv_filename NA '.'.
        lv_ok = abap_true.
      ENDIF.
    ENDIF.

    IF lv_ok = abap_false. CONTINUE. ENDIF.

    " Build full file path
    CONCATENATE lv_prof_dir '/' lv_filename INTO lv_filepath.

    " Read the file
    OPEN DATASET lv_filepath FOR INPUT IN TEXT MODE ENCODING DEFAULT.
    IF sy-subrc <> 0. CONTINUE. ENDIF.

    DO.
      READ DATASET lv_filepath INTO lv_line.
      IF sy-subrc <> 0. EXIT. ENDIF.

      CONDENSE lv_line.

      " Skip empty lines and comments
      IF lv_line IS INITIAL. CONTINUE. ENDIF.
      IF lv_line(1) = '#'. CONTINUE. ENDIF.

      " Parse parameter = value
      IF lv_line NS '='. CONTINUE. ENDIF.
      SPLIT lv_line AT '=' INTO lv_name lv_value.
      CONDENSE: lv_name, lv_value.

      IF lv_name IS INITIAL. CONTINUE. ENDIF.

      " Apply filter
      IF lv_filter IS NOT INITIAL.
        IF lv_name NP lv_filter.
          CONTINUE.
        ENDIF.
      ENDIF.

      CLEAR ls_param.
      ls_param-name    = lv_name.
      ls_param-value   = lv_value.
      ls_param-profile = lv_filename.
      APPEND ls_param TO lt_params.
    ENDDO.

    CLOSE DATASET lv_filepath.
  ENDLOOP.

  " Sort by name, then profile
  SORT lt_params BY name profile.

  IF lt_params IS INITIAL.
    IF lv_filter IS NOT INITIAL.
      MESSAGE |No parameters matching '{ lv_filter }' found.| TYPE 'S' DISPLAY LIKE 'W'.
    ELSE.
      MESSAGE 'No profile files found or not readable.' TYPE 'S' DISPLAY LIKE 'W'.
    ENDIF.
    RETURN.
  ENDIF.

  " Display as ALV
  TRY.
      CALL METHOD cl_salv_table=>factory
        IMPORTING
          r_salv_table = lo_alv
        CHANGING
          t_table      = lt_params.

      lo_cols = lo_alv->get_columns( ).
      lo_cols->set_optimize( 'X' ).

      TRY. lo_col = lo_cols->get_column( 'NAME' ). lo_col->set_short_text( 'Param' ). lo_col->set_medium_text( 'Parameter' ). lo_col->set_long_text( 'Parameter Name' ). CATCH cx_salv_not_found. ENDTRY.
      TRY. lo_col = lo_cols->get_column( 'VALUE' ). lo_col->set_short_text( 'Value' ). lo_col->set_medium_text( 'Current Value' ). lo_col->set_long_text( 'Current Value' ). CATCH cx_salv_not_found. ENDTRY.
      TRY. lo_col = lo_cols->get_column( 'PROFILE' ). lo_col->set_short_text( 'Profile' ). lo_col->set_medium_text( 'Profile File' ). lo_col->set_long_text( 'Profile File' ). CATCH cx_salv_not_found. ENDTRY.

      lo_funcs = lo_alv->get_functions( ).
      lo_funcs->set_all( 'X' ).

      lo_alv->get_display_settings( )->set_list_header( |Profile Parameters - { lines( lt_params ) } found| ).
      lo_alv->set_screen_popup( start_column = 2 end_column = 160 start_line = 3 end_line = 35 ).
      lo_alv->display( ).
    CATCH cx_salv_msg.
      MESSAGE 'Error displaying parameters.' TYPE 'S' DISPLAY LIKE 'E'.
  ENDTRY.
ENDFORM.

*--- SYSTEM INFO ---*
FORM execute_system_info.
  DATA: lt_info    TYPE TABLE OF ty_sysinfo_line,
        ls_info    TYPE ty_sysinfo_line,
        lo_alv     TYPE REF TO cl_salv_table,
        lo_cols    TYPE REF TO cl_salv_columns_table,
        lo_col     TYPE REF TO cl_salv_column,
        lo_funcs   TYPE REF TO cl_salv_functions_list.

  " --- Basic System Info ---
  CLEAR ls_info. ls_info-label = 'System ID'. ls_info-value = sy-sysid. APPEND ls_info TO lt_info.
  CLEAR ls_info. ls_info-label = 'Client'. ls_info-value = sy-mandt. APPEND ls_info TO lt_info.
  CLEAR ls_info. ls_info-label = 'Server Host'. ls_info-value = sy-host. APPEND ls_info TO lt_info.
  CLEAR ls_info. ls_info-label = 'SAP Release'. ls_info-value = sy-saprl. APPEND ls_info TO lt_info.
  CLEAR ls_info. ls_info-label = 'Database System'. ls_info-value = sy-dbsys. APPEND ls_info TO lt_info.
  CLEAR ls_info. ls_info-label = 'Operating System'. ls_info-value = sy-opsys. APPEND ls_info TO lt_info.

  " --- IP Address via hostname -i ---
  DATA: BEGIN OF lt_ip_tab OCCURS 0,
          line(200),
        END OF lt_ip_tab.
  DATA: lv_ip_cmd TYPE c LENGTH 100 VALUE 'hostname -i'.

  CALL 'SYSTEM'
    ID 'COMMAND' FIELD lv_ip_cmd
    ID 'TAB'     FIELD lt_ip_tab-*sys*.

  DATA lv_ip_line TYPE string.
  LOOP AT lt_ip_tab.
    lv_ip_line = lt_ip_tab-line.
    CONDENSE lv_ip_line.
    IF lv_ip_line IS NOT INITIAL.
      CLEAR ls_info. ls_info-label = 'IP Address'. ls_info-value = lv_ip_line. APPEND ls_info TO lt_info.
      EXIT.
    ENDIF.
  ENDLOOP.

  " --- Instance Number ---
  DATA: lv_inst_nr TYPE c LENGTH 10.
  CALL 'C_SAPGPARAM'
    ID 'NAME'  FIELD 'SAPSYSTEM'
    ID 'VALUE' FIELD lv_inst_nr.
  IF sy-subrc = 0.
    CLEAR ls_info. ls_info-label = 'Instance Nr'. ls_info-value = lv_inst_nr. APPEND ls_info TO lt_info.
  ENDIF.

  " --- Separator ---
  CLEAR ls_info. ls_info-label = '--- Disk Usage ---'. APPEND ls_info TO lt_info.

  " --- Disk Space via df -h ---
  DATA: BEGIN OF lt_df_tab OCCURS 0,
          line(200),
        END OF lt_df_tab.
  DATA: lv_df_cmd TYPE c LENGTH 100 VALUE 'df -h'.

  CALL 'SYSTEM'
    ID 'COMMAND' FIELD lv_df_cmd
    ID 'TAB'     FIELD lt_df_tab-*sys*.

  DATA: lv_df_line TYPE string,
        lv_first   TYPE abap_bool VALUE abap_true.
  LOOP AT lt_df_tab.
    lv_df_line = lt_df_tab-line.
    CONDENSE lv_df_line.
    IF lv_df_line IS INITIAL. CONTINUE. ENDIF.
    IF lv_first = abap_true.
      " Header line
      CLEAR ls_info.
      ls_info-label = 'Filesystem'.
      ls_info-value = lv_df_line.
      APPEND ls_info TO lt_info.
      lv_first = abap_false.
    ELSE.
      " Data lines: first token is filesystem name
      DATA lt_tokens TYPE TABLE OF string.
      DATA lv_fs TYPE string.
      SPLIT lv_df_line AT space INTO TABLE lt_tokens.
      DELETE lt_tokens WHERE table_line IS INITIAL.
      IF lines( lt_tokens ) > 0.
        READ TABLE lt_tokens INTO lv_fs INDEX 1.
      ELSE.
        lv_fs = ''.
      ENDIF.
      CLEAR ls_info.
      ls_info-label = lv_fs.
      ls_info-value = lv_df_line.
      APPEND ls_info TO lt_info.
    ENDIF.
  ENDLOOP.

  " --- Display as ALV Popup ---
  TRY.
      CALL METHOD cl_salv_table=>factory
        IMPORTING
          r_salv_table = lo_alv
        CHANGING
          t_table      = lt_info.

      lo_cols = lo_alv->get_columns( ).
      lo_cols->set_optimize( 'X' ).

      TRY.
          lo_col = lo_cols->get_column( 'LABEL' ).
          lo_col->set_short_text( 'Info' ).
          lo_col->set_medium_text( 'Information' ).
          lo_col->set_long_text( 'Information' ).
        CATCH cx_salv_not_found.
      ENDTRY.
      TRY.
          lo_col = lo_cols->get_column( 'VALUE' ).
          lo_col->set_short_text( 'Value' ).
          lo_col->set_medium_text( 'Value' ).
          lo_col->set_long_text( 'Value' ).
        CATCH cx_salv_not_found.
      ENDTRY.

      lo_funcs = lo_alv->get_functions( ).
      lo_funcs->set_all( 'X' ).

      lo_alv->set_screen_popup( start_column = 5 end_column = 120 start_line = 3 end_line = 30 ).
      lo_alv->display( ).
    CATCH cx_salv_msg.
      MESSAGE 'Error displaying system info.' TYPE 'S' DISPLAY LIKE 'E'.
  ENDTRY.
ENDFORM.

*--- F4 HELP: FILE OPEN ---*
FORM f4_file_open USING cv_path TYPE string iv_zip TYPE c.
  DATA: lt_f      TYPE filetable,
        lv_rc     TYPE i,
        lv_filter TYPE string.

  IF iv_zip = 'X'.
    lv_filter = '*.zip'.
  ELSE.
    lv_filter = '*.*'.
  ENDIF.

  cl_gui_frontend_services=>file_open_dialog(
    EXPORTING
      file_filter = lv_filter
    CHANGING
      file_table  = lt_f
      rc          = lv_rc
    EXCEPTIONS
      OTHERS      = 1 ).

  IF lines( lt_f ) > 0.
    cv_path = lt_f[ 1 ]-filename.
  ENDIF.
ENDFORM.

*--- F4 HELP: TRU K/R FILE OPEN WITH SIBLING AUTO-FILL (plan B2) ---*
* Opens file picker for a K or R transport file. If the selected file name
* starts with K/R, we try to find the sibling (R/K) in the same directory
* and auto-populate cv_sibling if found.
FORM f4_tru_file USING    iv_path_field    TYPE string
                          iv_sibling_field TYPE string
                 CHANGING cv_path          TYPE string
                          cv_sibling       TYPE string.
  DATA: lt_f        TYPE filetable,
        lv_rc       TYPE i,
        lv_sel      TYPE string,
        lv_sep      TYPE c LENGTH 1,
        lv_dir      TYPE string,
        lv_name     TYPE string,
        lv_first    TYPE c LENGTH 1,
        lv_rest     TYPE string,
        lv_new      TYPE string,
        lv_sib_full TYPE string,
        lv_exists   TYPE abap_bool,
        lv_pos      TYPE i,
        lt_match    TYPE match_result_tab,
        lt_dynp     TYPE TABLE OF dynpread,
        ls_dynp     TYPE dynpread.

  cl_gui_frontend_services=>file_open_dialog(
    EXPORTING
      file_filter = '*.*'
    CHANGING
      file_table  = lt_f
      rc          = lv_rc
    EXCEPTIONS
      OTHERS      = 1 ).
  IF lines( lt_f ) = 0.
    RETURN.
  ENDIF.

  lv_sel = lt_f[ 1 ]-filename.
  cv_path = lv_sel.

  " Determine path separator (Windows path => '\', else '/')
  IF lv_sel CS '\'.
    lv_sep = '\'.
  ELSE.
    lv_sep = '/'.
  ENDIF.

  " Split into directory + file name (offset of LAST separator)
  FIND ALL OCCURRENCES OF lv_sep IN lv_sel RESULTS lt_match.
  IF lt_match IS NOT INITIAL.
    lv_pos = lt_match[ lines( lt_match ) ]-offset + 1.   " include the separator in the dir prefix
    lv_dir  = lv_sel(lv_pos).
    lv_name = lv_sel+lv_pos.
  ELSE.
    lv_dir  = ''.
    lv_name = lv_sel.
  ENDIF.

  IF strlen( lv_name ) < 1.
    RETURN.
  ENDIF.

  lv_first = lv_name(1).
  TRANSLATE lv_first TO UPPER CASE.
  lv_rest  = lv_name+1.

  CASE lv_first.
    WHEN 'K'. lv_new = |R{ lv_rest }|.
    WHEN 'R'. lv_new = |K{ lv_rest }|.
    WHEN OTHERS.
      MESSAGE |File '{ lv_name }' does not start with K or R - sibling auto-fill skipped.| TYPE 'S'.
      RETURN.
  ENDCASE.

  lv_sib_full = |{ lv_dir }{ lv_new }|.

  cl_gui_frontend_services=>file_exist(
    EXPORTING  file   = lv_sib_full
    RECEIVING  result = lv_exists
    EXCEPTIONS OTHERS = 1 ).

  IF sy-subrc = 0 AND lv_exists = abap_true.
    cv_sibling = lv_sib_full.
    MESSAGE |Sibling auto-filled: { lv_new }| TYPE 'S'.
  ELSE.
    " Help the tester see why nothing happened.
    MESSAGE |Sibling '{ lv_new }' not found in '{ lv_dir }' - field left empty.| TYPE 'S'.
  ENDIF.

  " Push values to the dynpro screen buffer. CHANGING parameters update the
  " program variables, but the screen field still shows its old value
  " unless DYNP_VALUES_UPDATE writes it back. Without this the user sees
  " an empty data-file field even when cv_sibling was successfully set.
  CLEAR lt_dynp.
  ls_dynp-fieldname  = iv_path_field.
  ls_dynp-fieldvalue = cv_path.
  APPEND ls_dynp TO lt_dynp.
  IF cv_sibling IS NOT INITIAL.
    ls_dynp-fieldname  = iv_sibling_field.
    ls_dynp-fieldvalue = cv_sibling.
    APPEND ls_dynp TO lt_dynp.
  ENDIF.
  CALL FUNCTION 'DYNP_VALUES_UPDATE'
    EXPORTING
      dyname     = sy-cprog
      dynumb     = sy-dynnr
    TABLES
      dynpfields = lt_dynp
    EXCEPTIONS
      OTHERS     = 1.
ENDFORM.

*--- F4 HELP FOR DIRECTORY ---*
FORM f4_dir_open USING cv_dir TYPE string.
  DATA: lv_folder TYPE string.

  CALL METHOD cl_gui_frontend_services=>directory_browse
    EXPORTING
      window_title    = 'Select Directory'
    CHANGING
      selected_folder = lv_folder
    EXCEPTIONS
      OTHERS          = 1.

  IF lv_folder IS NOT INITIAL.
    cv_dir = lv_folder.
  ENDIF.
ENDFORM.

*======================================================================*
* SECURITY LAYER IMPLEMENTATIONS
*======================================================================*

*--- HAS MODULE AUTH (lightweight check used by INIT + PBO) ---*
* Returns cv_has = 'X' if user has Z_BASTOOL with the given module and ACTN=01.
* No side effects (no message), unlike check_authorization.
FORM has_module_auth USING iv_module TYPE clike
                     CHANGING cv_has TYPE abap_bool.
  IF gv_debug_active = abap_true.
    cv_has = abap_true.
    RETURN.
  ENDIF.
  AUTHORITY-CHECK OBJECT 'Z_BASTOOL'
    ID 'ZBAS_MODL' FIELD iv_module
    ID 'ZBAS_ACTN' FIELD '01'.
  IF sy-subrc = 0.
    cv_has = abap_true.
  ELSE.
    cv_has = abap_false.
  ENDIF.
ENDFORM.

*--- CHECK AUTHORIZATION ---*
* Checks custom auth object Z_BASTOOL.
* Returns: ev_ok = 'X' if authorized, space if not.
FORM check_authorization USING iv_module TYPE c
                               iv_activity TYPE c
                         CHANGING ev_ok TYPE abap_bool.
  CLEAR ev_ok.

  IF gv_debug_active = abap_true.
    ev_ok = abap_true.
    RETURN.
  ENDIF.

  AUTHORITY-CHECK OBJECT 'Z_BASTOOL'
    ID 'ZBAS_MODL' FIELD iv_module
    ID 'ZBAS_ACTN' FIELD iv_activity.

  IF sy-subrc = 0.
    ev_ok = abap_true.
  ELSE.
    MESSAGE |Authorization missing for module { iv_module } (activity { iv_activity }).| TYPE 'S' DISPLAY LIKE 'E'.
  ENDIF.
ENDFORM.

*--- WRITE AUDIT LOG ---*
* Writes an entry to table ZBAS_TOOL_LOG.
* If the table does not exist yet, the INSERT silently fails.
* Critical actions (Severity C) are also written to SM20.
FORM write_audit_log USING iv_module   TYPE clike
                           iv_action   TYPE clike
                           iv_detail1  TYPE clike
                           iv_detail2  TYPE clike
                           iv_severity TYPE clike.
  " Gate 1: Debug mode WITHOUT audit suppresses ALL audit writes
  IF gv_debug_active = abap_true AND gv_debug_audit = abap_false.
    RETURN.
  ENDIF.
  " Gate 2: On non-PRD (and non-debug), audit is off by default (override via c_audit_non_prd).
  " In debug-WITH-audit we always write through, regardless of PRD/non-PRD.
  IF gv_debug_active = abap_false AND gv_is_prd = abap_false AND c_audit_non_prd = abap_false.
    RETURN.
  ENDIF.

  DATA: lv_guid      TYPE sysuuid_c32,
        lv_timestamp TYPE timestampl,
        lv_msg       TYPE c LENGTH 200.

  TRY.
      lv_guid = cl_system_uuid=>create_uuid_c32_static( ).
    CATCH cx_uuid_error.
      lv_guid = sy-uzeit.
  ENDTRY.

  GET TIME STAMP FIELD lv_timestamp.

  " Write to ZBAS_TOOL_LOG via dynamic SQL (compiles even if table missing)
  TRY.
      DATA lr_log TYPE REF TO data.
      FIELD-SYMBOLS <ls_log> TYPE any.
      FIELD-SYMBOLS <fv> TYPE any.

      CREATE DATA lr_log TYPE ('ZBAS_TOOL_LOG').
      ASSIGN lr_log->* TO <ls_log>.

      ASSIGN COMPONENT 'MANDT'     OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = sy-mandt.     ENDIF.
      ASSIGN COMPONENT 'LOG_ID'    OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = lv_guid.      ENDIF.
      ASSIGN COMPONENT 'TIMESTAMP' OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = lv_timestamp. ENDIF.
      ASSIGN COMPONENT 'USERNAME'  OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = sy-uname.     ENDIF.
      ASSIGN COMPONENT 'SYSID'    OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = sy-sysid.     ENDIF.
      ASSIGN COMPONENT 'MODL'     OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = iv_module.    ENDIF.
      ASSIGN COMPONENT 'ACTION'   OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = iv_action.    ENDIF.
      ASSIGN COMPONENT 'DETAIL1'  OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = iv_detail1.   ENDIF.
      ASSIGN COMPONENT 'DETAIL2'  OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = iv_detail2.   ENDIF.
      ASSIGN COMPONENT 'SEVERITY' OF STRUCTURE <ls_log> TO <fv>. IF sy-subrc = 0. <fv> = iv_severity.  ENDIF.

      INSERT ('ZBAS_TOOL_LOG') FROM <ls_log>.
    CATCH cx_root.
      " Table does not exist yet - silently continue
  ENDTRY.

  " Critical actions: also write to SM20 Security Audit Log
  IF iv_severity = 'C'.
    lv_msg = |Z_BASTOOL: { iv_module } / { iv_action } / { iv_detail1 }|.
    TRY.
        CALL FUNCTION 'RSAU_WRITE_ALARM_ENTRY'
          EXPORTING
            message = lv_msg
          EXCEPTIONS
            OTHERS  = 4.
      CATCH cx_root.
        " FM not available on this system - skip SM20 logging
    ENDTRY.
  ENDIF.
ENDFORM.

*--- DETECT PRODUCTION SYSTEM ---*
* Sets gv_is_prd based on:
* 1. Custom config table ZBAS_TOOL_CFG (if exists)
* 2. Fallback: T000-CCCATEGORY (P = productive client)
FORM detect_production_system.
  gv_is_prd = abap_false.

  " Method 1: Try custom config table (dynamic SQL, compiles without table)
  TRY.
      DATA lr_data TYPE REF TO data.
      DATA lv_where TYPE string.
      FIELD-SYMBOLS <lv_type> TYPE any.

      CREATE DATA lr_data TYPE c LENGTH 10.
      ASSIGN lr_data->* TO <lv_type>.

      lv_where = |SYSID = '{ sy-sysid }'|.
      SELECT SINGLE ('SYS_TYPE') FROM ('ZBAS_TOOL_CFG')
        INTO <lv_type>
        WHERE (lv_where).

      IF sy-subrc = 0 AND <lv_type> = 'PRD'.
        gv_is_prd = abap_true.
        RETURN.
      ELSEIF sy-subrc = 0.
        RETURN.
      ENDIF.
    CATCH cx_root.
      " Config table doesn't exist yet - use fallback
  ENDTRY.

  " Method 2: Check T000 system role (works on any SAP system)
  DATA lv_cccategory TYPE t000-cccategory.
  SELECT SINGLE cccategory FROM t000
    INTO lv_cccategory
    WHERE mandt = sy-mandt.

  IF sy-subrc = 0 AND lv_cccategory = 'P'.
    gv_is_prd = abap_true.
  ENDIF.
ENDFORM.

*--- CHECK DDIC OBJECTS ---*
* Verifies existence of DDIC objects required by this report.
* Missing objects are listed in a popup; user can Continue or Abort.
* The ZBAS_TOOL_LOG table is only required on productive systems.
FORM check_ddic_objects.
  TYPES: BEGIN OF ty_missing,
           object TYPE c LENGTH 30,
           kind   TYPE c LENGTH 20,
         END OF ty_missing.
  DATA: lt_missing TYPE TABLE OF ty_missing,
        ls_missing TYPE ty_missing,
        lv_cnt     TYPE i.

  " Domains
  SELECT SINGLE domname FROM dd01l INTO @DATA(lv_dom1) WHERE domname = 'ZBAS_DO_MODL'.
  IF sy-subrc <> 0.
    ls_missing-object = 'ZBAS_DO_MODL'. ls_missing-kind = 'Domain'.
    APPEND ls_missing TO lt_missing.
  ENDIF.
  SELECT SINGLE domname FROM dd01l INTO @DATA(lv_dom2) WHERE domname = 'ZBAS_DO_ACTN'.
  IF sy-subrc <> 0.
    ls_missing-object = 'ZBAS_DO_ACTN'. ls_missing-kind = 'Domain'.
    APPEND ls_missing TO lt_missing.
  ENDIF.

  " Data Elements
  SELECT SINGLE rollname FROM dd04l INTO @DATA(lv_de1) WHERE rollname = 'ZBAS_DE_MODL'.
  IF sy-subrc <> 0.
    ls_missing-object = 'ZBAS_DE_MODL'. ls_missing-kind = 'Data Element'.
    APPEND ls_missing TO lt_missing.
  ENDIF.
  SELECT SINGLE rollname FROM dd04l INTO @DATA(lv_de2) WHERE rollname = 'ZBAS_DE_ACTN'.
  IF sy-subrc <> 0.
    ls_missing-object = 'ZBAS_DE_ACTN'. ls_missing-kind = 'Data Element'.
    APPEND ls_missing TO lt_missing.
  ENDIF.

  " Authorization Fields
  SELECT SINGLE fieldname FROM authx INTO @DATA(lv_af1) WHERE fieldname = 'ZBAS_MODL'.
  IF sy-subrc <> 0.
    ls_missing-object = 'ZBAS_MODL'. ls_missing-kind = 'Auth Field'.
    APPEND ls_missing TO lt_missing.
  ENDIF.
  SELECT SINGLE fieldname FROM authx INTO @DATA(lv_af2) WHERE fieldname = 'ZBAS_ACTN'.
  IF sy-subrc <> 0.
    ls_missing-object = 'ZBAS_ACTN'. ls_missing-kind = 'Auth Field'.
    APPEND ls_missing TO lt_missing.
  ENDIF.

  " Authorization Object: dummy check - sy-subrc = 16 means object unknown
  AUTHORITY-CHECK OBJECT 'Z_BASTOOL'
    ID 'ZBAS_MODL' FIELD 'XX'
    ID 'ZBAS_ACTN' FIELD 'XX'.
  IF sy-subrc = 16.
    ls_missing-object = 'Z_BASTOOL'. ls_missing-kind = 'Auth Object'.
    APPEND ls_missing TO lt_missing.
  ENDIF.

  " Audit log table - only required on PRD (dynamic CREATE DATA)
  IF gv_is_prd = abap_true.
    TRY.
        DATA lr_probe TYPE REF TO data.
        CREATE DATA lr_probe TYPE ('ZBAS_TOOL_LOG').
      CATCH cx_root.
        ls_missing-object = 'ZBAS_TOOL_LOG'. ls_missing-kind = 'Table (PRD)'.
        APPEND ls_missing TO lt_missing.
    ENDTRY.
  ENDIF.

  lv_cnt = lines( lt_missing ).
  IF lv_cnt = 0.
    RETURN.
  ENDIF.

  " Display missing objects + Continue / Abort confirm
  TYPES: ty_text_line TYPE c LENGTH 80.
  DATA: lt_text TYPE TABLE OF ty_text_line,
        lv_line TYPE ty_text_line,
        lv_ans  TYPE c LENGTH 1.
  lv_line = 'The following DDIC objects are missing:'.
  APPEND lv_line TO lt_text.
  LOOP AT lt_missing INTO ls_missing.
    lv_line = |  { ls_missing-kind } - { ls_missing-object }|.
    APPEND lv_line TO lt_text.
  ENDLOOP.

  CALL FUNCTION 'POPUP_WITH_TABLE_DISPLAY'
    EXPORTING
      endpos_col   = 80
      endpos_row   = 15
      startpos_col = 5
      startpos_row = 5
      titletext    = 'Z_BASIS_TOOLBOX - Missing DDIC Objects'
    TABLES
      valuetab     = lt_text
    EXCEPTIONS
      break_off    = 1
      OTHERS       = 2.

  CALL FUNCTION 'POPUP_TO_CONFIRM'
    EXPORTING
      titlebar              = 'Missing DDIC Objects'
      text_question         = |{ lv_cnt } required object(s) missing. Continue anyway?|
      text_button_1         = 'Continue'
      text_button_2         = 'Abort'
      default_button        = '2'
      display_cancel_button = abap_false
    IMPORTING
      answer                = lv_ans
    EXCEPTIONS
      text_not_found        = 1
      OTHERS                = 2.

  IF lv_ans = '2' OR lv_ans = 'A'.
    LEAVE PROGRAM.
  ENDIF.
ENDFORM.
