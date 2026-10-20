*&---------------------------------------------------------------------*
*& Report Z_DATA_TO_OAUTH_REST
*&---------------------------------------------------------------------*
REPORT z_data_to_oauth_rest.

CONSTANTS:
  gc_max_payload_bytes TYPE i VALUE 1048576,
  gc_token_skew_secs   TYPE i VALUE 30,
  gc_max_json_depth    TYPE i VALUE 64.

PARAMETERS:
  p_api_dest   TYPE rfcdest DEFAULT 'Z_API_EVENTS_OUTBOUND' OBLIGATORY,
  p_token_dest TYPE rfcdest DEFAULT 'Z_OAUTH_TOKEN_SERVER' OBLIGATORY.

TYPES ty_string_tab TYPE STANDARD TABLE OF string WITH DEFAULT KEY.

TYPES:
  BEGIN OF ty_metadata,
    SOURCE_TEXT TYPE string,
    PILOT       TYPE string,
  END OF ty_metadata.

TYPES:
  BEGIN OF ty_event,
    CARRID   TYPE c LENGTH 3,
    CONNID   TYPE n LENGTH 4,
    CITYFROM TYPE string,
    AMOUNT   TYPE p LENGTH 8 DECIMALS 2,
    METADATA TYPE ty_metadata,
    TAGS     TYPE ty_string_tab,
  END OF ty_event.

TYPES ty_event_tab TYPE STANDARD TABLE OF ty_event WITH DEFAULT KEY.

CLASS lcl_rest_handler DEFINITION.
  PUBLIC SECTION.
    CONSTANTS:
      c_msg_output_error  TYPE symsgno VALUE '023',
      c_msg_output_status TYPE symsgno VALUE '024',
      c_msg_output_body   TYPE symsgno VALUE '025'.

    TYPES:
      BEGIN OF ty_api_result,
        status_code TYPE i,
        body        TYPE string,
        error_msg   TYPE string,
        retry_after TYPE string,
      END OF ty_api_result.

    CLASS-METHODS send_data
      IMPORTING
        io_data              TYPE REF TO data
        iv_api_destination   TYPE rfcdest
        iv_token_destination TYPE rfcdest
      EXPORTING
        es_result            TYPE ty_api_result.

    CLASS-METHODS message_text
      IMPORTING
        iv_msgno TYPE symsgno
        iv_v1    TYPE symsgv OPTIONAL
        iv_v2    TYPE symsgv OPTIONAL
        iv_v3    TYPE symsgv OPTIONAL
        iv_v4    TYPE symsgv OPTIONAL
      RETURNING
        VALUE(rv_text) TYPE string.

    CLASS-METHODS serialize_to_json
      IMPORTING
        io_data  TYPE REF TO data
        iv_depth TYPE i
      EXPORTING
        ev_json  TYPE string
        ev_error TYPE string.

  PRIVATE SECTION.
    TYPES:
      BEGIN OF ty_token_cache,
        destination TYPE rfcdest,
        token       TYPE string,
        valid_until TYPE tzntstmpl,
      END OF ty_token_cache.

    CLASS-DATA gt_token_cache TYPE STANDARD TABLE OF ty_token_cache
                              WITH DEFAULT KEY.

    CONSTANTS:
      c_msg_http_client    TYPE symsgno VALUE '001',
      c_msg_http_transport TYPE symsgno VALUE '002',
      c_msg_source_ref     TYPE symsgno VALUE '003',
      c_msg_source_read    TYPE symsgno VALUE '004',
      c_msg_json_depth     TYPE symsgno VALUE '005',
      c_msg_component      TYPE symsgno VALUE '006',
      c_msg_table          TYPE symsgno VALUE '007',
      c_msg_reference      TYPE symsgno VALUE '008',
      c_msg_json_type      TYPE symsgno VALUE '009',
      c_msg_json_control   TYPE symsgno VALUE '010',
      c_msg_json_number    TYPE symsgno VALUE '011',
      c_msg_json_exception TYPE symsgno VALUE '012',
      c_msg_utf8           TYPE symsgno VALUE '013',
      c_msg_payload_size   TYPE symsgno VALUE '014',
      c_msg_token_field    TYPE symsgno VALUE '015',
      c_msg_token_type     TYPE symsgno VALUE '016',
      c_msg_token_empty    TYPE symsgno VALUE '017',
      c_msg_token_char     TYPE symsgno VALUE '018',
      c_msg_token_status   TYPE symsgno VALUE '019',
      c_msg_token_expiry   TYPE symsgno VALUE '020',
      c_msg_api_status     TYPE symsgno VALUE '021',
      c_msg_retry_after    TYPE symsgno VALUE '022',
      c_json_hex_digits    TYPE string VALUE '0123456789ABCDEF',
      c_json_ascii_printable TYPE string VALUE ' !"#$%&''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'.

    CLASS-METHODS create_http_client
      IMPORTING
        iv_destination TYPE rfcdest
      RETURNING
        VALUE(ro_client) TYPE REF TO if_http_client.

    CLASS-METHODS post_destination
      IMPORTING
        iv_destination   TYPE rfcdest
        iv_content_type  TYPE string
        iv_authorization TYPE string
        iv_body          TYPE xstring
      EXPORTING
        ev_status        TYPE i
        ev_reason        TYPE string
        ev_body          TYPE string
        ev_retry_after   TYPE string
        ev_error         TYPE string.

    CLASS-METHODS quote_json_string
      IMPORTING
        iv_value TYPE string
      EXPORTING
        ev_json  TYPE string
        ev_error TYPE string.

    CLASS-METHODS is_json_number
      IMPORTING
        iv_value TYPE string
      RETURNING
        VALUE(rv_valid) TYPE abap_bool.

    CLASS-METHODS get_access_token
      IMPORTING
        iv_token_destination TYPE rfcdest
      EXPORTING
        ev_token             TYPE string
        ev_error             TYPE string.

    CLASS-METHODS parse_token_response
      IMPORTING
        iv_json TYPE string
      EXPORTING
        ev_token      TYPE string
        ev_token_type TYPE string
        ev_expires_in TYPE i
        ev_error      TYPE string.

    CLASS-METHODS extract_json_string
      IMPORTING
        iv_json TYPE string
        iv_key  TYPE string
      EXPORTING
        ev_value TYPE string
        ev_error TYPE string.

    CLASS-METHODS extract_json_integer
      IMPORTING
        iv_json TYPE string
        iv_key  TYPE string
      EXPORTING
        ev_value TYPE i
        ev_error TYPE string.

    CLASS-METHODS skip_json_whitespace
      IMPORTING
        iv_json TYPE string
      CHANGING
        cv_position TYPE i.

    CLASS-METHODS decode_json_token_escape
      IMPORTING
        iv_codepoint TYPE i
        iv_key       TYPE string
      EXPORTING
        ev_char      TYPE c LENGTH 1
        ev_error     TYPE string.

    CLASS-METHODS add_seconds_to_timestamp
      IMPORTING
        iv_timestamp TYPE tzntstmpl
        iv_seconds   TYPE i
      EXPORTING
        ev_timestamp TYPE tzntstmpl
        ev_error     TYPE string.
ENDCLASS.

CLASS lcl_rest_handler IMPLEMENTATION.
  METHOD message_text.
    MESSAGE ID 'Z_OAUTH_REST' TYPE 'S' NUMBER iv_msgno
      WITH iv_v1 iv_v2 iv_v3 iv_v4
      INTO rv_text.
  ENDMETHOD.

  METHOD create_http_client.
    CLEAR ro_client.
    CALL METHOD cl_http_client=>create_by_destination
      EXPORTING
        destination = iv_destination
      IMPORTING
        client      = ro_client
      EXCEPTIONS
        OTHERS      = 1.
    IF sy-subrc <> 0.
      CLEAR ro_client.
    ENDIF.
  ENDMETHOD.

  METHOD post_destination.
    DATA lo_client TYPE REF TO if_http_client.
    DATA lo_request TYPE REF TO if_http_request.
    DATA lo_response TYPE REF TO if_http_response.
    DATA lv_subrc TYPE i.
    DATA lv_subrc_text TYPE c LENGTH 10.

    CLEAR: ev_status, ev_reason, ev_body, ev_retry_after, ev_error.

    CALL METHOD lcl_rest_handler=>create_http_client
      EXPORTING
        iv_destination = iv_destination
      RECEIVING
        ro_client      = lo_client.

    IF lo_client IS NOT BOUND.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_http_client
          iv_v1    = iv_destination
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    lo_request = lo_client->request.
    CALL METHOD lo_request->set_method
      EXPORTING
        method = if_http_request=>co_request_method_post.
    CALL METHOD lo_request->set_header_field
      EXPORTING
        name  = 'Content-Type'
        value = iv_content_type.
    CALL METHOD lo_request->set_header_field
      EXPORTING
        name  = 'Accept'
        value = 'application/json'.

    IF iv_authorization IS NOT INITIAL.
      CALL METHOD lo_request->set_header_field
        EXPORTING
          name  = 'Authorization'
          value = iv_authorization.
    ENDIF.

    CALL METHOD lo_request->set_data
      EXPORTING
        data = iv_body.

    CALL METHOD lo_client->send
      EXCEPTIONS
        OTHERS = 1.
    lv_subrc = sy-subrc.

    IF lv_subrc = 0.
      CALL METHOD lo_client->receive
        EXCEPTIONS
          OTHERS = 1.
      lv_subrc = sy-subrc.
    ENDIF.

    IF lv_subrc <> 0.
      WRITE lv_subrc TO lv_subrc_text.
      CONDENSE lv_subrc_text NO-GAPS.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_http_transport
          iv_v1    = lv_subrc_text
        RECEIVING
          rv_text  = ev_error.
      CALL METHOD lo_client->close
        EXCEPTIONS
          OTHERS = 1.
      RETURN.
    ENDIF.

    lo_response = lo_client->response.
    CALL METHOD lo_response->get_status
      IMPORTING
        code   = ev_status
        reason = ev_reason.
    CALL METHOD lo_response->get_cdata
      RECEIVING
        data = ev_body.
    CALL METHOD lo_response->get_header_field
      EXPORTING
        name  = 'Retry-After'
      RECEIVING
        value = ev_retry_after.

    CALL METHOD lo_client->close
      EXCEPTIONS
        OTHERS = 1.
  ENDMETHOD.

  METHOD send_data.
    DATA lv_json TYPE string.
    DATA lv_utf8_body TYPE xstring.
    DATA lv_body_size TYPE i.
    DATA lv_token TYPE string.
    DATA lv_authorization TYPE string.
    DATA lv_error TYPE string.
    DATA lv_status_text TYPE c LENGTH 10.
    DATA lv_retry_message TYPE string.
    DATA lo_exception TYPE REF TO cx_root.

    CLEAR es_result.

    CALL METHOD lcl_rest_handler=>serialize_to_json
      EXPORTING
        io_data  = io_data
        iv_depth = 0
      IMPORTING
        ev_json  = lv_json
        ev_error = lv_error.
    IF lv_error IS NOT INITIAL.
      es_result-error_msg = lv_error.
      RETURN.
    ENDIF.

    TRY.
        lv_utf8_body = cl_abap_codepage=>convert_to(
                         source   = lv_json
                         codepage = 'UTF-8' ).
      CATCH cx_root INTO lo_exception.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_utf8
            iv_v1    = lo_exception->get_text( )
          RECEIVING
            rv_text  = es_result-error_msg.
        RETURN.
    ENDTRY.

    lv_body_size = xstrlen( lv_utf8_body ).
    IF lv_body_size > gc_max_payload_bytes.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_payload_size
        RECEIVING
          rv_text  = es_result-error_msg.
      RETURN.
    ENDIF.

    CALL METHOD lcl_rest_handler=>get_access_token
      EXPORTING
        iv_token_destination = iv_token_destination
      IMPORTING
        ev_token             = lv_token
        ev_error             = lv_error.
    IF lv_error IS NOT INITIAL OR lv_token IS INITIAL.
      IF lv_error IS INITIAL.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_token_empty
          RECEIVING
            rv_text = lv_error.
      ENDIF.
      es_result-error_msg = lv_error.
      RETURN.
    ENDIF.

    CONCATENATE 'Bearer' lv_token
           INTO lv_authorization SEPARATED BY space.
    CALL METHOD lcl_rest_handler=>post_destination
      EXPORTING
        iv_destination   = iv_api_destination
        iv_content_type  = 'application/json; charset=utf-8'
        iv_authorization = lv_authorization
        iv_body          = lv_utf8_body
      IMPORTING
        ev_status        = es_result-status_code
        ev_reason        = lv_error
        ev_body          = es_result-body
        ev_retry_after   = es_result-retry_after
        ev_error         = es_result-error_msg.

    IF es_result-error_msg IS NOT INITIAL.
      RETURN.
    ENDIF.

    IF es_result-status_code = 401.
      DELETE gt_token_cache WHERE destination = iv_token_destination.
    ENDIF.

    IF es_result-status_code <> 201.
      WRITE es_result-status_code TO lv_status_text.
      CONDENSE lv_status_text NO-GAPS.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_api_status
          iv_v1    = lv_status_text
          iv_v2    = lv_error
        RECEIVING
          rv_text  = es_result-error_msg.
      IF es_result-status_code = 429
         AND es_result-retry_after IS NOT INITIAL.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_retry_after
            iv_v1    = es_result-retry_after
          RECEIVING
            rv_text  = lv_retry_message.
        CONCATENATE es_result-error_msg lv_retry_message
               INTO es_result-error_msg SEPARATED BY space.
      ENDIF.
    ENDIF.
  ENDMETHOD.

  METHOD serialize_to_json.
    DATA lo_type_desc TYPE REF TO cl_abap_typedescr.
    DATA lo_struct_desc TYPE REF TO cl_abap_structdescr.
    DATA lt_components TYPE cl_abap_structdescr=>component_table.
    DATA ls_component TYPE abap_componentdescr.
    DATA lr_child TYPE REF TO data.
    DATA lv_name TYPE string.
    DATA lv_quoted_name TYPE string.
    DATA lv_text TYPE string.
    DATA lv_number TYPE string.
    DATA lv_iso_date TYPE string.
    DATA lv_iso_time TYPE string.
    DATA lv_sub_json TYPE string.
    DATA lv_first TYPE abap_bool.
    DATA lv_next_depth TYPE i.
    DATA lv_valid_number TYPE abap_bool.
    DATA lv_message_arg TYPE symsgv.
    DATA lo_exception TYPE REF TO cx_root.

    FIELD-SYMBOLS:
      <fs_data> TYPE any,
      <fs_table> TYPE ANY TABLE,
      <fs_row> TYPE any,
      <fs_component> TYPE any,
      <fs_data_ref> TYPE REF TO data,
      <fs_referent> TYPE any.

    CLEAR: ev_json, ev_error.

    IF iv_depth > gc_max_json_depth.
      WRITE gc_max_json_depth TO lv_message_arg.
      CONDENSE lv_message_arg NO-GAPS.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_json_depth
          iv_v1    = lv_message_arg
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.
    IF io_data IS INITIAL.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_source_ref
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    TRY.
        ASSIGN io_data->* TO <fs_data>.
        IF sy-subrc <> 0.
          CALL METHOD lcl_rest_handler=>message_text
            EXPORTING
              iv_msgno = c_msg_source_read
            RECEIVING
              rv_text  = ev_error.
          RETURN.
        ENDIF.
        lo_type_desc = cl_abap_typedescr=>describe_by_data( <fs_data> ).

        CASE lo_type_desc->kind.
          WHEN cl_abap_typedescr=>kind_struct.
            lo_struct_desc ?= lo_type_desc.
            lt_components = lo_struct_desc->get_components( ).
            ev_json = '{'.
            lv_first = 'X'.

            LOOP AT lt_components INTO ls_component.
              IF lv_first IS INITIAL.
                CONCATENATE ev_json ',' INTO ev_json.
              ENDIF.
              CLEAR lv_first.

              lv_name = ls_component-name.
              TRANSLATE lv_name TO LOWER CASE.
              CALL METHOD lcl_rest_handler=>quote_json_string
                EXPORTING
                  iv_value = lv_name
                IMPORTING
                  ev_json  = lv_quoted_name
                  ev_error = ev_error.
              IF ev_error IS NOT INITIAL.
                RETURN.
              ENDIF.
              CONCATENATE ev_json lv_quoted_name ':' INTO ev_json.

              ASSIGN COMPONENT ls_component-name
                OF STRUCTURE <fs_data> TO <fs_component>.
              IF sy-subrc <> 0.
                CALL METHOD lcl_rest_handler=>message_text
                  EXPORTING
                    iv_msgno = c_msg_component
                    iv_v1    = ls_component-name
                  RECEIVING
                    rv_text  = ev_error.
                RETURN.
              ENDIF.

              GET REFERENCE OF <fs_component> INTO lr_child.
              lv_next_depth = iv_depth + 1.
              CALL METHOD lcl_rest_handler=>serialize_to_json
                EXPORTING
                  io_data  = lr_child
                  iv_depth = lv_next_depth
                IMPORTING
                  ev_json  = lv_sub_json
                  ev_error = ev_error.
              IF ev_error IS NOT INITIAL.
                RETURN.
              ENDIF.
              CONCATENATE ev_json lv_sub_json INTO ev_json RESPECTING BLANKS.
            ENDLOOP.
            CONCATENATE ev_json '}' INTO ev_json.

          WHEN cl_abap_typedescr=>kind_table.
            ASSIGN <fs_data> TO <fs_table>.
            IF sy-subrc <> 0.
              CALL METHOD lcl_rest_handler=>message_text
                EXPORTING
                  iv_msgno = c_msg_table
                RECEIVING
                  rv_text  = ev_error.
              RETURN.
            ENDIF.

            ev_json = '['.
            lv_first = 'X'.
            LOOP AT <fs_table> ASSIGNING <fs_row>.
              IF lv_first IS INITIAL.
                CONCATENATE ev_json ',' INTO ev_json.
              ENDIF.
              CLEAR lv_first.

              GET REFERENCE OF <fs_row> INTO lr_child.
              lv_next_depth = iv_depth + 1.
              CALL METHOD lcl_rest_handler=>serialize_to_json
                EXPORTING
                  io_data  = lr_child
                  iv_depth = lv_next_depth
                IMPORTING
                  ev_json  = lv_sub_json
                  ev_error = ev_error.
              IF ev_error IS NOT INITIAL.
                RETURN.
              ENDIF.
              CONCATENATE ev_json lv_sub_json INTO ev_json RESPECTING BLANKS.
            ENDLOOP.
            CONCATENATE ev_json ']' INTO ev_json.

          WHEN cl_abap_typedescr=>kind_ref.
            ASSIGN <fs_data> TO <fs_data_ref>.
            IF sy-subrc <> 0.
              CALL METHOD lcl_rest_handler=>message_text
                EXPORTING
                  iv_msgno = c_msg_reference
                RECEIVING
                  rv_text  = ev_error.
              RETURN.
            ENDIF.
            IF <fs_data_ref> IS INITIAL.
              ev_json = 'null'.
            ELSE.
              ASSIGN <fs_data_ref>->* TO <fs_referent>.
              IF sy-subrc <> 0.
                CALL METHOD lcl_rest_handler=>message_text
                  EXPORTING
                    iv_msgno = c_msg_source_read
                  RECEIVING
                    rv_text  = ev_error.
                RETURN.
              ENDIF.
              GET REFERENCE OF <fs_referent> INTO lr_child.
              lv_next_depth = iv_depth + 1.
              CALL METHOD lcl_rest_handler=>serialize_to_json
                EXPORTING
                  io_data  = lr_child
                  iv_depth = lv_next_depth
                IMPORTING
                  ev_json  = ev_json
                  ev_error = ev_error.
            ENDIF.

          WHEN cl_abap_typedescr=>kind_elem.
            CASE lo_type_desc->type_kind.
              WHEN 'C' OR 'N' OR 'g'.
                lv_text = <fs_data>.
                IF lo_type_desc->type_kind = 'C'.
                  SHIFT lv_text RIGHT DELETING TRAILING space.
                ENDIF.
                CALL METHOD lcl_rest_handler=>quote_json_string
                  EXPORTING
                    iv_value = lv_text
                  IMPORTING
                    ev_json  = ev_json
                    ev_error = ev_error.

              WHEN 'D'.
                lv_text = <fs_data>.
                IF lv_text = '00000000'.
                  ev_json = 'null'.
                ELSE.
                  CONCATENATE lv_text+0(4) '-'
                              lv_text+4(2) '-'
                              lv_text+6(2)
                         INTO lv_iso_date.
                  CALL METHOD lcl_rest_handler=>quote_json_string
                    EXPORTING
                      iv_value = lv_iso_date
                    IMPORTING
                      ev_json  = ev_json
                      ev_error = ev_error.
                ENDIF.

              WHEN 'T'.
                lv_text = <fs_data>.
                CONCATENATE lv_text+0(2) ':'
                            lv_text+2(2) ':'
                            lv_text+4(2)
                       INTO lv_iso_time.
                CALL METHOD lcl_rest_handler=>quote_json_string
                  EXPORTING
                    iv_value = lv_iso_time
                  IMPORTING
                    ev_json  = ev_json
                    ev_error = ev_error.

              WHEN 'I' OR 'b' OR 's' OR '8' OR 'P' OR 'F' OR 'a' OR 'e'.
                WRITE <fs_data> TO lv_number NO-GROUPING.
                CONDENSE lv_number NO-GAPS.
                IF sy-dcpfm = 'X' OR sy-dcpfm = 'Y'.
                  REPLACE ALL OCCURRENCES OF ',' IN lv_number WITH '.'.
                ENDIF.
                CALL METHOD lcl_rest_handler=>is_json_number
                  EXPORTING
                    iv_value = lv_number
                  RECEIVING
                    rv_valid = lv_valid_number.
                IF lv_valid_number IS INITIAL.
                  CALL METHOD lcl_rest_handler=>message_text
                    EXPORTING
                      iv_msgno = c_msg_json_number
                    RECEIVING
                      rv_text  = ev_error.
                  RETURN.
                ENDIF.
                ev_json = lv_number.

              WHEN 'X' OR 'y'.
                WRITE <fs_data> TO lv_text.
                CONDENSE lv_text NO-GAPS.
                CALL METHOD lcl_rest_handler=>quote_json_string
                  EXPORTING
                    iv_value = lv_text
                  IMPORTING
                    ev_json  = ev_json
                    ev_error = ev_error.

              WHEN OTHERS.
                CALL METHOD lcl_rest_handler=>message_text
                  EXPORTING
                    iv_msgno = c_msg_json_type
                    iv_v1    = lo_type_desc->type_kind
                  RECEIVING
                    rv_text  = ev_error.
            ENDCASE.

          WHEN OTHERS.
            CALL METHOD lcl_rest_handler=>message_text
              EXPORTING
                iv_msgno = c_msg_json_type
                iv_v1    = lo_type_desc->kind
              RECEIVING
                rv_text  = ev_error.
        ENDCASE.

      CATCH cx_root INTO lo_exception.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_json_exception
            iv_v1    = lo_exception->get_text( )
          RECEIVING
            rv_text  = ev_error.
    ENDTRY.
  ENDMETHOD.

  METHOD quote_json_string.
    DATA lv_length TYPE i.
    DATA lv_position TYPE i.
    DATA lv_char TYPE c LENGTH 1.
    DATA lv_escaped TYPE string.
    DATA lv_crlf TYPE c LENGTH 2.
    DATA lv_cr TYPE c LENGTH 1.

    CLEAR: ev_json, ev_error.
    lv_escaped = iv_value.
    lv_crlf = cl_abap_char_utilities=>cr_lf.
    lv_cr = lv_crlf+0(1).
    lv_length = strlen( iv_value ).

    DO lv_length TIMES.
      lv_position = sy-index - 1.
      lv_char = iv_value+lv_position(1).
      IF lv_char < space
         AND lv_char <> lv_cr
         AND lv_char <> cl_abap_char_utilities=>newline
         AND lv_char <> cl_abap_char_utilities=>horizontal_tab.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_json_control
          RECEIVING
            rv_text  = ev_error.
        RETURN.
      ENDIF.
    ENDDO.

    REPLACE ALL OCCURRENCES OF '\' IN lv_escaped WITH '\\'.
    REPLACE ALL OCCURRENCES OF '"' IN lv_escaped WITH '\"'.
    REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>cr_lf
      IN lv_escaped WITH '\r\n'.
    REPLACE ALL OCCURRENCES OF lv_cr IN lv_escaped WITH '\r'.
    REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>newline
      IN lv_escaped WITH '\n'.
    REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>horizontal_tab
      IN lv_escaped WITH '\t'.
    CONCATENATE '"' lv_escaped '"' INTO ev_json RESPECTING BLANKS.
  ENDMETHOD.

  METHOD is_json_number.
    DATA lv_length TYPE i.
    DATA lv_position TYPE i.
    DATA lv_digits TYPE i.
    DATA lv_char TYPE c LENGTH 1.

    rv_valid = space.
    lv_length = strlen( iv_value ).
    IF lv_length = 0.
      RETURN.
    ENDIF.

    lv_position = 0.
    lv_char = iv_value+lv_position(1).
    IF lv_char = '-'.
      ADD 1 TO lv_position.
      IF lv_position >= lv_length.
        RETURN.
      ENDIF.
    ENDIF.

    lv_char = iv_value+lv_position(1).
    IF lv_char = '0'.
      ADD 1 TO lv_position.
      IF lv_position < lv_length.
        lv_char = iv_value+lv_position(1).
        IF lv_char >= '0' AND lv_char <= '9'.
          RETURN.
        ENDIF.
      ENDIF.
    ELSEIF lv_char >= '1' AND lv_char <= '9'.
      WHILE lv_position < lv_length.
        lv_char = iv_value+lv_position(1).
        IF lv_char < '0' OR lv_char > '9'.
          EXIT.
        ENDIF.
        ADD 1 TO lv_position.
      ENDWHILE.
    ELSE.
      RETURN.
    ENDIF.

    IF lv_position < lv_length.
      lv_char = iv_value+lv_position(1).
      IF lv_char = '.'.
        ADD 1 TO lv_position.
        CLEAR lv_digits.
        WHILE lv_position < lv_length.
          lv_char = iv_value+lv_position(1).
          IF lv_char < '0' OR lv_char > '9'.
            EXIT.
          ENDIF.
          ADD 1 TO lv_digits.
          ADD 1 TO lv_position.
        ENDWHILE.
        IF lv_digits = 0.
          RETURN.
        ENDIF.
      ENDIF.
    ENDIF.

    IF lv_position < lv_length.
      lv_char = iv_value+lv_position(1).
      IF lv_char = 'e' OR lv_char = 'E'.
        ADD 1 TO lv_position.
        IF lv_position < lv_length.
          lv_char = iv_value+lv_position(1).
          IF lv_char = '+' OR lv_char = '-'.
            ADD 1 TO lv_position.
          ENDIF.
        ENDIF.
        CLEAR lv_digits.
        WHILE lv_position < lv_length.
          lv_char = iv_value+lv_position(1).
          IF lv_char < '0' OR lv_char > '9'.
            EXIT.
          ENDIF.
          ADD 1 TO lv_digits.
          ADD 1 TO lv_position.
        ENDWHILE.
        IF lv_digits = 0.
          RETURN.
        ENDIF.
      ENDIF.
    ENDIF.

    IF lv_position = lv_length.
      rv_valid = 'X'.
    ENDIF.
  ENDMETHOD.

  METHOD get_access_token.
    DATA ls_cache TYPE ty_token_cache.
    DATA lv_now TYPE tzntstmpl.
    DATA lv_cache_seconds TYPE i.
    DATA lv_status TYPE i.
    DATA lv_reason TYPE string.
    DATA lv_body TYPE string.
    DATA lv_retry_after TYPE string.
    DATA lv_form TYPE string.
    DATA lv_form_bytes TYPE xstring.
    DATA lv_token_type TYPE string.
    DATA lv_expires_in TYPE i.
    DATA lv_parse_error TYPE string.
    DATA lv_expiry_error TYPE string.
    DATA lv_status_text TYPE c LENGTH 10.
    DATA lo_exception TYPE REF TO cx_root.
    FIELD-SYMBOLS <ls_cache> TYPE ty_token_cache.

    CLEAR: ev_token, ev_error.
    GET TIME STAMP FIELD lv_now.

    READ TABLE gt_token_cache ASSIGNING <ls_cache>
      WITH KEY destination = iv_token_destination.
    IF sy-subrc = 0.
      IF <ls_cache>-token IS NOT INITIAL
         AND lv_now < <ls_cache>-valid_until.
        ev_token = <ls_cache>-token.
        RETURN.
      ENDIF.
      DELETE gt_token_cache WHERE destination = iv_token_destination.
    ENDIF.

    lv_form = 'grant_type=client_credentials'.
    TRY.
        lv_form_bytes = cl_abap_codepage=>convert_to(
                          source   = lv_form
                          codepage = 'UTF-8' ).
      CATCH cx_root INTO lo_exception.
        ev_error = lo_exception->get_text( ).
        RETURN.
    ENDTRY.

    CALL METHOD lcl_rest_handler=>post_destination
      EXPORTING
        iv_destination   = iv_token_destination
        iv_content_type  = 'application/x-www-form-urlencoded; charset=utf-8'
        iv_authorization = space
        iv_body          = lv_form_bytes
      IMPORTING
        ev_status        = lv_status
        ev_reason        = lv_reason
        ev_body          = lv_body
        ev_retry_after   = lv_retry_after
        ev_error         = ev_error.
    IF ev_error IS NOT INITIAL.
      RETURN.
    ENDIF.

    IF lv_status <> 200.
      WRITE lv_status TO lv_status_text.
      CONDENSE lv_status_text NO-GAPS.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_status
          iv_v1    = lv_status_text
          iv_v2    = lv_reason
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    CALL METHOD lcl_rest_handler=>parse_token_response
      EXPORTING
        iv_json = lv_body
      IMPORTING
        ev_token      = ev_token
        ev_token_type = lv_token_type
        ev_expires_in = lv_expires_in
        ev_error      = lv_parse_error.
    IF lv_parse_error IS NOT INITIAL.
      ev_error = lv_parse_error.
      CLEAR ev_token.
      RETURN.
    ENDIF.

    GET TIME STAMP FIELD lv_now.
    lv_cache_seconds = lv_expires_in - gc_token_skew_secs.
    IF lv_cache_seconds < 0.
      CLEAR lv_cache_seconds.
    ENDIF.

    CLEAR ls_cache.
    ls_cache-destination = iv_token_destination.
    ls_cache-token = ev_token.
    CALL METHOD lcl_rest_handler=>add_seconds_to_timestamp
      EXPORTING
        iv_timestamp = lv_now
        iv_seconds   = lv_cache_seconds
      IMPORTING
        ev_timestamp = ls_cache-valid_until
        ev_error     = lv_expiry_error.
    IF lv_expiry_error IS NOT INITIAL.
      ev_error = lv_expiry_error.
      CLEAR ev_token.
      RETURN.
    ENDIF.

    APPEND ls_cache TO gt_token_cache.
  ENDMETHOD.

  METHOD parse_token_response.
    DATA lv_type_upper TYPE string.
    DATA lv_token_length TYPE i.
    DATA lv_padding_offset TYPE i.
    DATA lv_padding_length TYPE i.
    DATA lv_padding TYPE string.

    CLEAR: ev_token, ev_token_type, ev_expires_in, ev_error.

    CALL METHOD lcl_rest_handler=>extract_json_string
      EXPORTING
        iv_json  = iv_json
        iv_key   = 'access_token'
      IMPORTING
        ev_value = ev_token
        ev_error = ev_error.
    IF ev_error IS NOT INITIAL.
      RETURN.
    ENDIF.

    CALL METHOD lcl_rest_handler=>extract_json_string
      EXPORTING
        iv_json  = iv_json
        iv_key   = 'token_type'
      IMPORTING
        ev_value = ev_token_type
        ev_error = ev_error.
    IF ev_error IS NOT INITIAL.
      RETURN.
    ENDIF.

    CALL METHOD lcl_rest_handler=>extract_json_integer
      EXPORTING
        iv_json  = iv_json
        iv_key   = 'expires_in'
      IMPORTING
        ev_value = ev_expires_in
        ev_error = ev_error.
    IF ev_error IS NOT INITIAL.
      RETURN.
    ENDIF.

    lv_type_upper = ev_token_type.
    TRANSLATE lv_type_upper TO UPPER CASE.
    IF lv_type_upper <> 'BEARER'.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_type
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    IF ev_token IS INITIAL OR ev_expires_in <= 0.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_empty
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    IF ev_token CN 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/='.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_char
        RECEIVING
          rv_text  = ev_error.
      CLEAR ev_token.
      RETURN.
    ENDIF.

    " RFC 6750 allows Base64 padding only at the end of the Bearer token.
    FIND FIRST OCCURRENCE OF '=' IN ev_token MATCH OFFSET lv_padding_offset.
    IF sy-subrc = 0.
      IF lv_padding_offset = 0.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_token_char
          RECEIVING
            rv_text  = ev_error.
        CLEAR ev_token.
        RETURN.
      ENDIF.

      lv_token_length = strlen( ev_token ).
      lv_padding_length = lv_token_length - lv_padding_offset.
      lv_padding = ev_token+lv_padding_offset(lv_padding_length).
      IF lv_padding CN '='.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_token_char
          RECEIVING
            rv_text  = ev_error.
        CLEAR ev_token.
        RETURN.
      ENDIF.
    ENDIF.
  ENDMETHOD.

  METHOD extract_json_string.
    DATA lv_search TYPE string.
    DATA lv_length TYPE i.
    DATA lv_position TYPE i.
    DATA lv_char TYPE c LENGTH 1.
    DATA lv_escape TYPE c LENGTH 1.
    DATA lv_hex_value TYPE c LENGTH 4.
    DATA lv_hex_char TYPE c LENGTH 1.
    DATA lv_hex_offset TYPE i.
    DATA lv_hex_digit_value TYPE i.
    DATA lv_unicode_value TYPE i.
    DATA lv_decode_escape TYPE abap_bool.
    DATA lv_closed TYPE abap_bool.

    CLEAR: ev_value, ev_error.
    CONCATENATE '"' iv_key '"' INTO lv_search.
    FIND FIRST OCCURRENCE OF lv_search IN iv_json MATCH OFFSET lv_position.
    IF sy-subrc <> 0.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    lv_length = strlen( iv_json ).
    lv_position = lv_position + strlen( lv_search ).
    CALL METHOD lcl_rest_handler=>skip_json_whitespace
      EXPORTING
        iv_json = iv_json
      CHANGING
        cv_position = lv_position.
    IF lv_position >= lv_length.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    lv_char = iv_json+lv_position(1).
    IF lv_char <> ':'.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.
    ADD 1 TO lv_position.

    CALL METHOD lcl_rest_handler=>skip_json_whitespace
      EXPORTING
        iv_json = iv_json
      CHANGING
        cv_position = lv_position.
    IF lv_position >= lv_length.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    lv_char = iv_json+lv_position(1).
    IF lv_char <> '"'.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.
    ADD 1 TO lv_position.
    CLEAR lv_closed.

    WHILE lv_position < lv_length.
      lv_char = iv_json+lv_position(1).
      ADD 1 TO lv_position.

      IF lv_char = '"'.
        lv_closed = 'X'.
        EXIT.
      ELSEIF lv_char = '\'.
        IF lv_position >= lv_length.
          EXIT.
        ENDIF.
        lv_escape = iv_json+lv_position(1).
        ADD 1 TO lv_position.
        CLEAR lv_decode_escape.
        CASE lv_escape.
          WHEN '"'.
            lv_char = '"'.
          WHEN '\'.
            lv_char = '\'.
          WHEN '/'.
            lv_char = '/'.
          WHEN 'b'.
            lv_unicode_value = 8.
            lv_decode_escape = 'X'.
          WHEN 'f'.
            lv_unicode_value = 12.
            lv_decode_escape = 'X'.
          WHEN 'n'.
            lv_unicode_value = 10.
            lv_decode_escape = 'X'.
          WHEN 'r'.
            lv_unicode_value = 13.
            lv_decode_escape = 'X'.
          WHEN 't'.
            lv_unicode_value = 9.
            lv_decode_escape = 'X'.
          WHEN 'u'.
            IF lv_position + 4 > lv_length.
              CALL METHOD lcl_rest_handler=>message_text
                EXPORTING
                  iv_msgno = c_msg_token_field
                  iv_v1    = iv_key
                RECEIVING
                  rv_text  = ev_error.
              RETURN.
            ENDIF.

            lv_hex_value = iv_json+lv_position(4).
            TRANSLATE lv_hex_value TO UPPER CASE.
            IF lv_hex_value CN c_json_hex_digits.
              CALL METHOD lcl_rest_handler=>message_text
                EXPORTING
                  iv_msgno = c_msg_token_field
                  iv_v1    = iv_key
                RECEIVING
                  rv_text  = ev_error.
              RETURN.
            ENDIF.

            CLEAR lv_unicode_value.
            DO 4 TIMES.
              lv_hex_offset = sy-index - 1.
              lv_hex_char = lv_hex_value+lv_hex_offset(1).
              FIND FIRST OCCURRENCE OF lv_hex_char
                IN c_json_hex_digits MATCH OFFSET lv_hex_digit_value.
              IF sy-subrc <> 0.
                CALL METHOD lcl_rest_handler=>message_text
                  EXPORTING
                    iv_msgno = c_msg_token_field
                    iv_v1    = iv_key
                  RECEIVING
                    rv_text  = ev_error.
                RETURN.
              ENDIF.
              lv_unicode_value = lv_unicode_value * 16
                               + lv_hex_digit_value.
            ENDDO.
            ADD 4 TO lv_position.
            lv_decode_escape = 'X'.
          WHEN OTHERS.
            CALL METHOD lcl_rest_handler=>message_text
              EXPORTING
                iv_msgno = c_msg_token_field
                iv_v1    = iv_key
              RECEIVING
                rv_text  = ev_error.
            RETURN.
        ENDCASE.

        IF lv_decode_escape = 'X'.
          CALL METHOD lcl_rest_handler=>decode_json_token_escape
            EXPORTING
              iv_codepoint = lv_unicode_value
              iv_key       = iv_key
            IMPORTING
              ev_char      = lv_char
              ev_error     = ev_error.
          IF ev_error IS NOT INITIAL.
            RETURN.
          ENDIF.
        ENDIF.

        CONCATENATE ev_value lv_char INTO ev_value RESPECTING BLANKS.
      ELSEIF lv_char < space.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_token_field
            iv_v1    = iv_key
          RECEIVING
            rv_text  = ev_error.
        RETURN.
      ELSE.
        CONCATENATE ev_value lv_char INTO ev_value RESPECTING BLANKS.
      ENDIF.
    ENDWHILE.

    IF lv_closed IS INITIAL.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
    ENDIF.
  ENDMETHOD.

  METHOD decode_json_token_escape.
    DATA lv_ascii_offset TYPE i.
    DATA lv_control_bytes TYPE xstring.
    DATA lv_control_text TYPE string.
    DATA lv_crlf TYPE c LENGTH 2.
    DATA lv_cr TYPE c LENGTH 1.
    DATA lo_exception TYPE REF TO cx_root.

    CLEAR: ev_char, ev_error.

    IF iv_codepoint >= 32 AND iv_codepoint <= 126.
      lv_ascii_offset = iv_codepoint - 32.
      ev_char = c_json_ascii_printable+lv_ascii_offset(1).
      RETURN.
    ENDIF.

    CASE iv_codepoint.
      WHEN 8.
        lv_control_bytes = X'08'.
      WHEN 9.
        ev_char = cl_abap_char_utilities=>horizontal_tab.
        RETURN.
      WHEN 10.
        ev_char = cl_abap_char_utilities=>newline.
        RETURN.
      WHEN 12.
        lv_control_bytes = X'0C'.
      WHEN 13.
        lv_crlf = cl_abap_char_utilities=>cr_lf.
        lv_cr = lv_crlf+0(1).
        ev_char = lv_cr.
        RETURN.
      WHEN OTHERS.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_token_field
            iv_v1    = iv_key
          RECEIVING
            rv_text  = ev_error.
        RETURN.
    ENDCASE.

    TRY.
        lv_control_text = cl_abap_codepage=>convert_from(
                            source   = lv_control_bytes
                            codepage = 'UTF-8' ).
        ev_char = lv_control_text.
      CATCH cx_root INTO lo_exception.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_token_field
            iv_v1    = iv_key
          RECEIVING
            rv_text  = ev_error.
    ENDTRY.
  ENDMETHOD.

  METHOD extract_json_integer.
    DATA lv_search TYPE string.
    DATA lv_number TYPE string.
    DATA lv_length TYPE i.
    DATA lv_position TYPE i.
    DATA lv_char TYPE c LENGTH 1.
    DATA lo_exception TYPE REF TO cx_root.

    CLEAR: ev_value, ev_error.
    CONCATENATE '"' iv_key '"' INTO lv_search.
    FIND FIRST OCCURRENCE OF lv_search IN iv_json MATCH OFFSET lv_position.
    IF sy-subrc <> 0.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    lv_length = strlen( iv_json ).
    lv_position = lv_position + strlen( lv_search ).
    CALL METHOD lcl_rest_handler=>skip_json_whitespace
      EXPORTING
        iv_json = iv_json
      CHANGING
        cv_position = lv_position.
    IF lv_position >= lv_length.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    lv_char = iv_json+lv_position(1).
    IF lv_char <> ':'.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.
    ADD 1 TO lv_position.

    CALL METHOD lcl_rest_handler=>skip_json_whitespace
      EXPORTING
        iv_json = iv_json
      CHANGING
        cv_position = lv_position.

    WHILE lv_position < lv_length.
      lv_char = iv_json+lv_position(1).
      IF lv_char < '0' OR lv_char > '9'.
        EXIT.
      ENDIF.
      CONCATENATE lv_number lv_char INTO lv_number RESPECTING BLANKS.
      ADD 1 TO lv_position.
    ENDWHILE.

    IF lv_number IS INITIAL.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_field
          iv_v1    = iv_key
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    CALL METHOD lcl_rest_handler=>skip_json_whitespace
      EXPORTING
        iv_json = iv_json
      CHANGING
        cv_position = lv_position.
    IF lv_position < lv_length.
      lv_char = iv_json+lv_position(1).
      IF lv_char <> ',' AND lv_char <> '}'.
        CALL METHOD lcl_rest_handler=>message_text
          EXPORTING
            iv_msgno = c_msg_token_field
            iv_v1    = iv_key
          RECEIVING
            rv_text  = ev_error.
        RETURN.
      ENDIF.
    ENDIF.

    TRY.
        ev_value = lv_number.
      CATCH cx_root INTO lo_exception.
        ev_error = lo_exception->get_text( ).
    ENDTRY.
  ENDMETHOD.

  METHOD skip_json_whitespace.
    DATA lv_length TYPE i.
    DATA lv_char TYPE c LENGTH 1.
    DATA lv_crlf TYPE c LENGTH 2.
    DATA lv_cr TYPE c LENGTH 1.

    lv_length = strlen( iv_json ).
    lv_crlf = cl_abap_char_utilities=>cr_lf.
    lv_cr = lv_crlf+0(1).

    WHILE cv_position < lv_length.
      lv_char = iv_json+cv_position(1).
      IF lv_char = space
         OR lv_char = lv_cr
         OR lv_char = cl_abap_char_utilities=>newline
         OR lv_char = cl_abap_char_utilities=>horizontal_tab.
        ADD 1 TO cv_position.
      ELSE.
        EXIT.
      ENDIF.
    ENDWHILE.
  ENDMETHOD.

  METHOD add_seconds_to_timestamp.
    DATA lv_date TYPE d.
    DATA lv_expiry_date TYPE d.
    DATA lv_time TYPE t.
    DATA lv_expiry_time TYPE t.
    DATA lv_hours TYPE i.
    DATA lv_minutes TYPE i.
    DATA lv_seconds TYPE i.
    DATA lv_total_seconds TYPE i.
    DATA lv_days TYPE i.
    DATA lv_hh TYPE c LENGTH 2.
    DATA lv_mm TYPE c LENGTH 2.
    DATA lv_ss TYPE c LENGTH 2.

    CLEAR: ev_timestamp, ev_error.
    IF iv_seconds < 0.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_expiry
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    CONVERT TIME STAMP iv_timestamp TIME ZONE 'UTC'
      INTO DATE lv_date TIME lv_time.
    IF sy-subrc <> 0.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_expiry
        RECEIVING
          rv_text  = ev_error.
      RETURN.
    ENDIF.

    lv_hours = lv_time+0(2).
    lv_minutes = lv_time+2(2).
    lv_seconds = lv_time+4(2).
    lv_total_seconds = lv_hours * 3600
                     + lv_minutes * 60
                     + lv_seconds
                     + iv_seconds.

    lv_days = lv_total_seconds DIV 86400.
    lv_total_seconds = lv_total_seconds MOD 86400.
    lv_expiry_date = lv_date + lv_days.
    lv_hours = lv_total_seconds DIV 3600.
    lv_total_seconds = lv_total_seconds MOD 3600.
    lv_minutes = lv_total_seconds DIV 60.
    lv_seconds = lv_total_seconds MOD 60.

    WRITE lv_hours TO lv_hh USING EDIT MASK '00'.
    WRITE lv_minutes TO lv_mm USING EDIT MASK '00'.
    WRITE lv_seconds TO lv_ss USING EDIT MASK '00'.
    CONCATENATE lv_hh lv_mm lv_ss INTO lv_expiry_time.

    CONVERT DATE lv_expiry_date TIME lv_expiry_time
      INTO TIME STAMP ev_timestamp TIME ZONE 'UTC'.
    IF sy-subrc <> 0.
      CALL METHOD lcl_rest_handler=>message_text
        EXPORTING
          iv_msgno = c_msg_token_expiry
        RECEIVING
          rv_text  = ev_error.
    ENDIF.
  ENDMETHOD.
ENDCLASS.

CLASS ltc_rest_handler DEFINITION FOR TESTING
  RISK LEVEL HARMLESS
  DURATION SHORT.
  PRIVATE SECTION.
    METHODS test_nested_json_shape FOR TESTING.
    METHODS test_json_string_escaping FOR TESTING.
ENDCLASS.

CLASS ltc_rest_handler IMPLEMENTATION.
  METHOD test_nested_json_shape.
    DATA ls_event TYPE ty_event.
    DATA lt_events TYPE ty_event_tab.
    DATA lr_data TYPE REF TO data.
    DATA lv_json TYPE string.
    DATA lv_error TYPE string.
    DATA lv_expected TYPE string.

    ls_event-CARRID = 'LH'.
    ls_event-CONNID = '0400'.
    ls_event-CITYFROM = 'Zürich'.
    ls_event-AMOUNT = 125.50.
    ls_event-METADATA-SOURCE_TEXT = 'ABAP assignment'.
    ls_event-METADATA-PILOT = 'Müller'.
    APPEND 'training' TO ls_event-TAGS.
    APPEND ls_event TO lt_events.
    GET REFERENCE OF lt_events INTO lr_data.

    CALL METHOD lcl_rest_handler=>serialize_to_json
      EXPORTING
        io_data  = lr_data
        iv_depth = 0
      IMPORTING
        ev_json  = lv_json
        ev_error = lv_error.

    lv_expected = '[{"carrid":"LH","connid":"0400","cityfrom":"Zürich","amount":125.50,"metadata":{"source_text":"ABAP assignment","pilot":"Müller"},"tags":["training"]}]'.
    CALL METHOD cl_abap_unit_assert=>assert_initial
      EXPORTING
        act = lv_error.
    CALL METHOD cl_abap_unit_assert=>assert_equals
      EXPORTING
        act = lv_json
        exp = lv_expected.
  ENDMETHOD.

  METHOD test_json_string_escaping.
    TYPES:
      BEGIN OF ty_text,
        TEXT_VALUE TYPE string,
      END OF ty_text.

    DATA ls_text TYPE ty_text.
    DATA lr_data TYPE REF TO data.
    DATA lv_json TYPE string.
    DATA lv_error TYPE string.
    DATA lv_expected TYPE string.

    ls_text-TEXT_VALUE = 'quote: " slash: \ end'.
    GET REFERENCE OF ls_text INTO lr_data.

    CALL METHOD lcl_rest_handler=>serialize_to_json
      EXPORTING
        io_data  = lr_data
        iv_depth = 0
      IMPORTING
        ev_json  = lv_json
        ev_error = lv_error.

    lv_expected = '{"text_value":"quote: \" slash: \\ end"}'.
    CALL METHOD cl_abap_unit_assert=>assert_initial
      EXPORTING
        act = lv_error.
    CALL METHOD cl_abap_unit_assert=>assert_equals
      EXPORTING
        act = lv_json
        exp = lv_expected.
  ENDMETHOD.
ENDCLASS.

START-OF-SELECTION.
  DATA gs_event TYPE ty_event.
  DATA gt_events TYPE ty_event_tab.
  DATA lr_data TYPE REF TO data.
  DATA ls_result TYPE lcl_rest_handler=>ty_api_result.
  DATA lv_output_text TYPE string.
  DATA lv_status_text TYPE c LENGTH 10.

  CLEAR gs_event.
  gs_event-CARRID = 'LH'.
  gs_event-CONNID = '0400'.
  gs_event-CITYFROM = 'Zürich'.
  gs_event-AMOUNT = 125.50.
  gs_event-METADATA-SOURCE_TEXT = 'ABAP assignment'.
  gs_event-METADATA-PILOT = 'Müller'.
  APPEND 'training' TO gs_event-TAGS.
  APPEND 'delivery' TO gs_event-TAGS.
  APPEND gs_event TO gt_events.

  GET REFERENCE OF gt_events INTO lr_data.
  CALL METHOD lcl_rest_handler=>send_data
    EXPORTING
      io_data              = lr_data
      iv_api_destination   = p_api_dest
      iv_token_destination = p_token_dest
    IMPORTING
      es_result            = ls_result.

  IF ls_result-error_msg IS NOT INITIAL.
    CALL METHOD lcl_rest_handler=>message_text
      EXPORTING
        iv_msgno = lcl_rest_handler=>c_msg_output_error
      RECEIVING
        rv_text  = lv_output_text.
    WRITE: / lv_output_text, ls_result-error_msg.
  ENDIF.
  IF ls_result-status_code > 0.
    WRITE ls_result-status_code TO lv_status_text.
    CONDENSE lv_status_text NO-GAPS.
    CALL METHOD lcl_rest_handler=>message_text
      EXPORTING
        iv_msgno = lcl_rest_handler=>c_msg_output_status
        iv_v1    = lv_status_text
      RECEIVING
        rv_text  = lv_output_text.
    WRITE: / lv_output_text.
    CALL METHOD lcl_rest_handler=>message_text
      EXPORTING
        iv_msgno = lcl_rest_handler=>c_msg_output_body
      RECEIVING
        rv_text  = lv_output_text.
    WRITE: / lv_output_text, / ls_result-body.
  ENDIF.
