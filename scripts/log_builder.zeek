module mms;

@load ./helper

export {
    type MMS_LogCommonFields: record {
        ts:        time;
        uid:       string;
        id:        conn_id;
        src_ip:    addr;
        dst_ip:    addr;
        src_port:  port;
        dst_port:  port;
        direction: string;
        invoke_id: int;
        result:    string;
        error_code: string;
        parse_status: string;
        parse_error: string;
        diag:      string &optional;
        success:   bool;
    };

    global mms_log_common_fields: function(
        c: connection,
        direction: string,
        invokeID: int,
        result_fields: MMS_ResultFields
    ): MMS_LogCommonFields;
}

function mms_log_common_fields(
    c: connection,
    direction: string,
    invokeID: int,
    result_fields: MMS_ResultFields
): MMS_LogCommonFields {
    local rec: MMS_LogCommonFields = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $src_ip=c$id$orig_h,
        $dst_ip=c$id$resp_h,
        $src_port=c$id$orig_p,
        $dst_port=c$id$resp_p,
        $direction=direction,
        $invoke_id=invokeID,
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $success=result_fields$result == "success"
    ];

    if(result_fields?$diag)
        rec$diag = result_fields$diag;

    return rec;
}
