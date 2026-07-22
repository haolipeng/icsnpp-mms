module mms;

@load ./helper

export {
    # 无法归入具体业务日志的 MMS 错误 → mms_error.log
    redef enum Log::ID += { LOG_ERROR };

    type ErrorRecord: record {
        ts:           time    &log;
        uid:          string  &log;
        id:           conn_id &log;
        src_ip:       addr    &log;
        dst_ip:       addr    &log;
        src_port:     port    &log;
        dst_port:     port    &log;
        direction:    string  &log;
        invoke_id:    int     &log &optional;
        operation:    string  &log;
        result:       string  &log;
        error_code:   string  &log;
        diag:         string  &log &optional;
        parse_status: string  &log;
        parse_error:  string  &log;
    };

    global log_mms_error: event(rec: ErrorRecord);

    const log_error: bool = T &redef;
}

event zeek_init() &priority=5
{
    Log::create_stream(mms::LOG_ERROR, [$columns = ErrorRecord, $ev = log_mms_error, $path="mms_error"]);
}

# ConfirmedError 没有匹配到请求缓存时，写入通用错误日志。
event UnmatchedConfirmedError(c: connection, direction: string, invokeID: int, pdu: Confirmed_ErrorPDU) {
    if(!log_error) return;

    local endpoint_fields = mms_endpoint_fields(c$id);
    local diag = errorClass_to_string(pdu$serviceError);
    local result_fields = mms_result_fields(
        "failure",
        mms_service_error_code(diag),
        diag,
        "partial",
        "request_response_unmatched"
    );

    local rec: ErrorRecord = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $src_ip=endpoint_fields$src_ip,
        $dst_ip=endpoint_fields$dst_ip,
        $src_port=endpoint_fields$src_port,
        $dst_port=endpoint_fields$dst_port,
        $direction=direction,
        $invoke_id=invokeID,
        $operation="confirmed_error",
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $diag=diag
    ];

    Log::write(LOG_ERROR, rec);
}
