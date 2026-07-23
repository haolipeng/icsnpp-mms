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

function reject_reason_to_string(reason: RejectPDU): string {
    if(reason$rejectReason?$confirmed_requestPDU)
        return cat(reason$rejectReason$confirmed_requestPDU);
    if(reason$rejectReason?$confirmed_responsePDU)
        return cat(reason$rejectReason$confirmed_responsePDU);
    if(reason$rejectReason?$confirmed_errorPDU)
        return cat(reason$rejectReason$confirmed_errorPDU);
    if(reason$rejectReason?$unconfirmedPDU)
        return cat(reason$rejectReason$unconfirmedPDU);
    if(reason$rejectReason?$pdu_error)
        return cat(reason$rejectReason$pdu_error);
    if(reason$rejectReason?$cancel_requestPDU)
        return cat(reason$rejectReason$cancel_requestPDU);
    if(reason$rejectReason?$cancel_responsePDU)
        return cat(reason$rejectReason$cancel_responsePDU);
    if(reason$rejectReason?$cancel_errorPDU)
        return cat(reason$rejectReason$cancel_errorPDU);
    if(reason$rejectReason?$conclude_requestPDU)
        return cat(reason$rejectReason$conclude_requestPDU);
    if(reason$rejectReason?$conclude_responsePDU)
        return cat(reason$rejectReason$conclude_responsePDU);
    if(reason$rejectReason?$conclude_errorPDU)
        return cat(reason$rejectReason$conclude_errorPDU);

    return "<unknown>";
}

function reject_reason_to_error_code(reason: string): string {
    if(reason == "<unknown>")
        return "unknown_error";
    if("_unrecognized_service" in reason)
        return "unrecognized_service";
    if("_invalid_invokeID" in reason)
        return "invalid_invoke_id";
    if("_invalid_argument" in reason)
        return "invalid_argument";
    if("_invalid_result" in reason)
        return "invalid_result";
    if("_invalid_serviceError" in reason)
        return "invalid_service_error";
    if("_value_out_of_range" in reason)
        return "value_out_of_range";
    if("_max_recursion_exceeded" in reason)
        return "max_recursion_exceeded";
    if("_unrecognized_modifier" in reason)
        return "unrecognized_modifier";
    if("_invalid_modifier" in reason)
        return "invalid_modifier";
    if("_max_serv_outstanding_exceeded" in reason)
        return "max_serv_outstanding_exceeded";
    if("_illegal_acse_mapping" in reason)
        return "illegal_acse_mapping";
    if("_invalid_pdu" in reason)
        return "invalid_pdu";
    if("_unknown_pdu_type" in reason)
        return "unknown_pdu_type";
    if("_other" in reason)
        return "other";

    return "unknown_error";
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

event RejectPDU_evt(c: connection, direction: string, pdu: RejectPDU) {
    if(!log_error) return;

    local endpoint_fields = mms_endpoint_fields(c$id);
    local diag = remove_ns(reject_reason_to_string(pdu));
    local result_fields = mms_result_fields(
        "failure",
        reject_reason_to_error_code(diag),
        diag
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
        $operation="reject",
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $diag=diag
    ];

    if(pdu?$originalInvokeID)
        rec$invoke_id = pdu$originalInvokeID;

    Log::write(LOG_ERROR, rec);
}

event CancelErrorPDU_evt(c: connection, direction: string, pdu: Cancel_ErrorPDU) {
    if(!log_error) return;

    local endpoint_fields = mms_endpoint_fields(c$id);
    local diag = errorClass_to_string(pdu$serviceError);
    local result_fields = mms_result_fields("failure", mms_service_error_code(diag), diag);

    local rec: ErrorRecord = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $src_ip=endpoint_fields$src_ip,
        $dst_ip=endpoint_fields$dst_ip,
        $src_port=endpoint_fields$src_port,
        $dst_port=endpoint_fields$dst_port,
        $direction=direction,
        $invoke_id=pdu$originalInvokeID,
        $operation="cancel_error",
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $diag=diag
    ];

    Log::write(LOG_ERROR, rec);
}

event ConcludeErrorPDU_evt(c: connection, direction: string, pdu: Conclude_ErrorPDU) {
    if(!log_error) return;

    local endpoint_fields = mms_endpoint_fields(c$id);
    local diag = errorClass_to_string(pdu);
    local result_fields = mms_result_fields("failure", mms_service_error_code(diag), diag);

    local rec: ErrorRecord = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $src_ip=endpoint_fields$src_ip,
        $dst_ip=endpoint_fields$dst_ip,
        $src_port=endpoint_fields$src_port,
        $dst_port=endpoint_fields$dst_port,
        $direction=direction,
        $operation="conclude_error",
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $diag=diag
    ];

    Log::write(LOG_ERROR, rec);
}
