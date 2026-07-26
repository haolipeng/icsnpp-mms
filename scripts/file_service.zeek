module mms;

@load ./helper

export {
    # File service operations share one log stream: mms_file_service.log.
    redef enum Log::ID += { LOG_FILE_SERVICE };

    type FileService: record {
        ts:        time     &log;
        uid:       string   &log;
        id:        conn_id  &log;
        src_ip:    addr     &log;
        dst_ip:    addr     &log;
        src_port:  port     &log;
        dst_port:  port     &log;
        direction: string   &log;
        invoke_id: int      &log;
        operation: string   &log;
        file_path: string   &log;
        file_handle: int    &log &optional;
        result:    string   &log;
        error_code: string  &log;
        diag:      string   &log &optional;
        parse_status: string &log;
        parse_error: string &log;
        is_high_risk_operation: bool &log;
        success:   bool     &log;
    };

    global log_mms_file_service: event(rec: FileService);

    const log_file_service: bool = T &redef;
}

function fileName_to_string(name: FileName): string {
    local path = "";

    for(i in name) {
        if(|path| > 0)
            path += "/";

        path += name[i];
    }

    return path;
}

function write_file_service(
    c: connection,
    direction: string,
    invokeID: int,
    operation: string,
    file_handle: int,
    file_path: string,
    result_fields: MMS_ResultFields
) {
    local endpoint_fields = mms_endpoint_fields(c$id);
    local rec: FileService = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $src_ip=endpoint_fields$src_ip,
        $dst_ip=endpoint_fields$dst_ip,
        $src_port=endpoint_fields$src_port,
        $dst_port=endpoint_fields$dst_port,
        $direction=direction,
        $invoke_id=invokeID,
        $operation=operation,
        $file_path=file_path,
        $file_handle=file_handle,
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $is_high_risk_operation=mms_is_high_risk_operation(operation),
        $success=result_fields$result == "success"
    ];

    if(result_fields?$diag)
        rec$diag = result_fields$diag;

    Log::write(LOG_FILE_SERVICE, rec);
}

function file_handle_result(c: connection, file_handle: int): MMS_ResultFields {
    if(c?$mms_file_handles && file_handle in c$mms_file_handles)
        return mms_result_fields();

    return mms_result_fields(
        "success",
        "none",
        "",
        "partial",
        "file_handle_unmatched"
    );
}

function file_handle_path(c: connection, file_handle: int): string {
    if(c?$mms_file_handles && file_handle in c$mms_file_handles)
        return c$mms_file_handles[file_handle];

    return "";
}

event zeek_init() &priority=5
{
    Log::create_stream(mms::LOG_FILE_SERVICE,
        [$columns = FileService,
        $ev = log_mms_file_service,
        $path="mms_file_service"]);
}

event fileOpenResponse(c: connection, direction: string, invokeID: int, pdu: FileOpen_Response) {
    if(! log_file_service)
        return;

    if(! c?$mms_file_open_requests || invokeID !in c$mms_file_open_requests)
        return;

    if(! c?$mms_file_handles)
        c$mms_file_handles = table();

    local request = c$mms_file_open_requests[invokeID];
    local file_path = fileName_to_string(request$fileName);
    local file_handle = pdu$frsmID;
    c$mms_file_handles[file_handle] = file_path;

    local result_fields = mms_result_fields();
    write_file_service(c, direction, invokeID, "file_open", file_handle, file_path, result_fields);
}

event fileReadRequest(c: connection, direction: string, invokeID: int, pdu: FileRead_Request) {
    if(! log_file_service)
        return;

    local file_handle = pdu;
    local file_path = file_handle_path(c, file_handle);
    local result_fields = file_handle_result(c, file_handle);

    write_file_service(c, direction, invokeID, "file_read", file_handle, file_path, result_fields);
}

event fileCloseResponse(c: connection, direction: string, invokeID: int, pdu: FileClose_Response) {
    if(! log_file_service)
        return;

    if(! c?$mms_file_close_requests || invokeID !in c$mms_file_close_requests)
        return;

    local file_handle = c$mms_file_close_requests[invokeID];
    local file_path = file_handle_path(c, file_handle);
    local result_fields = file_handle_result(c, file_handle);

    write_file_service(c, direction, invokeID, "file_close", file_handle, file_path, result_fields);

    if(c?$mms_file_handles && file_handle in c$mms_file_handles)
        delete c$mms_file_handles[file_handle];
}

event connection_state_remove(c: connection) {
    if(c?$mms_file_open_requests)
        delete c$mms_file_open_requests;

    if(c?$mms_file_close_requests)
        delete c$mms_file_close_requests;

    if(c?$mms_file_handles)
        delete c$mms_file_handles;
}
