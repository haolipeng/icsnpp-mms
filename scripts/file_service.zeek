module mms;

@load ./log_builder
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
        source_file_path: string &log &optional;
        destination_file_path: string &log &optional;
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
    local common_fields = mms_log_common_fields(c, direction, invokeID, result_fields);
    local rec: FileService = [
        $ts=common_fields$ts,
        $uid=common_fields$uid,
        $id=common_fields$id,
        $src_ip=common_fields$src_ip,
        $dst_ip=common_fields$dst_ip,
        $src_port=common_fields$src_port,
        $dst_port=common_fields$dst_port,
        $direction=common_fields$direction,
        $invoke_id=common_fields$invoke_id,
        $operation=operation,
        $file_path=file_path,
        $result=common_fields$result,
        $error_code=common_fields$error_code,
        $parse_status=common_fields$parse_status,
        $parse_error=common_fields$parse_error,
        $is_high_risk_operation=mms_is_high_risk_operation(operation),
        $success=common_fields$success
    ];

    if(common_fields?$diag)
        rec$diag = common_fields$diag;

    if(file_handle >= 0)
        rec$file_handle = file_handle;

    Log::write(LOG_FILE_SERVICE, rec);
}

function visible_request_result(): MMS_ResultFields {
    return mms_result_fields(
        "unknown",
        "none",
        "",
        "partial",
        "request_response_unmatched"
    );
}

function write_obtain_file_service(c: connection, direction: string, invokeID: int, pdu: ObtainFile_Request) {
    local source_file_path = fileName_to_string(pdu$sourceFile);
    local destination_file_path = fileName_to_string(pdu$destinationFile);
    local file_path = source_file_path + " -> " + destination_file_path;
    local result_fields = visible_request_result();
    local common_fields = mms_log_common_fields(c, direction, invokeID, result_fields);
    local rec: FileService = [
        $ts=common_fields$ts,
        $uid=common_fields$uid,
        $id=common_fields$id,
        $src_ip=common_fields$src_ip,
        $dst_ip=common_fields$dst_ip,
        $src_port=common_fields$src_port,
        $dst_port=common_fields$dst_port,
        $direction=common_fields$direction,
        $invoke_id=common_fields$invoke_id,
        $operation="obtain_file",
        $file_path=file_path,
        $source_file_path=source_file_path,
        $destination_file_path=destination_file_path,
        $result=common_fields$result,
        $error_code=common_fields$error_code,
        $parse_status=common_fields$parse_status,
        $parse_error=common_fields$parse_error,
        $is_high_risk_operation=mms_is_high_risk_operation("obtain_file"),
        $success=common_fields$success
    ];

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

function directory_request_path(pdu: FileDirectory_Request): string {
    if(pdu?$fileSpecification)
        return fileName_to_string(pdu$fileSpecification);

    if(pdu?$continueAfter)
        return fileName_to_string(pdu$continueAfter);

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

event fileDeleteRequest(c: connection, direction: string, invokeID: int, pdu: FileDelete_Request) {
    if(! log_file_service)
        return;

    write_file_service(
        c,
        direction,
        invokeID,
        "file_delete",
        -1,
        fileName_to_string(pdu),
        visible_request_result()
    );
}

event fileDirectoryRequest(c: connection, direction: string, invokeID: int, pdu: FileDirectory_Request) {
    if(! log_file_service)
        return;

    write_file_service(
        c,
        direction,
        invokeID,
        "file_directory",
        -1,
        directory_request_path(pdu),
        visible_request_result()
    );
}

event obtainFileRequest(c: connection, direction: string, invokeID: int, pdu: ObtainFile_Request) {
    if(! log_file_service)
        return;

    write_obtain_file_service(c, direction, invokeID, pdu);
}

event connection_state_remove(c: connection) {
    if(c?$mms_file_open_requests)
        delete c$mms_file_open_requests;

    if(c?$mms_file_close_requests)
        delete c$mms_file_close_requests;

    if(c?$mms_file_handles)
        delete c$mms_file_handles;
}
