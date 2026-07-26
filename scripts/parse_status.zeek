@load base/frameworks/notice/weird
@load ./main

module mms;

export {
    # Parse failures that cannot be attributed to a more specific business log.
    redef enum Log::ID += { LOG_PARSE_STATUS };

    type ParseStatus: record {
        ts:           time    &log;
        uid:          string  &log &optional;
        id:           conn_id &log &optional;
        src_ip:       addr    &log &optional;
        dst_ip:       addr    &log &optional;
        src_port:     port    &log &optional;
        dst_port:     port    &log &optional;
        direction:    string  &log;
        result:       string  &log;
        error_code:   string  &log;
        diag:         string  &log &optional;
        parse_status: string  &log;
        parse_error:  string  &log;
    };

    global log_mms_parse_status: event(rec: ParseStatus);

    const log_parse_status: bool = T &redef;
}

global parse_status_business_contexts: table[string] of connection;

function weird_parse_error(name: string): string {
    if(name in mms_parse_error_values)
        return name;

    return "unknown_parse_error";
}

function is_mms_parse_weird(w: Weird::Info): bool {
    if(w$name == "mms_parse_error" || w$name == "mms_constraint_error")
        return T;

    if(w?$source && w$source == "MMS" && /parse_error|constraint_error/ in w$name)
        return T;

    return F;
}

event IdentifyResponse(c: connection, direction: string, id: Identify_Response) {
    parse_status_business_contexts[c$uid] = c;
}

event zeek_init() &priority=5
{
    Log::create_stream(mms::LOG_PARSE_STATUS,
        [$columns = ParseStatus,
        $ev = log_mms_parse_status,
        $path="mms_parse_status"]);
}

hook Weird::log_policy(w: Weird::Info, id: Log::ID, filter: Log::Filter)
{
    if(! log_parse_status || ! is_mms_parse_weird(w))
        return;

    local parse_error = weird_parse_error(w$name);
    local result_fields = mms_result_fields(
        "failure",
        parse_error,
        w?$addl ? w$addl : "",
        "failed",
        parse_error
    );

    if(w?$uid && w$uid in parse_status_business_contexts) {
        local c = parse_status_business_contexts[w$uid];
        if(! c?$mms_info)
            return;

        local info = get_info(c);
        info$result = result_fields$result;
        info$error_code = result_fields$error_code;
        info$parse_status = result_fields$parse_status;
        info$parse_error = result_fields$parse_error;
        return;
    }

    local rec: ParseStatus = [
        $ts=w$ts,
        $direction="unknown",
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error
    ];

    if(w?$uid)
        rec$uid = w$uid;

    if(w?$id) {
        rec$id = w$id;
        local endpoint_fields = mms_endpoint_fields(w$id);
        rec$src_ip = endpoint_fields$src_ip;
        rec$dst_ip = endpoint_fields$dst_ip;
        rec$src_port = endpoint_fields$src_port;
        rec$dst_port = endpoint_fields$dst_port;
    }

    if(result_fields?$diag)
        rec$diag = result_fields$diag;

    Log::write(LOG_PARSE_STATUS, rec);
}

event connection_state_remove(c: connection) &priority=-5 {
    if(c$uid in parse_status_business_contexts)
        delete parse_status_business_contexts[c$uid];
}
