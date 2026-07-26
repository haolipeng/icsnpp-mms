# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/parse_status.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port result error_code parse_status parse_error deviceVendor deviceModel deviceRevision protocolVersion parameterCBB servicesSupported
# @TEST-EXEC: check-mms-log-contract enum mms.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms.log parse_status ok partial failed not_applicable
# @TEST-EXEC: zeek-cut result error_code parse_status parse_error deviceVendor < mms.log > mms-parse.out
# @TEST-EXEC: btest-diff mms-parse.out
# @TEST-EXEC: zeek-cut name addl < weird.log > weird.out
# @TEST-EXEC: btest-diff weird.out

# 验证已有关联业务上下文的 MMS parse weird 会落入对应业务日志解析字段。
module mms;

global emit_parse_weird: event(c: connection);

function test_connection(): connection {
    local id: conn_id = [
        $orig_h=192.168.1.10,
        $orig_p=12000/tcp,
        $resp_h=192.168.1.20,
        $resp_p=102/tcp
    ];

    local ep: endpoint = [
        $size=0,
        $state=0,
        $flow_label=0
    ];

    return [
        $id=id,
        $orig=ep,
        $resp=ep,
        $start_time=network_time(),
        $duration=0sec,
        $service=set("mms"),
        $history="",
        $uid="Cparsebiz"
    ];
}

event zeek_init() {
    local c = test_connection();
    local ident: Identify_Response = [
        $vendorName="Acme",
        $modelName="Relay",
        $revision="1"
    ];

    event IdentifyResponse(c, "resp_to_orig", ident);
    event emit_parse_weird(c);
}

event emit_parse_weird(c: connection) {
    Weird::weird([
        $ts=network_time(),
        $conn=c,
        $name="mms_constraint_error",
        $addl="constraint failed",
        $source="MMS"
    ]);

    event connection_state_remove(c);
}
