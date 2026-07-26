# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/parse_status.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_parse_status.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port direction result error_code diag parse_status parse_error
# @TEST-EXEC: check-mms-log-contract enum mms_parse_status.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_parse_status.log parse_status ok partial failed not_applicable
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction result error_code diag parse_status parse_error < mms_parse_status.log > parse-status.out
# @TEST-EXEC: btest-diff parse-status.out
# @TEST-EXEC: zeek-cut name addl < weird.log > weird.out
# @TEST-EXEC: btest-diff weird.out

# 验证无法归属具体业务日志的 MMS parse weird 进入通用解析状态日志，同时保留原始 weird.log。
module mms;

event zeek_init() {
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

    local c: connection = [
        $id=id,
        $orig=ep,
        $resp=ep,
        $start_time=network_time(),
        $duration=0sec,
        $service=set("mms"),
        $history="",
        $uid="Cparse"
    ];

    Weird::weird([
        $ts=network_time(),
        $conn=c,
        $name="mms_parse_error",
        $addl="unable to parse packet",
        $source="MMS"
    ]);
}
