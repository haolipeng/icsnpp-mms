# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/parse_status.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_parse_status.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port direction result error_code diag parse_status parse_error
# @TEST-EXEC: check-mms-log-contract enum mms_parse_status.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_parse_status.log parse_status ok partial failed not_applicable
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction result error_code diag parse_status parse_error < mms_parse_status.log > parse-status.out
# @TEST-EXEC: btest-diff parse-status.out
# @TEST-EXEC: if test -f mms.log; then ! zeek-cut uid < mms.log | grep -q .; fi
# @TEST-EXEC: echo "iso-pres classification kept out of MMS business logs" > no-business-log.out
# @TEST-EXEC: btest-diff no-business-log.out
# @TEST-EXEC: zeek-cut name addl < weird.log > weird.out
# @TEST-EXEC: btest-diff weird.out

# 这个测试区分“未进入 MMS analyzer”的 ISO/PRES 分类和“MMS 已进入但业务 handler 未覆盖”。
# ISO/PRES weird 只能写通用解析状态日志，不得伪造 mms.log 等 MMS 业务日志记录。
module mms;

function test_connection(uid: string): connection {
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
        $service=set("pres"),
        $history="",
        $uid=uid
    ];
}

event zeek_init() {
    local pres_conn = test_connection("Cpres");
    Weird::weird([
        $ts=network_time(),
        $conn=pres_conn,
        $name="pres_parse_error",
        $addl="bad presentation pdu",
        $source="PRES"
    ]);

    local iso_conn = test_connection("Ciso");
    Weird::weird([
        $ts=network_time(),
        $conn=iso_conn,
        $name="iso_stack_incomplete",
        $addl="mms analyzer was not reached",
        $source="ISO"
    ]);
}
