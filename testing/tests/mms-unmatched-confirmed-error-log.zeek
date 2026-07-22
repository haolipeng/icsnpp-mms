# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/error.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_error.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port direction invoke_id operation result error_code diag parse_status parse_error
# @TEST-EXEC: check-mms-log-contract enum mms_error.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_error.log parse_status ok partial failed not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_error.log direction orig_to_resp resp_to_orig unknown not_applicable
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction invoke_id operation result error_code diag parse_status parse_error < mms_error.log > error.out
# @TEST-EXEC: btest-diff error.out

# 验证无法配对请求的 ConfirmedError 会进入通用错误日志。
module mms;

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
        $uid="Cunmatched"
    ];
}

event zeek_init() {
    local c = test_connection();
    local error_response: Confirmed_ErrorPDU = [
        $invokeID=1901,
        $serviceError=[$errorClass=[$definition=ServiceError_object_undefined]]
    ];

    event confirmedErrorPDU_evt(c, "resp_to_orig", 1901, error_response);
}
