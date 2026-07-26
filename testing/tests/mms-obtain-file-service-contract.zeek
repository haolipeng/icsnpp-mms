# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/file_service.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_file_service.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port direction invoke_id operation file_path source_file_path destination_file_path file_handle result error_code diag parse_status parse_error is_high_risk_operation success
# @TEST-EXEC: check-mms-log-contract enum mms_file_service.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_file_service.log parse_status ok partial failed not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_file_service.log direction orig_to_resp resp_to_orig unknown not_applicable
# @TEST-EXEC: zeek-cut direction invoke_id operation file_path source_file_path destination_file_path file_handle result error_code parse_status parse_error success < mms_file_service.log > obtain-file.out
# @TEST-EXEC: btest-diff obtain-file.out

# 验证 ObtainFile 在源路径和目标路径直接可见时写入文件服务日志，即使没有响应也保留请求可观测性。
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
        $uid="Cobtainfile"
    ];
}

event zeek_init() {
    local c = test_connection();
    local request: ObtainFile_Request = [
        $sourceFile=vector("remote", "events.bin"),
        $destinationFile=vector("local", "events.bin")
    ];

    event obtainFileRequest(c, "orig_to_resp", 4001, request);
}
