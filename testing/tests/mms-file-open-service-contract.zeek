# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/file_service.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_file_service.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port direction invoke_id operation file_path file_handle result error_code diag parse_status parse_error is_high_risk_operation success
# @TEST-EXEC: check-mms-log-contract enum mms_file_service.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_file_service.log parse_status ok partial failed not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_file_service.log direction orig_to_resp resp_to_orig unknown not_applicable
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction invoke_id operation file_path file_handle result error_code diag parse_status parse_error is_high_risk_operation success < mms_file_service.log > file-service.out
# @TEST-EXEC: btest-diff file-service.out

# 验证 FileOpen 响应与请求配对后写入文件服务日志，并建立连接内句柄上下文。
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
        $uid="Cfileopen"
    ];
}

event zeek_init() {
    local c = test_connection();
    local request: FileOpen_Request = [
        $fileName=vector("cfg", "settings.bin"),
        $initialPosition=+0
    ];
    local response: FileOpen_Response = [
        $frsmID=42,
        $fileAttributes=[$sizeOfFile=+1024]
    ];

    event fileOpenRequest(c, "orig_to_resp", 1001, request);
    event fileOpenResponse(c, "resp_to_orig", 1001, response);
    event connection_state_remove(c);

    if(c?$mms_file_handles)
        Reporter::fatal("mms_file_handles was not cleared on connection removal");
}
