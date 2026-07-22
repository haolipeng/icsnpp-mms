# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_var_access.log operation variable result error_code success diag invoke_id
# @TEST-EXEC: check-mms-log-contract enum mms_var_access.log result success failure unknown not_applicable
# @TEST-EXEC: zeek-cut operation variable result error_code success diag invoke_id < mms_var_access.log > result-error-code.out
# @TEST-EXEC: btest-diff result-error-code.out

# 验证单变量访问日志的 result/error_code 契约，并确认 diag 保留原始错误。
module mms;

# 构造一条最小连接，供测试手动触发 MMS 事件写日志。
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
        $uid="Cvarresult"
    ];
}

event zeek_init() {
    local c = test_connection();
    local read_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="ST"]];
    local write_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="MX"]];
    local report_name: ObjectName = [$vmd_specific="ReportVar"];
    local value: Data = [$visible_string="ok"];
    local bad_value: Data = [$visible_string="bad"];

    # 依次模拟单变量 Read 响应、Write 响应和 InformationReport 上报的成功结果。
    # 这三类成功事件都应统一输出 result=success、error_code=none。
    event VariableReadResponse(c, "resp_to_orig", 401, read_name, value);
    event VariableWriteResponse(c, "resp_to_orig", 403, write_name, value);
    event VariableReport(c, "resp_to_orig", report_name, value);

    # 依次模拟单变量 Read 响应、Write 响应和 InformationReport 上报的失败结果。
    # 失败事件应统一输出 result=failure，并映射 DataAccessError 到 error_code。
    event VariableReadResponseError(c, "resp_to_orig", 402, read_name, DataAccessError_object_access_denied);
    event VariableWriteResponseError(c, "resp_to_orig", 404, write_name, bad_value, hardware_fault);
    event VariableReportError(c, "resp_to_orig", report_name, object_value_invalid);
}
