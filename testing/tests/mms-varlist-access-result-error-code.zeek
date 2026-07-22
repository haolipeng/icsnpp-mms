# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_varlist_access.log operation listname result error_code listindex success diag invoke_id
# @TEST-EXEC: check-mms-log-contract enum mms_varlist_access.log result success failure unknown not_applicable
# @TEST-EXEC: zeek-cut operation listname result error_code listindex success diag invoke_id < mms_varlist_access.log > result-error-code.out
# @TEST-EXEC: btest-diff result-error-code.out

# 验证变量列表访问日志的 result/error_code 契约，并确认 diag 保留原始错误。
module mms;

# 构造一条最小连接，供测试手动触发变量列表访问事件写日志。
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
        $uid="Cvarlistresult"
    ];
}

event zeek_init() {
    local c = test_connection();
    local read_list: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="DatasetR"]];
    local write_list: ObjectName = [$vmd_specific="DatasetW"];
    local report_list: ObjectName = [$aa_specific="DatasetReport"];
    local value: Data = [$visible_string="ok"];
    local bad_value: Data = [$visible_string="bad"];

    # 依次模拟变量列表 Read 响应、Write 响应和 InformationReport 上报的成功结果。
    # 这三类成功事件都应统一输出 result=success、error_code=none。
    event VariableListReadResponse(c, "resp_to_orig", 501, read_list, 1, value);
    event VariableListWriteResponse(c, "resp_to_orig", 503, write_list, 2, value);
    event VariableListReport(c, "resp_to_orig", report_list, 3, value);

    # 依次模拟变量列表 Read 响应、Write 响应和 InformationReport 上报的失败结果。
    # 失败事件应统一输出 result=failure，并映射 DataAccessError 到 error_code。
    event VariableListReadResponseError(c, "resp_to_orig", 502, read_list, 4, DataAccessError_object_access_denied);
    event VariableListWriteResponseError(c, "resp_to_orig", 504, write_list, 5, bad_value, hardware_fault);
    event VariableListReportError(c, "resp_to_orig", report_list, 6, object_value_invalid);
}
