# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/helper.zeek" %INPUT > output
# @TEST-EXEC: btest-diff output

# 验证 helper.zeek 提供的通用字段构造和枚举集合契约。
module mms;

event zeek_init() {
    local id: conn_id = [
        $orig_h=192.168.1.10,
        $orig_p=12000/tcp,
        $resp_h=192.168.1.20,
        $resp_p=102/tcp
    ];

    # 从 Zeek 连接五元组中提取标准端点字段。
    local ep = mms_endpoint_fields(id);
    print fmt("endpoint=%s,%s,%s,%s",
        ep$src_ip,
        ep$dst_ip,
        ep$src_port,
        ep$dst_port);

    # 默认结果字段表示一次成功且解析正常的 MMS 行为。
    local result_fields = mms_result_fields();
    print fmt("result-fields=%s,%s,%s,%s,%s",
        result_fields$result,
        result_fields$error_code,
        result_fields?$diag,
        result_fields$parse_status,
        result_fields$parse_error);

    # partial 场景用于表达请求/响应上下文不完整，但仍保留已观察行为。
    local partial_result_fields = mms_result_fields(
        "unknown",
        "none",
        "",
        "partial",
        "request_response_unmatched");
    print fmt("partial-result-fields=%s,%s",
        partial_result_fields$parse_status,
        partial_result_fields$parse_error);

    # parse_status 只能使用约定集合中的稳定枚举值。
    print fmt("parse-status-values=%s,%s,%s,%s,%s",
        "ok" in mms_parse_status_values,
        "partial" in mms_parse_status_values,
        "failed" in mms_parse_status_values,
        "not_applicable" in mms_parse_status_values,
        "unknown" in mms_parse_status_values);

    # parse_error 只能使用约定集合中的稳定错误码。
    print fmt("parse-error-values=%s,%s,%s,%s,%s,%s,%s,%s,%s",
        "none" in mms_parse_error_values,
        "mms_parse_error" in mms_parse_error_values,
        "mms_constraint_error" in mms_parse_error_values,
        "pres_parse_error" in mms_parse_error_values,
        "request_response_unmatched" in mms_parse_error_values,
        "file_handle_unmatched" in mms_parse_error_values,
        "iso_stack_incomplete" in mms_parse_error_values,
        "unknown_parse_error" in mms_parse_error_values,
        "unknown" in mms_parse_error_values);

    # 高风险操作集合用于标记 write 等需要重点关注的行为。
    print fmt("risk=%s,%s",
        mms_is_high_risk_operation("write"),
        mms_is_high_risk_operation("read"));
}
