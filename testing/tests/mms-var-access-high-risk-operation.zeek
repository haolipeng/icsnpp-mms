# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_var_access.log operation variable is_high_risk_operation
# @TEST-EXEC: check-mms-log-contract fields mms_varlist_access.log operation listname listindex is_high_risk_operation
# @TEST-EXEC: zeek-cut operation variable is_high_risk_operation < mms_var_access.log > var-access.out
# @TEST-EXEC: btest-diff var-access.out
# @TEST-EXEC: zeek-cut operation listname listindex is_high_risk_operation < mms_varlist_access.log > varlist-access.out
# @TEST-EXEC: btest-diff varlist-access.out

# 验证变量访问类日志基于 operation 静态集合派生 high-risk 标识。
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
        $uid="Chighrisk"
    ];
}

event zeek_init() {
    local c = test_connection();
    local variable_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="ST"]];
    local list_name: ObjectName = [$vmd_specific="DatasetA"];
    local value: Data = [$boolean=T];

    # write 是静态高风险操作；read/report 不依赖资产清单即可判定为非高风险。
    event VariableReadResponse(c, "resp_to_orig", 601, variable_name, value);
    event VariableWriteResponse(c, "resp_to_orig", 602, variable_name, value);
    event VariableReport(c, "resp_to_orig", variable_name, value);

    event VariableListReadResponse(c, "resp_to_orig", 603, list_name, 1, value);
    event VariableListWriteResponse(c, "resp_to_orig", 604, list_name, 2, value);
    event VariableListReport(c, "resp_to_orig", list_name, 3, value);
}
