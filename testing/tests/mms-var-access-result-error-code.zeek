# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_var_access.log operation variable result error_code success diag invoke_id
# @TEST-EXEC: check-mms-log-contract enum mms_var_access.log result success failure unknown not_applicable
# @TEST-EXEC: zeek-cut operation variable result error_code success diag invoke_id < mms_var_access.log > result-error-code.out
# @TEST-EXEC: btest-diff result-error-code.out

module mms;

function test_connection(): connection
    {
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

event zeek_init()
    {
    local c = test_connection();
    local read_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="ST"]];
    local write_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="MX"]];
    local report_name: ObjectName = [$vmd_specific="ReportVar"];
    local value: Data = [$visible_string="ok"];
    local bad_value: Data = [$visible_string="bad"];

    event VariableReadResponse(c, "resp_to_orig", 401, read_name, value);
    event VariableReadResponseError(c, "resp_to_orig", 402, read_name, DataAccessError_object_access_denied);

    event VariableWriteResponse(c, "resp_to_orig", 403, write_name, value);
    event VariableWriteResponseError(c, "resp_to_orig", 404, write_name, bad_value, hardware_fault);

    event VariableReport(c, "resp_to_orig", report_name, value);
    event VariableReportError(c, "resp_to_orig", report_name, object_value_invalid);
    }
