# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_var_access.log operation variable value success diag invoke_id
# @TEST-EXEC: check-mms-log-contract fields mms_varlist_access.log operation listname listindex value success diag invoke_id
# @TEST-EXEC: check-mms-log-contract empty mms_var_access.log invoke_id
# @TEST-EXEC: check-mms-log-contract empty mms_varlist_access.log invoke_id
# @TEST-EXEC: zeek-cut operation variable value success diag invoke_id < mms_var_access.log > var-access.out
# @TEST-EXEC: btest-diff var-access.out
# @TEST-EXEC: zeek-cut operation listname listindex value success diag invoke_id < mms_varlist_access.log > varlist-access.out
# @TEST-EXEC: btest-diff varlist-access.out

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
        $uid="Cuninvo"
    ];
}

event zeek_init() {
    local c = test_connection();
    local variable_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="ST"]];
    local list_name: ObjectName = [$vmd_specific="datasetR"];
    local variable_spec: VariableSpecification = [$name=variable_name];
    local variable_data: Data = [$visible_string="report-value"];
    local list_data: Data = [$boolean=T];
    local variable_result: AccessResult = [$success=variable_data];
    local list_result: AccessResult = [$success=list_data];

    local report_variables: vector of record {
        variableSpecification: VariableSpecification;
        alternateAccess: AlternateAccess &optional;
    };
    report_variables[0] = [$variableSpecification=variable_spec];

    local variable_report: InformationReport = [
        $variableAccessSpecification=[$listOfVariable=report_variables],
        $listOfAccessResult=vector(variable_result)
    ];
    event informationReport_evt(c, "resp_to_orig", variable_report);

    local list_report: InformationReport = [
        $variableAccessSpecification=[$variableListName=list_name],
        $listOfAccessResult=vector(list_result)
    ];
    event informationReport_evt(c, "resp_to_orig", list_report);
}
