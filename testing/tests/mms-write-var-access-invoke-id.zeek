# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_var_access.log operation variable value success diag invoke_id
# @TEST-EXEC: check-mms-log-contract fields mms_varlist_access.log operation listname listindex value success diag invoke_id
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
        $uid="Cwriteinvoke"
    ];
}

event zeek_init() {
    local c = test_connection();
    local success_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="ST"]];
    local failure_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="MX"]];
    local list_name: ObjectName = [$vmd_specific="datasetW"];
    local success_spec: VariableSpecification = [$name=success_name];
    local failure_spec: VariableSpecification = [$name=failure_name];
    local success_data: Data = [$visible_string="write-value"];
    local failure_data: Data = [$visible_string="bad-value"];
    local list_data: Data = [$boolean=T];
    local success_response: Write_Response;
    local failure_response: Write_Response;
    success_response[0] = [$success=T];
    failure_response[0] = [$failure=DataAccessError_object_access_denied];

    local success_variables: vector of record {
        variableSpecification: VariableSpecification;
        alternateAccess: AlternateAccess &optional;
    };
    local failure_variables: vector of record {
        variableSpecification: VariableSpecification;
        alternateAccess: AlternateAccess &optional;
    };
    success_variables[0] = [$variableSpecification=success_spec];
    failure_variables[0] = [$variableSpecification=failure_spec];

    local success_request: Write_Request = [
        $variableAccessSpecificatn=[$listOfVariable=success_variables],
        $listOfData=vector(success_data)
    ];
    event writeRequest(c, "orig_to_resp", 111, success_request);
    event writeResponse(c, "resp_to_orig", 111, success_response);

    local failure_request: Write_Request = [
        $variableAccessSpecificatn=[$listOfVariable=failure_variables],
        $listOfData=vector(failure_data)
    ];
    event writeRequest(c, "orig_to_resp", 112, failure_request);
    event writeResponse(c, "resp_to_orig", 112, failure_response);

    local list_request: Write_Request = [
        $variableAccessSpecificatn=[$variableListName=list_name],
        $listOfData=vector(list_data)
    ];
    event writeRequest(c, "orig_to_resp", 113, list_request);
    event writeResponse(c, "resp_to_orig", 113, success_response);
}
