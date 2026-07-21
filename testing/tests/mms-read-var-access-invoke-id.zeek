# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_var_access.log operation variable value success diag invoke_id
# @TEST-EXEC: check-mms-log-contract fields mms_varlist_access.log operation listname listindex value success diag invoke_id
# @TEST-EXEC: zeek-cut operation variable value success diag invoke_id < mms_var_access.log > var-access.out
# @TEST-EXEC: btest-diff var-access.out
# @TEST-EXEC: zeek-cut operation listname listindex value success diag invoke_id < mms_varlist_access.log > varlist-access.out
# @TEST-EXEC: btest-diff varlist-access.out

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
        $uid="Creadinvoke"
    ];
    }

event zeek_init()
    {
    local c = test_connection();
    local request_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="ST"]];
    local response_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="MX"]];
    local list_name: ObjectName = [$vmd_specific="datasetA"];
    local request_spec: VariableSpecification = [$name=request_name];
    local response_spec: VariableSpecification = [$name=response_name];
    local cached_data: Data = [$visible_string="cached-value"];
    local list_data: Data = [$boolean=T];
    local cached_result: AccessResult = [$success=cached_data];
    local failure_result: AccessResult = [$failure=DataAccessError_object_access_denied];
    local list_result: AccessResult = [$success=list_data];
    local request_variables: vector of record {
        variableSpecification: VariableSpecification;
        alternateAccess: AlternateAccess &optional;
    };
    local response_variables: vector of record {
        variableSpecification: VariableSpecification;
        alternateAccess: AlternateAccess &optional;
    };
    request_variables[0] = [$variableSpecification=request_spec];
    response_variables[0] = [$variableSpecification=response_spec];

    local cached_request: Read_Request = [
        $specificationWithResult=F,
        $variableAccessSpecificatn=[$listOfVariable=request_variables]
    ];
    event readRequest(c, "orig_to_resp", 77, cached_request);

    local cached_response: Read_Response = [
        $listOfAccessResult=vector(cached_result)
    ];
    event readResponse(c, "resp_to_orig", 77, cached_response);

    local inline_response: Read_Response = [
        $variableAccessSpecificatn=[$listOfVariable=response_variables],
        $listOfAccessResult=vector(failure_result)
    ];
    event readResponse(c, "resp_to_orig", 88, inline_response);

    local list_request: Read_Request = [
        $specificationWithResult=T,
        $variableAccessSpecificatn=[$variableListName=list_name]
    ];
    event readRequest(c, "orig_to_resp", 99, list_request);

    local list_response: Read_Response = [
        $variableAccessSpecificatn=[$variableListName=list_name],
        $listOfAccessResult=vector(list_result)
    ];
    event readResponse(c, "resp_to_orig", 99, list_response);
    }
