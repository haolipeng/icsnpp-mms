# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_var_access.log operation variable object_path result error_code value success diag invoke_id
# @TEST-EXEC: check-mms-log-contract fields mms_varlist_access.log operation listname object_path result error_code listindex value success diag invoke_id
# @TEST-EXEC: zeek-cut operation variable object_path result error_code value success diag invoke_id < mms_var_access.log > var-access.out
# @TEST-EXEC: btest-diff var-access.out
# @TEST-EXEC: zeek-cut operation listname object_path result error_code listindex value success diag invoke_id < mms_varlist_access.log > varlist-access.out
# @TEST-EXEC: btest-diff varlist-access.out

# 验证 read/write 的 ConfirmedError 命中缓存后写入对应业务日志。
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
        $uid="Cconfirmerr"
    ];
}

event zeek_init() {
    local c = test_connection();

    local read_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="LLN0$Mod$stVal"]];
    local read_spec: VariableSpecification = [$name=read_name];
    local read_variables: vector of record {
        variableSpecification: VariableSpecification;
        alternateAccess: AlternateAccess &optional;
    };
    read_variables[0] = [$variableSpecification=read_spec];
    local read_request: Read_Request = [
        $specificationWithResult=F,
        $variableAccessSpecificatn=[$listOfVariable=read_variables]
    ];
    local read_error: Confirmed_ErrorPDU = [
        $invokeID=1001,
        $serviceError=[$errorClass=[$definition=ServiceError_object_undefined]]
    ];

    event readRequest(c, "orig_to_resp", 1001, read_request);
    event confirmedErrorPDU_evt(c, "resp_to_orig", 1001, read_error);

    local read_list_name: ObjectName = [$vmd_specific="ReadDataset"];
    local read_list_request: Read_Request = [
        $specificationWithResult=T,
        $variableAccessSpecificatn=[$variableListName=read_list_name]
    ];
    local read_list_error: Confirmed_ErrorPDU = [
        $invokeID=1002,
        $serviceError=[$errorClass=[$access=ServiceError_object_access_denied]]
    ];

    event readRequest(c, "orig_to_resp", 1002, read_list_request);
    event confirmedErrorPDU_evt(c, "resp_to_orig", 1002, read_list_error);

    local write_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="LLN0$Mod$q"]];
    local write_spec: VariableSpecification = [$name=write_name];
    local write_value: Data = [$boolean=F];
    local write_variables: vector of record {
        variableSpecification: VariableSpecification;
        alternateAccess: AlternateAccess &optional;
    };
    write_variables[0] = [$variableSpecification=write_spec];
    local write_request: Write_Request = [
        $variableAccessSpecificatn=[$listOfVariable=write_variables],
        $listOfData=vector(write_value)
    ];
    local write_error: Confirmed_ErrorPDU = [
        $invokeID=1003,
        $serviceError=[$errorClass=[$access=ServiceError_object_access_unsupported]]
    ];

    event writeRequest(c, "orig_to_resp", 1003, write_request);
    event confirmedErrorPDU_evt(c, "resp_to_orig", 1003, write_error);

    local write_list_name: ObjectName = [$aa_specific="WriteDataset"];
    local write_list_value: Data = [$visible_string="blocked"];
    local write_list_request: Write_Request = [
        $variableAccessSpecificatn=[$variableListName=write_list_name],
        $listOfData=vector(write_list_value)
    ];
    local write_list_error: Confirmed_ErrorPDU = [
        $invokeID=1004,
        $serviceError=[$errorClass=[$access=ServiceError_object_invalidated]]
    ];

    event writeRequest(c, "orig_to_resp", 1004, write_list_request);
    event confirmedErrorPDU_evt(c, "resp_to_orig", 1004, write_list_error);
}
