# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/name_list.zeek" "$PACKAGE/var_access.zeek" "$PACKAGE/var_attributes.zeek" "$PACKAGE/varlist_attributes.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract exists mms_name_list.log
# @TEST-EXEC: check-mms-log-contract exists mms_var_access.log
# @TEST-EXEC: check-mms-log-contract exists mms_var_attributes.log
# @TEST-EXEC: check-mms-log-contract exists mms_varlist_attributes.log
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction invoke_id operation object_path result error_code diag parse_status parse_error value success < mms_name_list.log > name-list-success.out
# @TEST-EXEC: btest-diff name-list-success.out
# @TEST-EXEC: zeek-cut operation variable object_path result error_code is_high_risk_operation value success diag invoke_id < mms_var_access.log > var-write-success.out
# @TEST-EXEC: btest-diff var-write-success.out
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction invoke_id operation object_path result error_code diag parse_status parse_error variable attributes success < mms_var_attributes.log > var-attributes-success.out
# @TEST-EXEC: btest-diff var-attributes-success.out
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction invoke_id operation object_path result error_code diag parse_status parse_error list attributes success < mms_varlist_attributes.log > varlist-attributes-success.out
# @TEST-EXEC: btest-diff varlist-attributes-success.out

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
        $uid="Csuccess"
    ];
}

event zeek_init() {
    local c = test_connection();

    local name_list_request: GetNameList_Request = [
        $extendedObjectClass=[$objectClass=nammedVariable],
        $objectScope=[$domainSpecific="LD0"]
    ];
    local name_list_response: GetNameList_Response = [
        $listOfIdentifier=vector("LLN0", "MX"),
        $moreFollows=F
    ];

    event getNameListRequest(c, "orig_to_resp", 1001, name_list_request);
    event getNameListResponse(c, "resp_to_orig", 1001, name_list_response);

    local write_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="LLN0$Mod$stVal"]];
    local write_value: Data = [$visible_string="enabled"];
    event VariableWriteResponse(c, "resp_to_orig", 1002, write_name, write_value);

    local var_attr_request: GetVariableAccessAttributes_Request = [
        $name=write_name
    ];
    local var_attr_response: GetVariableAccessAttributes_Response = [
        $mmsDeletable=F,
        $typeSpecification=[$boolean=T]
    ];

    event getVariableAccessAttributesRequest(c, "orig_to_resp", 1003, var_attr_request);
    event getVariableAccessAttributesResponse(c, "resp_to_orig", 1003, var_attr_response);

    local list_name: ObjectName = [
        $domain_specific=[$domainId="LD0", $itemId="DatasetA"]
    ];
    local member_spec: VariableSpecification = [$name=write_name];
    local varlist_attr_response: GetNamedVariableListAttributes_Response = [
        $mmsDeletable=F,
        $listOfVariable=vector()
    ];
    varlist_attr_response$listOfVariable[0] = [$variableSpecification=member_spec];

    event getNamedVariableListAttributesRequest(c, "orig_to_resp", 1004, list_name);
    event getNamedVariableListAttributesResponse(c, "resp_to_orig", 1004, varlist_attr_response);
}
