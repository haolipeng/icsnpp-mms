# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/varlist_attributes.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_varlist_attributes.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port direction invoke_id operation object_path result error_code diag parse_status parse_error list attributes success
# @TEST-EXEC: check-mms-log-contract enum mms_varlist_attributes.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_varlist_attributes.log parse_status ok partial failed not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_varlist_attributes.log direction orig_to_resp resp_to_orig unknown not_applicable
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction invoke_id operation object_path result error_code diag parse_status parse_error list attributes success < mms_varlist_attributes.log > varlist-attributes.out
# @TEST-EXEC: btest-diff varlist-attributes.out

# 验证 GetNamedVariableListAttributes 日志统一字段契约。
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
        $uid="Cvarlistattr"
    ];
}

event zeek_init() {
    local c = test_connection();

    local list_name: ObjectName = [
        $domain_specific=[$domainId="LD0", $itemId="DatasetA"]
    ];
    local member_name: ObjectName = [
        $domain_specific=[$domainId="LD0", $itemId="LLN0$Mod$stVal"]
    ];
    local member_spec: VariableSpecification = [$name=member_name];
    local success_response: GetNamedVariableListAttributes_Response = [
        $mmsDeletable=F,
        $listOfVariable=vector()
    ];
    success_response$listOfVariable[0] = [$variableSpecification=member_spec];

    event getNamedVariableListAttributesRequest(c, "orig_to_resp", 901, list_name);
    event getNamedVariableListAttributesResponse(c, "resp_to_orig", 901, success_response);

    local error_list: ObjectName = [$vmd_specific="DatasetB"];
    local error_response: Confirmed_ErrorPDU = [
        $invokeID=902,
        $serviceError=[$errorClass=[$access=ServiceError_object_access_denied]]
    ];

    event getNamedVariableListAttributesRequest(c, "orig_to_resp", 902, error_list);
    event confirmedErrorPDU_evt(c, "resp_to_orig", 902, error_response);
}
