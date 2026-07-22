# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/var_attributes.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_var_attributes.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port direction invoke_id operation object_path result error_code diag parse_status parse_error variable attributes success
# @TEST-EXEC: check-mms-log-contract enum mms_var_attributes.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_var_attributes.log parse_status ok partial failed not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_var_attributes.log direction orig_to_resp resp_to_orig unknown not_applicable
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction invoke_id operation object_path result error_code diag parse_status parse_error variable attributes success < mms_var_attributes.log > var-attributes.out
# @TEST-EXEC: btest-diff var-attributes.out

# 验证 GetVariableAccessAttributes 日志统一字段契约。
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
        $uid="Cvarattr"
    ];
}

event zeek_init() {
    local c = test_connection();
    local success_name: ObjectName = [$domain_specific=[$domainId="LD0", $itemId="LLN0$Mod$stVal"]];
    local error_name: ObjectName = [$vmd_specific="GlobalVar"];

    local success_request: GetVariableAccessAttributes_Request = [
        $name=success_name
    ];
    local success_response: GetVariableAccessAttributes_Response = [
        $mmsDeletable=F,
        $typeSpecification=[$boolean=T]
    ];

    event getVariableAccessAttributesRequest(c, "orig_to_resp", 801, success_request);
    event getVariableAccessAttributesResponse(c, "resp_to_orig", 801, success_response);

    local error_request: GetVariableAccessAttributes_Request = [
        $name=error_name
    ];
    local error_response: Confirmed_ErrorPDU = [
        $invokeID=802,
        $serviceError=[$errorClass=[$definition=ServiceError_object_undefined]]
    ];

    event getVariableAccessAttributesRequest(c, "orig_to_resp", 802, error_request);
    event confirmedErrorPDU_evt(c, "resp_to_orig", 802, error_response);
}
