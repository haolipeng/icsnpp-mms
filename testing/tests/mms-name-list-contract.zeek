# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/name_list.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_name_list.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port direction invoke_id operation object_path result error_code diag parse_status parse_error class scope domain value success
# @TEST-EXEC: check-mms-log-contract enum mms_name_list.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_name_list.log parse_status ok partial failed not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms_name_list.log direction orig_to_resp resp_to_orig unknown not_applicable
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port direction invoke_id operation object_path result error_code diag parse_status parse_error class scope domain value success < mms_name_list.log > name-list.out
# @TEST-EXEC: btest-diff name-list.out

# 验证 GetNameList 日志的统一字段契约，并确认成功结果和错误诊断都保留。
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
        $uid="Cnamelist"
    ];
}

event zeek_init() {
    local c = test_connection();

    local domain_request: GetNameList_Request = [
        $extendedObjectClass=[$objectClass=nammedVariable],
        $objectScope=[$domainSpecific="LD0"]
    ];
    local success_response: GetNameList_Response = [
        $listOfIdentifier=vector("LLN0", "MX"),
        $moreFollows=F
    ];

    event getNameListRequest(c, "orig_to_resp", 701, domain_request);
    event getNameListResponse(c, "resp_to_orig", 701, success_response);

    local vmd_request: GetNameList_Request = [
        $extendedObjectClass=[$objectClass=ObjectClass_namedVariableList],
        $objectScope=[$vmdSpecific=T]
    ];
    local error_response: Confirmed_ErrorPDU = [
        $invokeID=702,
        $serviceError=[$errorClass=[$access=ServiceError_object_access_denied]]
    ];

    event getNameListRequest(c, "orig_to_resp", 702, vmd_request);
    event confirmedErrorPDU_evt(c, "resp_to_orig", 702, error_response);
}
