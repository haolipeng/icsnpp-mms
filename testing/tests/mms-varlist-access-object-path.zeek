# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_varlist_access.log operation listname object_path listindex value success diag invoke_id
# @TEST-EXEC: zeek-cut operation listname object_path listindex success invoke_id < mms_varlist_access.log > object-path.out
# @TEST-EXEC: btest-diff object-path.out

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
        $uid="Cvarlistpath"
    ];
    }

event zeek_init()
    {
    local c = test_connection();
    local value: Data = [$boolean=T];

    local domain_list: ObjectName = [
        $domain_specific=[$domainId="LD0", $itemId="DatasetA"]
    ];
    event VariableListReadResponse(c, "resp_to_orig", 301, domain_list, 2, value);

    local vmd_list: ObjectName = [$vmd_specific="GlobalDataset"];
    event VariableListWriteResponse(c, "resp_to_orig", 302, vmd_list, 3, value);

    local aa_list: ObjectName = [$aa_specific="AssocDataset"];
    event VariableListReport(c, "resp_to_orig", aa_list, 4, value);
    }
