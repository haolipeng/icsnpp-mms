# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/var_access.zeek" %INPUT
# @TEST-EXEC: check-mms-log-contract fields mms_var_access.log operation variable object_path ld ln do da value success diag invoke_id
# @TEST-EXEC: zeek-cut operation variable object_path ld ln do da success invoke_id < mms_var_access.log > object-path.out
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
        $uid="Cobjectpath"
    ];
    }

event zeek_init()
    {
    local c = test_connection();
    local value: Data = [$boolean=T];

    local split_domain: ObjectName = [
        $domain_specific=[$domainId="LD0", $itemId="LLN0$Mod$stVal"]
    ];
    event VariableReadResponse(c, "resp_to_orig", 201, split_domain, value);

    local custom_domain: ObjectName = [
        $domain_specific=[$domainId="LD0", $itemId="VendorCustom"]
    ];
    event VariableReadResponse(c, "resp_to_orig", 202, custom_domain, value);

    local vmd_name: ObjectName = [$vmd_specific="NamedVariable"];
    event VariableReadResponse(c, "resp_to_orig", 203, vmd_name, value);

    local aa_name: ObjectName = [$aa_specific="AssociationVariable"];
    event VariableReadResponse(c, "resp_to_orig", 204, aa_name, value);
    }
