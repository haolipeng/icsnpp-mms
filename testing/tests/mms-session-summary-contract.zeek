# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/main.zeek" %INPUT > zeek.stdout 2> zeek.stderr
# @TEST-EXEC: check-mms-log-contract exists mms.log
# @TEST-EXEC: check-mms-log-contract fields mms.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port src_mac dst_mac src_ip_seen src_mac_seen mms_ip_pair_seen mms_full_pair_seen deviceVendor deviceModel deviceRevision protocolVersion parameterCBB servicesSupported
# @TEST-EXEC: check-mms-log-contract empty mms.log src_mac dst_mac src_ip_seen src_mac_seen mms_ip_pair_seen mms_full_pair_seen
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port < mms.log > endpoints.out
# @TEST-EXEC: btest-diff endpoints.out
# @TEST-EXEC: zeek-cut src_mac dst_mac src_ip_seen src_mac_seen mms_ip_pair_seen mms_full_pair_seen < mms.log > enrichment.out
# @TEST-EXEC: btest-diff enrichment.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log invoke_id 2> no-invoke-id.err
# @TEST-EXEC: cat no-invoke-id.err > no-invoke-id.out
# @TEST-EXEC: btest-diff no-invoke-id.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log object_path 2> no-object-path.err
# @TEST-EXEC: cat no-object-path.err > no-object-path.out
# @TEST-EXEC: btest-diff no-object-path.out
# @TEST-EXEC: echo 'session summary contract passed' > output
# @TEST-EXEC: btest-diff output

module mms;

event zeek_init()
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

    local c: connection = [
        $id=id,
        $orig=ep,
        $resp=ep,
        $start_time=network_time(),
        $duration=0sec,
        $service=set("mms"),
        $history="",
        $uid="Cissue4"
    ];

    local ident: Identify_Response = [
        $vendorName="Acme",
        $modelName="Relay",
        $revision="1"
    ];

    event IdentifyResponse(c, ident);
    event connection_state_remove(c);
    }
