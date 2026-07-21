# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" "$PACKAGE/main.zeek" %INPUT > zeek.stdout 2> zeek.stderr
# @TEST-EXEC: sed -E -e '/ignoring dynamic plugin OSS::MMS/d' -e 's|^warning in .*/icsnpp-mms/plugin/scripts/|warning in <repo>/plugin/scripts/|' -e 's|^warning in .*/icsnpp-mms/scripts/|warning in <repo>/scripts/|' -e 's|, line [0-9]+:|, line X:|' zeek.stderr > zeek.stderr.normalized
# @TEST-EXEC: btest-diff zeek.stderr.normalized
# @TEST-EXEC: check-mms-log-contract exists mms.log
# @TEST-EXEC: check-mms-log-contract fields mms.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p src_ip dst_ip src_port dst_port result error_code parse_status parse_error deviceVendor deviceModel deviceRevision protocolVersion parameterCBB servicesSupported
# @TEST-EXEC: check-mms-log-contract enum mms.log result success failure unknown not_applicable
# @TEST-EXEC: check-mms-log-contract enum mms.log parse_status ok partial failed not_applicable
# @TEST-EXEC: zeek-cut src_ip dst_ip src_port dst_port < mms.log > endpoints.out
# @TEST-EXEC: btest-diff endpoints.out
# @TEST-EXEC: zeek-cut result error_code parse_status parse_error < mms.log > outcome.out
# @TEST-EXEC: btest-diff outcome.out
# @TEST-EXEC: zeek-cut deviceVendor deviceModel deviceRevision < mms.log > identity.out
# @TEST-EXEC: btest-diff identity.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log src_mac 2> no-src-mac.err
# @TEST-EXEC: cat no-src-mac.err > no-src-mac.out
# @TEST-EXEC: btest-diff no-src-mac.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log dst_mac 2> no-dst-mac.err
# @TEST-EXEC: cat no-dst-mac.err > no-dst-mac.out
# @TEST-EXEC: btest-diff no-dst-mac.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log src_ip_seen 2> no-src-ip-seen.err
# @TEST-EXEC: cat no-src-ip-seen.err > no-src-ip-seen.out
# @TEST-EXEC: btest-diff no-src-ip-seen.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log src_mac_seen 2> no-src-mac-seen.err
# @TEST-EXEC: cat no-src-mac-seen.err > no-src-mac-seen.out
# @TEST-EXEC: btest-diff no-src-mac-seen.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log mms_ip_pair_seen 2> no-mms-ip-pair-seen.err
# @TEST-EXEC: cat no-mms-ip-pair-seen.err > no-mms-ip-pair-seen.out
# @TEST-EXEC: btest-diff no-mms-ip-pair-seen.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log mms_full_pair_seen 2> no-mms-full-pair-seen.err
# @TEST-EXEC: cat no-mms-full-pair-seen.err > no-mms-full-pair-seen.out
# @TEST-EXEC: btest-diff no-mms-full-pair-seen.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log invoke_id 2> no-invoke-id.err
# @TEST-EXEC: cat no-invoke-id.err > no-invoke-id.out
# @TEST-EXEC: btest-diff no-invoke-id.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log object_path 2> no-object-path.err
# @TEST-EXEC: cat no-object-path.err > no-object-path.out
# @TEST-EXEC: btest-diff no-object-path.out
# @TEST-EXEC-FAIL: check-mms-log-contract fields mms.log operation 2> no-operation.err
# @TEST-EXEC: cat no-operation.err > no-operation.out
# @TEST-EXEC: btest-diff no-operation.out
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

    event IdentifyResponse(c, "resp_to_orig", ident);
    event connection_state_remove(c);
    }
