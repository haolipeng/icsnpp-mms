# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/helper.zeek" %INPUT > output
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

    local ep = mms_endpoint_fields(id);
    print fmt("endpoint=%s,%s,%s,%s",
        ep$src_ip,
        ep$dst_ip,
        ep$src_port,
        ep$dst_port);

    local enrichment = mms_enrichment_fields();
    print fmt("enrichment-present=%s,%s,%s,%s,%s,%s",
        enrichment?$src_mac,
        enrichment?$dst_mac,
        enrichment?$src_ip_seen,
        enrichment?$src_mac_seen,
        enrichment?$mms_ip_pair_seen,
        enrichment?$mms_full_pair_seen);

    local outcome = mms_outcome_fields();
    print fmt("outcome=%s,%s,%s,%s,%s",
        outcome$result,
        outcome$error_code,
        outcome?$diag,
        outcome$parse_status,
        outcome$parse_error);

    print fmt("risk=%s,%s",
        mms_is_high_risk_operation("write"),
        mms_is_high_risk_operation("read"));
    }
