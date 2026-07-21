# @TEST-EXEC: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/../plugin/scripts/events.zeek" %INPUT > output
# @TEST-EXEC: btest-diff output

module mms;

event IdentifyResponse(c: connection, direction: string, id: Identify_Response)
    {
    print fmt("identify=%s", direction);
    }

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
        $uid="Cdirection"
    ];

    local ident: Identify_Response = [
        $vendorName="Acme",
        $modelName="Relay",
        $revision="1"
    ];

    local response: Confirmed_ResponsePDU = [
        $invokeID=1,
        $confirmedServiceResponse=[$identify=ident]
    ];

    local pdu: MMSpdu = [$confirmed_ResponsePDU=response];

    event mms_pdu(c, T, pdu);
    event mms_pdu(c, F, pdu);
    }
