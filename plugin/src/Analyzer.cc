#include "Analyzer.h"
#include "Plugin.h"
#include "process.h"
#include "events.bif.h"

#include <zeek/analyzer/Manager.h>

using namespace zeek;

namespace zeek::plugin::mms {

Analyzer::Analyzer(const char* name, zeek::Connection* c) : zeek::analyzer::Analyzer(name, c) {}

/*
MMS packet analyzer entry point.
data points to the MMS payload for this packet.
len is the MMS payload length.
orig is true for packets from the connection originator/client, and false for
packets from the responder/server.
*/

void Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t, const IP_Hdr*, int) {
    // 1. ASN.1 decoder output pointer, initialized as NULL.
    MMSpdu *pdu_raw = NULL;
    auto desc = &asn_DEF_MMSpdu; // ASN.1 type descriptor for MMSpdu.

    // 2. BER decode.
    asn_dec_rval_t rval = ber_decode(nullptr, desc, reinterpret_cast<void**>(&pdu_raw), data, len);
    if(rval.code != RC_OK) {
        // Record a parse error and stop processing this packet.
        Weird("mms_parse_error", "unable to parse packet");
        return;
    }
    // For debugging purposes
    //asn_fprint(stdout, desc, pdu_raw);

    // 3. ASN.1 constraint validation.
    char errbuf[128];
    size_t errlen = sizeof(errbuf)/sizeof(errbuf[0]);
    if(asn_check_constraints(desc, pdu_raw, errbuf, &errlen)) {
        Weird("mms_constraint_error", errbuf);
        desc->free_struct(desc, pdu_raw, 0);
        return;
    }

    // 4. Convert the MMSpdu C structure into a Zeek value.
    auto pdu=process_MMSpdu(pdu_raw);

    // 5. Release pdu_raw after conversion.
    desc->free_struct(desc, pdu_raw, 0);
    
    // 6. Deliver the decoded PDU to the Zeek script layer.
    zeek::BifEvent::mms::enqueue_mms_pdu(this, Conn(), orig, pdu);
}

} // namespace zeek::plugin::mms
