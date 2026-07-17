#include "Analyzer.h"
#include "Plugin.h"
#include "process.h"
#include "events.bif.h"

#include <zeek/analyzer/Manager.h>

using namespace zeek;

namespace zeek::plugin::mms {

Analyzer::Analyzer(const char* name, zeek::Connection* c) : zeek::analyzer::Analyzer(name, c) {}

/*
MMS数据解析入口
data：指向本次MMS数据的指针
len: 本次MMS数据的长度
orig: 数据方向：true 表示来自连接发起方（client/originator），false 表示来自响应方。
*/

void Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t, const IP_Hdr*, int) {
    //1. asn.1解码后填写的 C 结构指针，初始为 NULL
    MMSpdu *pdu_raw = NULL;
    auto desc = &asn_DEF_MMSpdu;//指向 MMSpdu 的 ASN.1 类型描述符

    //2. BER解码
    asn_dec_rval_t rval = ber_decode(nullptr, desc, reinterpret_cast<void**>(&pdu_raw), data, len);
    if(rval.code != RC_OK) {
        //失败记录mms_parse_error，并直接返回
        Weird("mms_parse_error", "unable to parse packet");
        return;
    }
    // For debugging purposes
    //asn_fprint(stdout, desc, pdu_raw);

    //3. ASN.1 约束检查
    char errbuf[128];
    size_t errlen = sizeof(errbuf)/sizeof(errbuf[0]);
    if(asn_check_constraints(desc, pdu_raw, errbuf, &errlen)) {
        Weird("mms_constraint_error", errbuf);
        desc->free_struct(desc, pdu_raw, 0);
        return;
    }

    //4. 把MMSpdu C 结构转换为zeek Val类型
    auto pdu=process_MMSpdu(pdu_raw);

    //5. 释放pdu_raw
    desc->free_struct(desc, pdu_raw, 0);
    
    //6. 将解析结果投递到Zeek脚本层，Conn()为当前连接，orig为数据方向，pdu为转换后的Zeek值
    zeek::BifEvent::mms::enqueue_mms_pdu(this, Conn(), orig, pdu);
}

} // namespace zeek::plugin::mms
