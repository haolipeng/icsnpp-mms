module mms;

@load ./helper

export {
    # 在 Zeek 的 Log::ID 里增加一个 ID，后面 Log::create_stream / Log::write 用其区分日志
    redef enum Log::ID += { LOG };

    # 一条 MMS 连接一条记录 → mms.log（连接级总账，非逐条读写明细）
    type Info: record {
        ts:                   time    &log;
        uid:                  string  &log;
        id:                   conn_id &log;
        src_ip:               addr    &log;
        dst_ip:               addr    &log;
        src_port:             port    &log;
        dst_port:             port    &log;
        src_mac:              string  &log &optional;
        dst_mac:              string  &log &optional;
        src_ip_seen:          bool    &log &optional;
        src_mac_seen:         bool    &log &optional;
        mms_ip_pair_seen:     bool    &log &optional;
        mms_full_pair_seen:   bool    &log &optional;
        deviceVendor:         string &log &optional;
        deviceModel:          string &log &optional;
        deviceRevision:       string &log &optional;
        protocolVersion:      string &log  &optional;
        parameterCBB:         string &log &optional;
        servicesSupported:    string &log &optional;
    };

    # 在 connection 上挂 mms_info，会话期间按需填充，连接结束时写入 mms.log
    redef record connection += {
        mms_info: Info &optional;
    };

    # 声明日志 event，供 zeek_init 里 Log::create_stream 的 $ev 绑定（不是 MMS 协议事件）：
    #   log_mms — 写连接总账时触发，携带 Info 记录
    # 后面 connection_state_remove 调用 Log::write 后，Zeek 会先触发该 event，再写入 mms.log
    global log_mms: event(rec: Info);
}

# 按需创建并返回 c$mms_info；同一条连接内复用同一 record
function get_info(c: connection): Info {
    if(!c?$mms_info) {
        local endpoint_fields = mms_endpoint_fields(c$id);
        local enrichment = mms_enrichment_fields();
        c$mms_info = [
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $src_ip=endpoint_fields$src_ip,
            $dst_ip=endpoint_fields$dst_ip,
            $src_port=endpoint_fields$src_port,
            $dst_port=endpoint_fields$dst_port
        ];

        if ( enrichment?$src_mac )
            c$mms_info$src_mac = enrichment$src_mac;
        if ( enrichment?$dst_mac )
            c$mms_info$dst_mac = enrichment$dst_mac;
        if ( enrichment?$src_ip_seen )
            c$mms_info$src_ip_seen = enrichment$src_ip_seen;
        if ( enrichment?$src_mac_seen )
            c$mms_info$src_mac_seen = enrichment$src_mac_seen;
        if ( enrichment?$mms_ip_pair_seen )
            c$mms_info$mms_ip_pair_seen = enrichment$mms_ip_pair_seen;
        if ( enrichment?$mms_full_pair_seen )
            c$mms_info$mms_full_pair_seen = enrichment$mms_full_pair_seen;
    }
    return c$mms_info;
}

event zeek_init() &priority=5
{
    # Log::create_stream 注册一条日志流，三个参数含义如下：
    #   $columns — 这条日志有哪些列（用上面的 Info 定义）
    #   $path     — 输出到哪个文件（mms.log）
    #   $ev       — 每次 Log::write 写日志时，Zeek 先触发哪个 event，再落盘
    Log::create_stream(mms::LOG, [$columns = Info, $ev = log_mms, $path="mms"]);
}

# =====================================================================
# 监听 events.zeek 服务级事件，往 c$mms_info 累积设备与会话信息
# =====================================================================

# Identify 响应：填充设备厂商 / 型号 / 版本
event IdentifyResponse(c: connection, id: Identify_Response) {
    local info = get_info(c);

    if(id?$vendorName)
        info$deviceVendor = id$vendorName;
    if(id?$modelName)
        info$deviceModel = id$modelName;
    if(id?$revision)
        info$deviceRevision = id$revision;
}

# Initiate 请求：当前无额外字段写入
event initiateRequestPdu(c: connection, pdu: Initiate_RequestPDU) {
}

# Initiate 响应：填充协商后的协议版本、参数 CBB、支持的服务
event initiateResponsePdu(c: connection, pdu: Initiate_ResponsePDU) {
    local info = get_info(c);

    if(pdu?$mmsInitResponseDetail) {
        if(pdu$mmsInitResponseDetail?$negociatedParameterCBB)
            info$parameterCBB = nice_ParameterCBB(pdu$mmsInitResponseDetail$negociatedParameterCBB);
        if(pdu$mmsInitResponseDetail?$servicesSupportedCalled)
            info$servicesSupported = nice_servicesSupported(pdu$mmsInitResponseDetail$servicesSupportedCalled);
        if(pdu$mmsInitResponseDetail?$negociatedVersionNumber)
            info$protocolVersion = cat(pdu$mmsInitResponseDetail$negociatedVersionNumber);
    }
}

# =====================================================================
# 连接结束时：若有 mms_info 则写入 mms.log，并清理 connection 字段
# =====================================================================
event connection_state_remove(c: connection) {
    if ( c?$mms_info ) {
        Log::write(LOG, c$mms_info);
        delete c$mms_info;
    }
}
