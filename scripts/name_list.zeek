module mms;

@load ./helper

export {
    # 在 Zeek 的 Log::ID 里增加一个 ID，后面 Log::create_stream / Log::write 用其区分日志
    redef enum Log::ID += { LOG_NAMELIST };

    # GetNameList 一次查询一条记录 → mms_name_list.log
    type NameListRecord: record {
        ts:         time     &log;
        uid:        string   &log;
        id:         conn_id  &log;
        src_ip:     addr     &log;
        dst_ip:     addr     &log;
        src_port:   port     &log;
        dst_port:   port     &log;
        direction:  string   &log;
        invoke_id:  int      &log;
        operation:  string   &log;
        object_path: string  &log;
        result:     string   &log;
        error_code: string   &log;
        parse_status: string &log;
        parse_error: string  &log;
        class:      string   &log &optional;
        scope:      string   &log &optional;
        domain:      string   &log &optional;
        value:      string   &log &optional;
        success:    bool     &log;
        diag:       string   &log &optional;
    };

    # 声明日志 event，供 zeek_init 里 Log::create_stream 的 $ev 绑定（不是 MMS 协议事件）：
    #   log_mms_name_list — 写名称列表日志时触发，携带 NameListRecord 记录
    # 后面 handler 调用 Log::write 后，Zeek 会先触发该 event，再写入 mms_name_list.log
    global log_mms_name_list: event(rec: NameListRecord);

    # 名称列表日志总开关（设为 F 可关闭本脚本全部写入）
    const log_name_list: bool = T &redef;
}

# 将 GetNameList 查询范围转换为日志中的 object_path。
function name_list_object_path(scope: string, domain: string): string {
    if(scope == "domainSpecific")
        return "domain:" + domain;
    if(scope == "vmdSpecific")
        return "vmd";
    if(scope == "aaSpecific")
        return "aa";

    return "<unknown>";
}

event zeek_init() &priority=5
{
    # Log::create_stream 注册一条日志流，三个参数含义如下：
    #   $columns — 这条日志有哪些列（用上面的 NameListRecord 定义）
    #   $path     — 输出到哪个文件（mms_name_list.log）
    #   $ev       — 每次 Log::write 写日志时，Zeek 先触发哪个 event，再落盘
    Log::create_stream(mms::LOG_NAMELIST, [$columns = NameListRecord, $ev = log_mms_name_list, $path="mms_name_list"]);
}

# =====================================================================
# 监听 events.zeek 的配对级事件 NameList（GetNameList 请求与响应按 invokeID 配对后）→ mms_name_list.log
# =====================================================================
event NameList(c: connection, direction: string, invokeID: int, request: GetNameList_Request, response: GetNameList_Response) {
    local scope: string = "";
    local value: string = "";
    local class: string = "";
    local domain: string = "";

    if(!log_name_list) return;

    # 从 GetNameList 请求取对象类（request$extendedObjectClass$objectClass）
    # cat 转字符串，remove_ns 去掉 mms:: 前缀，写入 class
    class = remove_ns(cat(request $ extendedObjectClass $ objectClass));

    # 从请求取查询范围：vmdSpecific / aaSpecific / domainSpecific
    if(request $ objectScope ?$ vmdSpecific) {
        scope="vmdSpecific";
    } else if(request $ objectScope ?$ aaSpecific) {
        scope="aaSpecific";
    } else {
        scope="domainSpecific";
        domain=request $ objectScope $ domainSpecific;
    }

    # 将响应中的标识符列表拼成 JSON 数组字符串
    value = "[";
    for(i in response $ listOfIdentifier) {
        if(i!=0)
            value+=",";
        value+=to_json(response $ listOfIdentifier[i]);
    }
    value += "]";

    local endpoint_fields = mms_endpoint_fields(c$id);
    local result_fields = mms_result_fields();

    # 组装日志记录（成功）；可选字段仅在非空时写入
    local rec: NameListRecord = record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $src_ip=endpoint_fields$src_ip,
        $dst_ip=endpoint_fields$dst_ip,
        $src_port=endpoint_fields$src_port,
        $dst_port=endpoint_fields$dst_port,
        $direction=direction,
        $invoke_id=invokeID,
        $operation="get_name_list",
        $object_path=name_list_object_path(scope, domain),
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $success=T
    );

    if(|class| > 0) {
        rec$class = class;
    }

    if(|scope| > 0) {
        rec$scope = scope;
    }

    if(|domain| > 0) {
        rec$domain = domain;
    }
    
    # value字符串的长度大于2，才将value值进行写入
    if(|value| > 2) {
        rec$value = value;
    }

    Log::write(LOG_NAMELIST, rec);
}

# GetNameList 失败（confirmed 错误与缓存请求配对后触发）
event NameListError (c: connection, direction: string, invokeID: int, request: GetNameList_Request, response: Confirmed_ErrorPDU) {
    local scope: string = "";
    local class: string = "";
    local domain: string = "";

    if(!log_name_list) return;

    # 从请求取对象类（extendedObjectClass / objectClass）
    class = remove_ns(cat(request $ extendedObjectClass $ objectClass));

    # 从请求取查询范围：vmdSpecific / aaSpecific / domainSpecific
    if(request $ objectScope ?$ vmdSpecific) {
        scope="vmdSpecific";
    } else if(request $ objectScope ?$ aaSpecific) {
        scope="aaSpecific";
    } else {
        scope="domainSpecific";
        domain=request $ objectScope $ domainSpecific;
    }

    local endpoint_fields = mms_endpoint_fields(c$id);
    local diag = errorClass_to_string(response$serviceError);
    local result_fields = mms_result_fields("failure", mms_service_error_code(diag), diag);

    # 组装日志记录（失败），diag 为服务错误码
    local rec: NameListRecord = record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $src_ip=endpoint_fields$src_ip,
        $dst_ip=endpoint_fields$dst_ip,
        $src_port=endpoint_fields$src_port,
        $dst_port=endpoint_fields$dst_port,
        $direction=direction,
        $invoke_id=invokeID,
        $operation="get_name_list",
        $object_path=name_list_object_path(scope, domain),
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $success=F,
        $diag=diag
    );

    # 可选字段仅在非空时写入
    if(|class| > 0) {
        rec$class = class;
    }

    if(|scope| > 0) {
        rec$scope = scope;
    }

    if(|domain| > 0) {
        rec$domain = domain;
    }

    Log::write(LOG_NAMELIST, rec);
}
