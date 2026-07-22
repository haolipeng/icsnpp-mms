module mms;

@load ./helper

export {
    # 在 Zeek 的 Log::ID 里增加一个 ID，后面 Log::create_stream / Log::write 用其区分日志
    redef enum Log::ID += { LOG_VAA };

    # GetVariableAccessAttributes 一次查询一条记录 → mms_var_attributes.log
    type VAA: record {
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
        variable:   string   &log;
        attributes: string   &log &optional;
        success:    bool     &log;
        diag:       string   &log &optional;
    };

    # 声明日志 event，供 zeek_init 里 Log::create_stream 的 $ev 绑定（不是 MMS 协议事件）：
    #   log_mms_var_attributes — 写变量属性日志时触发，携带 VAA 记录
    # 后面 handler 调用 Log::write 后，Zeek 会先触发该 event，再写入 mms_var_attributes.log
    global log_mms_var_attributes: event(rec: VAA);

    # 变量属性日志总开关（设为 F 可关闭本脚本全部写入）
    const log_var_attributes: bool = T &redef;
}

event zeek_init() &priority=5
{
    # Log::create_stream 注册一条日志流，三个参数含义如下：
    #   $columns — 这条日志有哪些列（用上面的 VAA 定义）
    #   $path     — 输出到哪个文件（mms_var_attributes.log）
    #   $ev       — 每次 Log::write 写日志时，Zeek 先触发哪个 event，再落盘
    Log::create_stream(mms::LOG_VAA, [$columns = VAA, $ev = log_mms_var_attributes, $path="mms_var_attributes"]);
}

# =====================================================================
# 监听 events.zeek 的配对级事件 VariableAccessAttributes
# （GetVariableAccessAttributes 请求与响应按 invokeID 配对后）→ mms_var_attributes.log
# =====================================================================
event VariableAccessAttributes(c: connection, direction: string, invokeID: int, request: GetVariableAccessAttributes_Request, response: GetVariableAccessAttributes_Response) {

    if(!log_var_attributes) return;

    local endpoint_fields = mms_endpoint_fields(c$id);
    local object_fields = mms_object_path_fields(request$name);
    local result_fields = mms_result_fields();

    # 组装日志记录（成功）：变量名来自请求，类型说明来自响应
    local rec=record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $src_ip=endpoint_fields$src_ip,
        $dst_ip=endpoint_fields$dst_ip,
        $src_port=endpoint_fields$src_port,
        $dst_port=endpoint_fields$dst_port,
        $direction=direction,
        $invoke_id=invokeID,
        $operation="get_variable_access_attributes",
        $object_path=object_fields$object_path,
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $variable=objectName_to_string(request$name),
        $attributes=typeSpecification_to_string(response$typeSpecification, objectName_to_string(request$name)),
        $success=T
    );

    Log::write(LOG_VAA, rec);
}

# GetVariableAccessAttributes 失败（confirmed 错误与缓存请求配对后触发）
event VariableAccessAttributesError(c: connection, direction: string, invokeID: int, request: GetVariableAccessAttributes_Request, response: Confirmed_ErrorPDU) {

    if(!log_var_attributes) return;

    local endpoint_fields = mms_endpoint_fields(c$id);
    local object_fields = mms_object_path_fields(request$name);
    local diag = errorClass_to_string(response$serviceError);
    local result_fields = mms_result_fields("failure", mms_service_error_code(diag), diag);

    # 组装日志记录（失败），diag 为服务错误码
    local rec=record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $src_ip=endpoint_fields$src_ip,
        $dst_ip=endpoint_fields$dst_ip,
        $src_port=endpoint_fields$src_port,
        $dst_port=endpoint_fields$dst_port,
        $direction=direction,
        $invoke_id=invokeID,
        $operation="get_variable_access_attributes",
        $object_path=object_fields$object_path,
        $result=result_fields$result,
        $error_code=result_fields$error_code,
        $parse_status=result_fields$parse_status,
        $parse_error=result_fields$parse_error,
        $variable=objectName_to_string(request$name),
        $success=F,
        $diag=diag
    );

    Log::write(LOG_VAA, rec);
}
