module mms;

@load ./helper

export {
    # 在 Zeek 的 Log::ID 里增加两个 ID，后面 Log::create_stream / Log::write 用它们区分两条日志
    redef enum Log::ID += { LOG_VAR_ACCESS, LOG_VARLIST_ACCESS };

    # 单变量一条记录 → mms_var_access.log
    type VariableAccess: record {
        ts:        time     &log;
        uid:       string   &log;
        id:        conn_id  &log;
        operation: string   &log;
        variable:  string   &log;
        value:     string   &log &optional;
        success:   bool     &log;
        diag:      string   &log &optional;
        invoke_id: int      &log &optional;
    };

    # 变量列表一项一条记录 → mms_varlist_access.log
    type VariableListAccess: record {
        ts:        time     &log;
        uid:       string   &log;
        id:        conn_id  &log;
        operation: string   &log;
        listname:  string   &log;
        listindex: count    &log;
        value:     string   &log &optional;
        success:   bool     &log;
        diag:      string   &log &optional;
        invoke_id: int      &log &optional;
    };

    # 声明两条日志 event，供 zeek_init 里 Log::create_stream 的 $ev 绑定（不是 MMS 协议事件）：
    #   log_mms_var_access     — 写单变量日志时触发，携带 VariableAccess 记录
    #   log_mms_varlist_access — 写变量列表日志时触发，携带 VariableListAccess 记录
    # 后面 handler 调用 Log::write 后，Zeek 会先触发对应 event，再写入对应的log 文件
    global log_mms_var_access: event(rec: VariableAccess);
    global log_mms_varlist_access: event(rec: VariableListAccess);

    # 变量访问日志总开关（设为 F 可关闭本脚本全部写入）
    const log_var_access: bool = T &redef;
}

event zeek_init() &priority=5
{
    # Log::create_stream 注册一条日志流，三个参数含义如下：
    #   $columns — 这条日志有哪些列（用上面的 VariableAccess 等 record 定义）
    #   $path     — 输出到哪个文件（如 mms_var_access.log）
    #   $ev       — 每次 Log::write 写日志时，Zeek 先触发哪个 event事件，再落盘
    # 单变量 → mms_var_access.log
    Log::create_stream(mms::LOG_VAR_ACCESS, [$columns = VariableAccess, $ev = log_mms_var_access, $path="mms_var_access"]);
    # 变量列表 → mms_varlist_access.log
    Log::create_stream(mms::LOG_VARLIST_ACCESS, [$columns = VariableListAccess, $ev = log_mms_varlist_access, $path="mms_varlist_access"]);
}

# =====================================================================
# 单变量：Confirmed 读/写响应（成功/失败）→ mms_var_access.log
# =====================================================================
event VariableReadRequest(c: connection, direction: string, invokeID: int, name: ObjectName) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read_request",
        $variable=objectName_to_string(name),
        $success=T,
        $invoke_id=invokeID
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableReadResponse(c: connection, direction: string, invokeID: int, name: ObjectName, data: Data) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read",
        $variable=objectName_to_string(name),
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableWriteRequest(c: connection, direction: string, invokeID: int, name: ObjectName, data: Data) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write_request",
        $variable=objectName_to_string(name),
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableWriteResponse(c: connection, direction: string, invokeID: int, name: ObjectName, data: Data) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write",
        $variable=objectName_to_string(name),
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableReadResponseError(c: connection, direction: string, invokeID: int, name: ObjectName, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read",
        $variable=objectName_to_string(name),
        $success=F,
        $diag=remove_ns(cat(error)),
        $invoke_id=invokeID
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableWriteResponseError(c: connection, direction: string, invokeID: int, name: ObjectName, data: Data, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write",
        $variable=objectName_to_string(name),
        $value=data_to_string(data),
        $success=F,
        $diag=remove_ns(cat(error)),
        $invoke_id=invokeID
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}


# =====================================================================
# 变量列表：Confirmed 读/写响应（成功 / 失败）→ mms_varlist_access.log
# =====================================================================
event VariableListReadRequest(c: connection, direction: string, invokeID: int, listname: ObjectName) {

    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read_request",
        $listname=objectName_to_string(listname),
        $listindex=0,
        $success=T,
        $invoke_id=invokeID
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListReadResponse(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, data: Data) {

    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListReadResponseError(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $success=F,
        $diag=remove_ns(cat(error)),
        $invoke_id=invokeID
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListWriteRequest(c: connection, direction: string, invokeID: int, listname: ObjectName, data: Data) {
    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write_request",
        $listname=objectName_to_string(listname),
        $listindex=0,
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListWriteResponse(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, data: Data) {

    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListWriteResponseError(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, data: Data, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $value=data_to_string(data),
        $success=F,
        $diag=remove_ns(cat(error)),
        $invoke_id=invokeID
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}


# =====================================================================
# 单变量 / 变量列表：Unconfirmed informationReport 上报 → 各自日志
# =====================================================================
# InformationReport 属于 Unconfirmed MMS 流量，协议层没有 invoke ID。
# 因此这些日志记录刻意不设置 invoke_id，用空值表达该协议事实。
event VariableReport(c: connection, direction: string, name: ObjectName, data: Data) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="report",
        $variable=objectName_to_string(name),
        $value=data_to_string(data),
        $success=T
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableReportError(c: connection, direction: string, name: ObjectName, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="report",
        $variable=objectName_to_string(name),
        $success=F,
        $diag=remove_ns(cat(error))
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableListReport(c: connection, direction: string, listname: ObjectName, listindex: count, data: Data) {
    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="report",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $value=data_to_string(data),
        $success=T
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListReportError(c: connection, direction: string, listname: ObjectName, listindex: count, error: DataAccessError) {
    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="report",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $success=F,
        $diag=remove_ns(cat(error))
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}
