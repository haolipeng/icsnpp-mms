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
        object_path: string &log;
        result:    string   &log;
        error_code: string  &log;
        ld:        string   &log &optional;
        ln:        string   &log &optional;
        do:        string   &log &optional;
        da:        string   &log &optional;
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
        object_path: string &log;
        result:    string   &log;
        error_code: string  &log;
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

# 补充单变量日志的 object_path，并尽力拆分 ld/ln/do/da。
function add_object_path_fields(rec: VariableAccess, name: ObjectName): VariableAccess {
    local object_fields = mms_object_path_fields(name);

    rec$object_path = object_fields$object_path;
    if(object_fields?$ld)
        rec$ld = object_fields$ld;
    if(object_fields?$ln)
        rec$ln = object_fields$ln;
    if(object_fields?$do)
        rec$do = object_fields$do;
    if(object_fields?$da)
        rec$da = object_fields$da;

    return rec;
}

# 补充变量列表日志的 object_path，listname/listindex 保持原语义。
function add_varlist_object_path_fields(rec: VariableListAccess, listname: ObjectName): VariableListAccess {
    local object_fields = mms_object_path_fields(listname);
    rec$object_path = object_fields$object_path;

    return rec;
}

# 按 plugin/scripts/types.zeek 中的 DataAccessError 枚举映射为稳定 error_code。
# 未覆盖的枚举统一归为 unknown_error。
function data_access_error_code(error: DataAccessError): string {
    if(error == DataAccessError_object_invalidated)
        return "object_invalidated";
    if(error == hardware_fault)
        return "hardware_fault";
    if(error == temporarily_unavailable)
        return "temporarily_unavailable";
    if(error == DataAccessError_object_access_denied)
        return "object_access_denied";
    if(error == DataAccessError_object_undefined)
        return "object_undefined";
    if(error == DataAccessError_invalid_address)
        return "invalid_address";
    if(error == DataAccessError_type_unsupported)
        return "type_unsupported";
    if(error == DataAccessError_type_inconsistent)
        return "type_inconsistent";
    if(error == DataAccessError_object_attribute_inconsistent)
        return "object_attribute_inconsistent";
    if(error == DataAccessError_object_access_unsupported)
        return "object_access_unsupported";
    if(error == DataAccessError_object_non_existent)
        return "object_non_existent";

    return "unknown_error";
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
        $object_path="",
        $result="success",
        $error_code="none",
        $success=T,
        $invoke_id=invokeID
    ];
    rec = add_object_path_fields(rec, name);

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
        $object_path="",
        $result="success",
        $error_code="none",
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];
    rec = add_object_path_fields(rec, name);

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
        $object_path="",
        $result="success",
        $error_code="none",
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];
    rec = add_object_path_fields(rec, name);

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
        $object_path="",
        $result="success",
        $error_code="none",
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];
    rec = add_object_path_fields(rec, name);

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
        $object_path="",
        $result="failure",
        $error_code=data_access_error_code(error),
        $success=F,
        $diag=remove_ns(cat(error)),
        $invoke_id=invokeID
    ];
    rec = add_object_path_fields(rec, name);

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
        $object_path="",
        $result="failure",
        $error_code=data_access_error_code(error),
        $value=data_to_string(data),
        $success=F,
        $diag=remove_ns(cat(error)),
        $invoke_id=invokeID
    ];
    rec = add_object_path_fields(rec, name);

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
        $object_path="",
        $result="success",
        $error_code="none",
        $listindex=0,
        $success=T,
        $invoke_id=invokeID
    ];
    rec = add_varlist_object_path_fields(rec, listname);

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
        $object_path="",
        $result="success",
        $error_code="none",
        $listindex=listindex,
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];
    rec = add_varlist_object_path_fields(rec, listname);

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
        $object_path="",
        $result="failure",
        $error_code=data_access_error_code(error),
        $listindex=listindex,
        $success=F,
        $diag=remove_ns(cat(error)),
        $invoke_id=invokeID
    ];
    rec = add_varlist_object_path_fields(rec, listname);

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
        $object_path="",
        $result="success",
        $error_code="none",
        $listindex=0,
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];
    rec = add_varlist_object_path_fields(rec, listname);

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
        $object_path="",
        $result="success",
        $error_code="none",
        $listindex=listindex,
        $value=data_to_string(data),
        $success=T,
        $invoke_id=invokeID
    ];
    rec = add_varlist_object_path_fields(rec, listname);

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
        $object_path="",
        $result="failure",
        $error_code=data_access_error_code(error),
        $listindex=listindex,
        $value=data_to_string(data),
        $success=F,
        $diag=remove_ns(cat(error)),
        $invoke_id=invokeID
    ];
    rec = add_varlist_object_path_fields(rec, listname);

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
        $object_path="",
        $result="success",
        $error_code="none",
        $value=data_to_string(data),
        $success=T
    ];
    rec = add_object_path_fields(rec, name);

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
        $object_path="",
        $result="failure",
        $error_code=data_access_error_code(error),
        $success=F,
        $diag=remove_ns(cat(error))
    ];
    rec = add_object_path_fields(rec, name);

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
        $object_path="",
        $result="success",
        $error_code="none",
        $listindex=listindex,
        $value=data_to_string(data),
        $success=T
    ];
    rec = add_varlist_object_path_fields(rec, listname);

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
        $object_path="",
        $result="failure",
        $error_code=data_access_error_code(error),
        $listindex=listindex,
        $success=F,
        $diag=remove_ns(cat(error))
    ];
    rec = add_varlist_object_path_fields(rec, listname);

    Log::write(LOG_VARLIST_ACCESS, rec);
}
