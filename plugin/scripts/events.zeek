@load base/protocols/conn/removal-hooks

module mms;

# =====================================================================
# 按需缓存请求，以便在响应阶段与请求配对、还原变量名等上下文
# （读请求仅在 specificationWithResult 为 false 时写入 mms_read_requests，其余表在请求阶段写入）
# 在 connection 上挂 5 张表，均以 invokeID 为 key
# Cache requests as needed to pair with responses and restore context
# (mms_read_requests only when specificationWithResult is false; other tables on every request).
# Five tables on the connection, all keyed by invokeID.
# =====================================================================
redef record connection += {
    mms_read_requests: table[int] of Read_Request &default=table();
    mms_write_requests: table[int] of Write_Request &default=table();
    mms_name_list_requests: table[int] of GetNameList_Request &default=table();
    mms_get_variable_access_attributes_request: table[int] of GetVariableAccessAttributes_Request &default=table();
    mms_get_named_variable_list_attributes_request: table[int] of GetNamedVariableListAttributes_Request &default=table();
};

export {

    # =====================================================================
    # 服务级事件：mms_pdu 按 PDU 类型分发后触发（Initiate、Confirmed 读写/查询、上报、错误等）
    # Service-level events: raised by mms_pdu after dispatching each PDU type
    # (Initiate, confirmed read/write/query, reports, errors, etc.)
    # =====================================================================
    global initiateRequestPdu: event(c: connection, direction: string, pdu: Initiate_RequestPDU);
    global initiateResponsePdu: event(c: connection, direction: string, pdu: Initiate_ResponsePDU);
    global initiateErrorPdu: event(c: connection, direction: string, pdu: Initiate_ErrorPDU);
    global readRequest: event(c: connection, direction: string, invokeID: int, pdu: Read_Request);
    global writeRequest: event(c: connection, direction: string, invokeID: int, pdu: Write_Request);
    global getNameListRequest: event(c: connection, direction: string, invokeID: int, pdu: GetNameList_Request);
    global getVariableAccessAttributesRequest: event(c: connection, direction: string, invokeID: int, pdu: GetVariableAccessAttributes_Request);
    global getNamedVariableListAttributesRequest: event(c: connection, direction: string, invokeID: int, pdu: GetNamedVariableListAttributes_Request);
    global readResponse: event(c: connection, direction: string, invokeID: int, pdu: Read_Response);
    global writeResponse: event(c: connection, direction: string, invokeID: int, pdu: Write_Response);
    global getNameListResponse: event(c: connection, direction: string, invokeID: int, pdu: GetNameList_Response);
    global getVariableAccessAttributesResponse: event(c: connection, direction: string, invokeID: int, pdu: GetVariableAccessAttributes_Response);
    global getNamedVariableListAttributesResponse: event(c: connection, direction: string, invokeID: int, pdu: GetNamedVariableListAttributes_Response);
    global informationReport_evt: event(c: connection, direction: string, pdu: InformationReport);
    global confirmedErrorPDU_evt: event(c: connection, direction: string, invokeID: int, pdu: Confirmed_ErrorPDU);

    # =====================================================================
    # 见到 identify 响应时触发下列事件
    # The following event is called when an identify response is seen.
    # =====================================================================
    global IdentifyResponse: event (c: connection, direction: string, id: Identify_Response);

    # =====================================================================
    # 变量级事件：在读、写或上报变量（或变量列表）时触发；一个 PDU 可能产生多个此类事件
    # Variable-level events: raised when a variable (or variable list) is read,
    # written, or reported; several such events can arise from one PDU
    # =====================================================================
    global VariableReadRequest: event(c: connection, direction: string, name: ObjectName);
    global VariableListReadRequest: event(c: connection, direction: string, listname: ObjectName);
    global VariableReadResponse: event(c: connection, direction: string, name: ObjectName, data: Data);
    global VariableReadResponseError: event(c: connection, direction: string, name: ObjectName, error: DataAccessError);
    global VariableListReadResponse: event(c: connection, direction: string, listname: ObjectName, listindex: count, data: Data);
    global VariableListReadResponseError: event(c: connection, direction: string, listname: ObjectName, listindex: count, error: DataAccessError);

    global VariableWriteRequest: event(c: connection, direction: string, name: ObjectName, data: Data);
    global VariableListWriteRequest: event(c: connection, direction: string, listname: ObjectName, data: Data);
    global VariableWriteResponse: event(c: connection, direction: string, name: ObjectName, data: Data);
    global VariableWriteResponseError: event(c: connection, direction: string, name: ObjectName, data: Data, error: DataAccessError);
    global VariableListWriteResponse: event(c: connection, direction: string, listname: ObjectName, listindex: count, data: Data);
    global VariableListWriteResponseError: event(c: connection, direction: string, listname: ObjectName, listindex: count, data: Data, error: DataAccessError);

    global VariableReport: event(c: connection, direction: string, name: ObjectName, data: Data);
    global VariableReportError: event(c: connection, direction: string, name: ObjectName, error: DataAccessError);
    global VariableListReport: event(c: connection, direction: string, listname: ObjectName, listindex: count, data: Data);
    global VariableListReportError: event(c: connection, direction: string, listname: ObjectName, listindex: count, error: DataAccessError);

    # =====================================================================
    # 配对级事件：invokeID 在缓存中命中时，将请求与响应（或错误）一并触发
    # Paired events: request and response (or error) emitted together when invokeID
    # matches a cached request
    # =====================================================================
    global NameList: event(c: connection, direction: string, request: GetNameList_Request, response: GetNameList_Response);
    global NameListError: event (c: connection, direction: string, request: GetNameList_Request, response: Confirmed_ErrorPDU);

    global VariableAccessAttributes: event(c: connection, direction: string, request: GetVariableAccessAttributes_Request, response: GetVariableAccessAttributes_Response);
    global VariableAccessAttributesError: event(c: connection, direction: string, request: GetVariableAccessAttributes_Request, response: Confirmed_ErrorPDU);

    global NamedVariableListAttributes: event(c: connection, direction: string, request: GetNamedVariableListAttributes_Request, response: GetNamedVariableListAttributes_Response);
    global NamedVariableListAttributesError: event(c: connection, direction: string, request: GetNamedVariableListAttributes_Request, response: Confirmed_ErrorPDU);
}

# =====================================================================
# 将通用 MMSpdu 映射为其所包含的具体 PDU 类型
# Mapping of a general MMSpdu to the respective PDU type it contains
# =====================================================================
event mms::mms_pdu(c: connection, is_orig: bool, pdu: MMSpdu) {
    local direction = is_orig ? "orig_to_resp" : "resp_to_orig";

    # Initiate 阶段（MMS 会话建立，非底层 TCP 连接）
    # Initiate phase (MMS session establishment, not the underlying transport connection)
    if(pdu ?$ initiate_RequestPDU) {
        event initiateRequestPdu(
            c,
            direction,
            pdu $ initiate_RequestPDU
        );
    } else if(pdu ?$ initiate_ResponsePDU) {
        event initiateResponsePdu(
            c,
            direction,
            pdu $ initiate_ResponsePDU
        );
    } else if(pdu ?$ initiate_ErrorPDU) {
        event initiateErrorPdu(
            c,
            direction,
            pdu $ initiate_ErrorPDU
        );
    # Confirmed 请求：按服务类型分发，携带 invokeID
    # Confirmed request: dispatch by service type, carrying invokeID
    } else if(pdu ?$ confirmed_RequestPDU) {
        if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ read) {
            event readRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ read
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ write) {
            event writeRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ write
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ getNameList) {
            event getNameListRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ getNameList
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ getVariableAccessAttributes) {
            event getVariableAccessAttributesRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ getVariableAccessAttributes
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ getNamedVariableListAttributes) {
            event getNamedVariableListAttributesRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ getNamedVariableListAttributes
            );
        }
    # Confirmed 响应：按服务类型分发；多数服务凭 invokeID 与请求配对（identify 除外）
    # Confirmed response: dispatch by service type; invokeID pairs with request for most
    # services (identify is an exception — IdentifyResponse carries no invokeID)
    } else if(pdu ?$ confirmed_ResponsePDU) {
        if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ read) {
            event readResponse(
                c,
                direction,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ read
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ write) {
            event writeResponse(
                c,
                direction,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ write
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ getNameList) {
            event getNameListResponse(
                c,
                direction,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ getNameList
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ getVariableAccessAttributes) {
            event getVariableAccessAttributesResponse(
                c,
                direction,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ getVariableAccessAttributes
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ getNamedVariableListAttributes) {
            event getNamedVariableListAttributesResponse(
                c,
                direction,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ getNamedVariableListAttributes
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ identify) {
            event IdentifyResponse(
                c,
                direction,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ identify
            );
        }

    # Confirmed 错误
    # Confirmed error
    } else if(pdu ?$ confirmed_ErrorPDU) {
        event confirmedErrorPDU_evt(
            c,
            direction,
            pdu $ confirmed_ErrorPDU $ invokeID,
            pdu $ confirmed_ErrorPDU
        );
    # Unconfirmed PDU 中的 informationReport（无 invokeID；其他 unconfirmed 服务未实现）
    # informationReport inside unconfirmed_PDU (no invokeID; other unconfirmed services not handled)
    } else if(pdu ?$ unconfirmed_PDU) {
        event informationReport_evt(
            c,
            direction,
            pdu $ unconfirmed_PDU $ unconfirmedService $ informationReport
        );
    }

}

# =====================================================================
# 将 Read_Request PDU 映射为（可能多个）VariableReadRequest 或 VariableListReadRequest 事件
# Mapping a Read_Request pdu to (possible multiple) VariableReadRequest
# or VariableListReadRequest events
# =====================================================================
event readRequest(c: connection, direction: string, invokeID: int, pdu: Read_Request) {
    # 当 specificationWithResult 为 false 时，响应按规定不带 variableAccessSpecificatn，
    # readResponse 需按 invokeID 从本表取回整份 Read_Request
    # When specificationWithResult is false, the response omits variableAccessSpecificatn;
    # readResponse must look up the full Read_Request from this table by invokeID
    
    # 当 specificationWithResult 为 false 时，用 invokeID 作 key，把整个读请求存进 c$mms_read_requests
    if (! pdu $ specificationWithResult) {
        c $ mms_read_requests[invokeID] = pdu;
    }

    # 读取多个独立变量
    if (pdu $ variableAccessSpecificatn ?$ listOfVariable) {
        for (i in pdu $ variableAccessSpecificatn $ listOfVariable) {
            event VariableReadRequest(c, direction, pdu $ variableAccessSpecificatn $ listOfVariable[i] $ variableSpecification $ name);
        }
    }
    # 读取变量列表
    if (pdu $ variableAccessSpecificatn ?$ variableListName) {
        event VariableListReadRequest(c, direction, pdu $ variableAccessSpecificatn $ variableListName);
    }
}

# =====================================================================
# 将 Read_Response PDU 映射为（可能多个）VariableReadResponse、VariableReadResponseError、
# VariableListReadResponse 或 VariableListReadResponseError 事件
# Mapping a Read_Response pdu to (possible multiple) VariableReadResponse
# VariableReadResponseError, VariableListReadResponse or
# VariableListReadResponseError
# =====================================================================
event readResponse(c: connection, direction: string, invokeID: int, pdu: Read_Response) {
    # 若 invokeID 在 c$mms_read_requests 中（即请求时 specificationWithResult 为 false），
    # 从缓存的 Read_Request 取 variableAccessSpecificatn；否则用响应 pdu 中的字段
    # If invokeID is in c$mms_read_requests (request had specificationWithResult false),
    # take variableAccessSpecificatn from the cached Read_Request; else use the response pdu
    local name: ObjectName;
    local vas = invokeID in c $ mms_read_requests
       ? c $ mms_read_requests[invokeID] $ variableAccessSpecificatn
       : pdu $ variableAccessSpecificatn;
    for (i in pdu $ listOfAccessResult) {
        # vas 里是 listOfVariable？
        if(vas ?$ listOfVariable) {
            # 是，取第 i 个变量名 name
            name = vas $ listOfVariable[i] $ variableSpecification $ name;
            if ( pdu $ listOfAccessResult[i] ?$ success) {
                 event VariableReadResponse(c, direction, name, pdu $ listOfAccessResult[i] $ success);
            } else {
                 event VariableReadResponseError(c, direction, name, pdu $ listOfAccessResult[i] $ failure);
            }
        } else {
            # 否（vas 无 listOfVariable），按 variableListName 路径处理
            # No listOfVariable in vas — use the variableListName branch
            name = vas $ variableListName;
            # 判断第i个读结果是成功还是失败
            if ( pdu $ listOfAccessResult[i] ?$ success) {
                 event VariableListReadResponse(c, direction, name, i, pdu $ listOfAccessResult[i] $ success);
            } else {
                 event VariableListReadResponseError(c, direction, name, i, pdu $ listOfAccessResult[i] $ failure);
            }
        }
    }
}

# =====================================================================
# 将 Write_Request PDU 映射为（可能多个）VariableWriteRequest 或 VariableListWriteRequest 事件
# Mapping a Write_Request pdu to (possible multiple) VariableWriteRequest
# or VariableListWriteRequest events
# =====================================================================
event writeRequest(c: connection, direction: string, invokeID: int, pdu: Write_Request) {
    # 整份请求按 invokeID 存表（给writeResponse用）
    c $ mms_write_requests[invokeID] = pdu;
    # 当 variableAccessSpecificatn 含 listOfVariable 时，逐个触发 VariableWriteRequest
    for (i in pdu $ variableAccessSpecificatn $ listOfVariable) {
        event VariableWriteRequest(
            c,
            direction,
            pdu $ variableAccessSpecificatn $ listOfVariable[i] $ variableSpecification $ name,
            pdu $ listOfData[i]
        );
    }
    # 若请求是写变量列表
    if (pdu $ variableAccessSpecificatn ?$ variableListName) {
        event VariableListWriteRequest(
            c,
            direction,
            pdu $ variableAccessSpecificatn $ variableListName,
            pdu $ listOfData[0]
        );
    }
}

# =====================================================================
# 将 Write_Response PDU 映射为（可能多个）VariableWriteResponse、VariableWriteResponseError、
# VariableListWriteResponse 或 VariableListWriteResponseError 事件
# Mapping a Write_Response pdu to (possible multiple) VariableWriteResponse
# VariableWriteResponseError, VariableListWriteResponse or
# VariableListWriteResponseError
# =====================================================================
event writeResponse(c: connection, direction: string, invokeID: int, pdu: Write_Response) {
    if(! (invokeID in c $ mms_write_requests))
        return;
    local request = c $ mms_write_requests[invokeID];
    local name: ObjectName;
    for(i in pdu) {
        if(request $ variableAccessSpecificatn ?$ listOfVariable) {
            name = request $ variableAccessSpecificatn $ listOfVariable[i] $ variableSpecification $ name;
            if(pdu[i] ?$ success) {
                event VariableWriteResponse(c, direction, name, request $ listOfData[i]);
            } else {
                event VariableWriteResponseError(c, direction, name, request $ listOfData[i], pdu[i] $ failure);
            }
        } else {
            name = request $ variableAccessSpecificatn $ variableListName;
            if(pdu[i] ?$ success) {
                event VariableListWriteResponse(c, direction, name, i, request $ listOfData[i]);
            } else {
                event VariableListWriteResponseError(c, direction, name, i, request $ listOfData[i], pdu[i] $ failure);
            }
        }
    }
}

# =====================================================================
# 将 InformationReport PDU 映射为 VariableReport / VariableListReport 等事件
# Mapping an InformationReport pdu to VariableReport or VariableListReport events
# =====================================================================
event informationReport_evt(c: connection, direction: string, pdu: InformationReport) {
    local name: ObjectName;
    for(i in pdu $ listOfAccessResult) {
        if(pdu $ variableAccessSpecification ?$ listOfVariable) {
            name = pdu $ variableAccessSpecification $ listOfVariable[i] $ variableSpecification $ name;
            if(pdu $ listOfAccessResult[i] ?$ success) {
                event VariableReport(c, direction, name, pdu $ listOfAccessResult[i] $ success);
            } else {
                event VariableReportError(c, direction, name, pdu $ listOfAccessResult[i] $ failure);
            }
        } else {
            name = pdu $ variableAccessSpecification $ variableListName;
            if(pdu $ listOfAccessResult[i] ?$ success) {
                event VariableListReport(c, direction, name, i, pdu $ listOfAccessResult[i] $ success);
            } else {
                event VariableListReportError(c, direction, name, i, pdu $ listOfAccessResult[i] $ failure);
            }
        }
    }
}

# =====================================================================
# 配对类服务（名称/属性查询）：请求阶段缓存；响应阶段 invokeID 命中缓存时合成 request+response 事件
# Paired request-response services (name/attribute queries): cache on request;
# emit paired events on response when invokeID matches the cached request
# =====================================================================
event getNameListRequest(c: connection, direction: string, invokeID: int, pdu: GetNameList_Request) {
    c $ mms_name_list_requests[invokeID] = pdu;
}

event getNameListResponse(c: connection, direction: string, invokeID: int, pdu: GetNameList_Response) {
    if(invokeID in c $ mms_name_list_requests)
        event NameList(c, direction, c $ mms_name_list_requests[invokeID], pdu);
}

event getVariableAccessAttributesRequest(c: connection, direction: string, invokeID: int, pdu: GetVariableAccessAttributes_Request) {
    c $ mms_get_variable_access_attributes_request[invokeID] = pdu;
}

event getVariableAccessAttributesResponse(c: connection, direction: string, invokeID: int, pdu: GetVariableAccessAttributes_Response) {
    if(invokeID in c $ mms_get_variable_access_attributes_request)
        event VariableAccessAttributes(c, direction, c $ mms_get_variable_access_attributes_request[invokeID], pdu);
}

event getNamedVariableListAttributesRequest(c: connection, direction: string, invokeID: int, pdu: GetNamedVariableListAttributes_Request) {
    c $ mms_get_named_variable_list_attributes_request[invokeID] = pdu;
}

event getNamedVariableListAttributesResponse(c: connection, direction: string, invokeID: int, pdu: GetNamedVariableListAttributes_Response) {
    if(invokeID in c $ mms_get_named_variable_list_attributes_request)
        event NamedVariableListAttributes(c, direction, c $ mms_get_named_variable_list_attributes_request[invokeID], pdu);
}

# =====================================================================
# 按 invokeID 查表，将 confirmed 错误与已缓存的名称/属性查询请求配对（不含读/写）
# Look up cached name/attribute query requests by invokeID and emit the matching
# error event (read/write confirmed errors are not handled here)
# =====================================================================
event confirmedErrorPDU_evt(c: connection, direction: string, invokeID: int, pdu: Confirmed_ErrorPDU) {
    if(invokeID in c $ mms_get_variable_access_attributes_request)
        event VariableAccessAttributesError(c, direction, c $ mms_get_variable_access_attributes_request[invokeID], pdu);
    else if(invokeID in c $ mms_name_list_requests)
        event NameListError(c, direction, c $ mms_name_list_requests[invokeID], pdu);
    else if(invokeID in c $ mms_get_named_variable_list_attributes_request)
        event NamedVariableListAttributesError(c, direction, c $ mms_get_named_variable_list_attributes_request[invokeID], pdu);
}
