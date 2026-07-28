module mms;

@load ./pairing_state

# 负责 MMS invokeID 请求-响应配对状态。

# 将 Read_Request PDU 映射为一个或多个 VariableReadRequest / VariableListReadRequest 事件。
event readRequest(c: connection, direction: string, invokeID: int, pdu: Read_Request) {
    c$mms_read_confirmed_error_requests[invokeID] = pdu;

    # 当 specificationWithResult 为 false 时，响应会省略 variableAccessSpecificatn，
    # readResponse 需要按 invokeID 找回原始 Read_Request。
    if(! pdu$specificationWithResult)
        c$mms_read_requests[invokeID] = pdu;

    if(pdu$variableAccessSpecificatn?$listOfVariable) {
        for(i in pdu$variableAccessSpecificatn$listOfVariable)
            event VariableReadRequest(c, direction, invokeID, pdu$variableAccessSpecificatn$listOfVariable[i]$variableSpecification$name);
    }

    if(pdu$variableAccessSpecificatn?$variableListName)
        event VariableListReadRequest(c, direction, invokeID, pdu$variableAccessSpecificatn$variableListName);
}

# 将 Read_Response PDU 映射为一个或多个读响应或读错误事件。
event readResponse(c: connection, direction: string, invokeID: int, pdu: Read_Response) {
    local name: ObjectName;
    local vas = invokeID in c$mms_read_requests
        ? c$mms_read_requests[invokeID]$variableAccessSpecificatn
        : pdu$variableAccessSpecificatn;

    for(i in pdu$listOfAccessResult) {
        if(vas?$listOfVariable) {
            name = vas$listOfVariable[i]$variableSpecification$name;
            if(pdu$listOfAccessResult[i]?$success)
                event VariableReadResponse(c, direction, invokeID, name, pdu$listOfAccessResult[i]$success);
            else
                event VariableReadResponseError(c, direction, invokeID, name, pdu$listOfAccessResult[i]$failure);
        } else {
            name = vas$variableListName;
            if(pdu$listOfAccessResult[i]?$success)
                event VariableListReadResponse(c, direction, invokeID, name, i, pdu$listOfAccessResult[i]$success);
            else
                event VariableListReadResponseError(c, direction, invokeID, name, i, pdu$listOfAccessResult[i]$failure);
        }
    }
}

# 将 Write_Request PDU 映射为一个或多个 VariableWriteRequest / VariableListWriteRequest 事件。
event writeRequest(c: connection, direction: string, invokeID: int, pdu: Write_Request) {
    c$mms_write_requests[invokeID] = pdu;

    if(pdu$variableAccessSpecificatn?$listOfVariable) {
        for(i in pdu$variableAccessSpecificatn$listOfVariable)
            event VariableWriteRequest(
                c,
                direction,
                invokeID,
                pdu$variableAccessSpecificatn$listOfVariable[i]$variableSpecification$name,
                pdu$listOfData[i]
            );
    }

    if(pdu$variableAccessSpecificatn?$variableListName)
        event VariableListWriteRequest(
            c,
            direction,
            invokeID,
            pdu$variableAccessSpecificatn$variableListName,
            pdu$listOfData[0]
        );
}

# 将 Write_Response PDU 映射为一个或多个写响应或写错误事件。
event writeResponse(c: connection, direction: string, invokeID: int, pdu: Write_Response) {
    if(!(invokeID in c$mms_write_requests))
        return;

    local request = c$mms_write_requests[invokeID];
    local name: ObjectName;
    for(i in pdu) {
        if(request$variableAccessSpecificatn?$listOfVariable) {
            name = request$variableAccessSpecificatn$listOfVariable[i]$variableSpecification$name;
            if(pdu[i]?$success)
                event VariableWriteResponse(c, direction, invokeID, name, request$listOfData[i]);
            else
                event VariableWriteResponseError(c, direction, invokeID, name, request$listOfData[i], pdu[i]$failure);
        } else {
            name = request$variableAccessSpecificatn$variableListName;
            if(pdu[i]?$success)
                event VariableListWriteResponse(c, direction, invokeID, name, i, request$listOfData[i]);
            else
                event VariableListWriteResponseError(c, direction, invokeID, name, i, request$listOfData[i], pdu[i]$failure);
        }
    }
}

# 配对类服务（名称/属性查询）：请求阶段缓存；
# 响应阶段 invokeID 命中缓存时触发配对事件。
event getNameListRequest(c: connection, direction: string, invokeID: int, pdu: GetNameList_Request) {
    c$mms_name_list_requests[invokeID] = pdu;
}

event getNameListResponse(c: connection, direction: string, invokeID: int, pdu: GetNameList_Response) {
    if(invokeID in c$mms_name_list_requests)
        event NameList(c, direction, invokeID, c$mms_name_list_requests[invokeID], pdu);
}

event getVariableAccessAttributesRequest(c: connection, direction: string, invokeID: int, pdu: GetVariableAccessAttributes_Request) {
    c$mms_get_variable_access_attributes_request[invokeID] = pdu;
}

event getVariableAccessAttributesResponse(c: connection, direction: string, invokeID: int, pdu: GetVariableAccessAttributes_Response) {
    if(invokeID in c$mms_get_variable_access_attributes_request)
        event VariableAccessAttributes(c, direction, invokeID, c$mms_get_variable_access_attributes_request[invokeID], pdu);
}

event getNamedVariableListAttributesRequest(c: connection, direction: string, invokeID: int, pdu: GetNamedVariableListAttributes_Request) {
    c$mms_get_named_variable_list_attributes_request[invokeID] = pdu;
}

event getNamedVariableListAttributesResponse(c: connection, direction: string, invokeID: int, pdu: GetNamedVariableListAttributes_Response) {
    if(invokeID in c$mms_get_named_variable_list_attributes_request)
        event NamedVariableListAttributes(c, direction, invokeID, c$mms_get_named_variable_list_attributes_request[invokeID], pdu);
}

event fileOpenRequest(c: connection, direction: string, invokeID: int, pdu: FileOpen_Request) {
    if(! c?$mms_file_open_requests)
        c$mms_file_open_requests = table();

    c$mms_file_open_requests[invokeID] = pdu;
}

event fileCloseRequest(c: connection, direction: string, invokeID: int, pdu: FileClose_Request) {
    if(! c?$mms_file_close_requests)
        c$mms_file_close_requests = table();

    c$mms_file_close_requests[invokeID] = pdu;
}

# 按 invokeID 查找缓存请求，并触发对应的 Confirmed 错误事件。
# 匹配顺序保留原 events.zeek 的路由优先级。
event confirmedErrorPDU_evt(c: connection, direction: string, invokeID: int, pdu: Confirmed_ErrorPDU) {
    if(invokeID in c$mms_read_confirmed_error_requests) {
        local read_request = c$mms_read_confirmed_error_requests[invokeID];
        if(read_request$variableAccessSpecificatn?$listOfVariable) {
            for(i in read_request$variableAccessSpecificatn$listOfVariable)
                event VariableReadConfirmedError(c, direction, invokeID, read_request$variableAccessSpecificatn$listOfVariable[i]$variableSpecification$name, pdu);
        } else {
            event VariableListReadConfirmedError(c, direction, invokeID, read_request$variableAccessSpecificatn$variableListName, 0, pdu);
        }
    } else if(invokeID in c$mms_write_requests) {
        local write_request = c$mms_write_requests[invokeID];
        if(write_request$variableAccessSpecificatn?$listOfVariable) {
            for(i in write_request$variableAccessSpecificatn$listOfVariable)
                event VariableWriteConfirmedError(c, direction, invokeID, write_request$variableAccessSpecificatn$listOfVariable[i]$variableSpecification$name, write_request$listOfData[i], pdu);
        } else {
            event VariableListWriteConfirmedError(c, direction, invokeID, write_request$variableAccessSpecificatn$variableListName, 0, write_request$listOfData[0], pdu);
        }
    } else if(invokeID in c$mms_get_variable_access_attributes_request)
        event VariableAccessAttributesError(c, direction, invokeID, c$mms_get_variable_access_attributes_request[invokeID], pdu);
    else if(invokeID in c$mms_name_list_requests)
        event NameListError(c, direction, invokeID, c$mms_name_list_requests[invokeID], pdu);
    else if(invokeID in c$mms_get_named_variable_list_attributes_request)
        event NamedVariableListAttributesError(c, direction, invokeID, c$mms_get_named_variable_list_attributes_request[invokeID], pdu);
    else
        event UnmatchedConfirmedError(c, direction, invokeID, pdu);
}
