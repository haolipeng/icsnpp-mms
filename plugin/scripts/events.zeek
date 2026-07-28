@load base/protocols/conn/removal-hooks
# 配对缓存字段必须先声明，随后本文件才能声明并分发其他模块会处理的事件。
@load ./pairing_state

module mms;

# 文件句柄状态属于文件服务行为，不属于 invokeID 配对状态。
redef record connection += {
    mms_file_handles: table[int] of string &optional;
};

export {

    # =====================================================================
    # 服务级事件：mms_pdu 按 PDU 类型分发后触发
    # （Initiate、Confirmed 读写/查询、上报、错误等）。
    # =====================================================================
    global initiateRequestPdu: event(c: connection, direction: string, pdu: Initiate_RequestPDU);
    global initiateResponsePdu: event(c: connection, direction: string, pdu: Initiate_ResponsePDU);
    global initiateErrorPdu: event(c: connection, direction: string, pdu: Initiate_ErrorPDU);
    global readRequest: event(c: connection, direction: string, invokeID: int, pdu: Read_Request);
    global writeRequest: event(c: connection, direction: string, invokeID: int, pdu: Write_Request);
    global getNameListRequest: event(c: connection, direction: string, invokeID: int, pdu: GetNameList_Request);
    global getVariableAccessAttributesRequest: event(c: connection, direction: string, invokeID: int, pdu: GetVariableAccessAttributes_Request);
    global getNamedVariableListAttributesRequest: event(c: connection, direction: string, invokeID: int, pdu: GetNamedVariableListAttributes_Request);
    global fileOpenRequest: event(c: connection, direction: string, invokeID: int, pdu: FileOpen_Request);
    global fileReadRequest: event(c: connection, direction: string, invokeID: int, pdu: FileRead_Request);
    global fileCloseRequest: event(c: connection, direction: string, invokeID: int, pdu: FileClose_Request);
    global fileDeleteRequest: event(c: connection, direction: string, invokeID: int, pdu: FileDelete_Request);
    global fileDirectoryRequest: event(c: connection, direction: string, invokeID: int, pdu: FileDirectory_Request);
    global obtainFileRequest: event(c: connection, direction: string, invokeID: int, pdu: ObtainFile_Request);
    global readResponse: event(c: connection, direction: string, invokeID: int, pdu: Read_Response);
    global writeResponse: event(c: connection, direction: string, invokeID: int, pdu: Write_Response);
    global getNameListResponse: event(c: connection, direction: string, invokeID: int, pdu: GetNameList_Response);
    global getVariableAccessAttributesResponse: event(c: connection, direction: string, invokeID: int, pdu: GetVariableAccessAttributes_Response);
    global getNamedVariableListAttributesResponse: event(c: connection, direction: string, invokeID: int, pdu: GetNamedVariableListAttributes_Response);
    global fileOpenResponse: event(c: connection, direction: string, invokeID: int, pdu: FileOpen_Response);
    global fileCloseResponse: event(c: connection, direction: string, invokeID: int, pdu: FileClose_Response);
    global informationReport_evt: event(c: connection, direction: string, pdu: InformationReport);
    global confirmedErrorPDU_evt: event(c: connection, direction: string, invokeID: int, pdu: Confirmed_ErrorPDU);
    global UnmatchedConfirmedError: event(c: connection, direction: string, invokeID: int, pdu: Confirmed_ErrorPDU);
    global RejectPDU_evt: event(c: connection, direction: string, pdu: RejectPDU);
    global CancelErrorPDU_evt: event(c: connection, direction: string, pdu: Cancel_ErrorPDU);
    global ConcludeErrorPDU_evt: event(c: connection, direction: string, pdu: Conclude_ErrorPDU);

    # =====================================================================
    # 见到 identify 响应时触发下列事件。
    # =====================================================================
    global IdentifyResponse: event (c: connection, direction: string, id: Identify_Response);

    # =====================================================================
    # 变量级事件：在读、写或上报变量（或变量列表）时触发；
    # 一个 PDU 可能产生多个此类事件。
    # =====================================================================
    global VariableReadRequest: event(c: connection, direction: string, invokeID: int, name: ObjectName);
    global VariableListReadRequest: event(c: connection, direction: string, invokeID: int, listname: ObjectName);
    global VariableReadResponse: event(c: connection, direction: string, invokeID: int, name: ObjectName, data: Data);
    global VariableReadResponseError: event(c: connection, direction: string, invokeID: int, name: ObjectName, error: DataAccessError);
    global VariableReadConfirmedError: event(c: connection, direction: string, invokeID: int, name: ObjectName, response: Confirmed_ErrorPDU);
    global VariableListReadResponse: event(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, data: Data);
    global VariableListReadResponseError: event(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, error: DataAccessError);
    global VariableListReadConfirmedError: event(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, response: Confirmed_ErrorPDU);

    global VariableWriteRequest: event(c: connection, direction: string, invokeID: int, name: ObjectName, data: Data);
    global VariableListWriteRequest: event(c: connection, direction: string, invokeID: int, listname: ObjectName, data: Data);
    global VariableWriteResponse: event(c: connection, direction: string, invokeID: int, name: ObjectName, data: Data);
    global VariableWriteResponseError: event(c: connection, direction: string, invokeID: int, name: ObjectName, data: Data, error: DataAccessError);
    global VariableWriteConfirmedError: event(c: connection, direction: string, invokeID: int, name: ObjectName, data: Data, response: Confirmed_ErrorPDU);
    global VariableListWriteResponse: event(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, data: Data);
    global VariableListWriteResponseError: event(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, data: Data, error: DataAccessError);
    global VariableListWriteConfirmedError: event(c: connection, direction: string, invokeID: int, listname: ObjectName, listindex: count, data: Data, response: Confirmed_ErrorPDU);

    global VariableReport: event(c: connection, direction: string, name: ObjectName, data: Data);
    global VariableReportError: event(c: connection, direction: string, name: ObjectName, error: DataAccessError);
    global VariableListReport: event(c: connection, direction: string, listname: ObjectName, listindex: count, data: Data);
    global VariableListReportError: event(c: connection, direction: string, listname: ObjectName, listindex: count, error: DataAccessError);

    # =====================================================================
    # 配对级事件：invokeID 在缓存中命中时，将请求与响应（或错误）一并触发。
    # =====================================================================
    global NameList: event(c: connection, direction: string, invokeID: int, request: GetNameList_Request, response: GetNameList_Response);
    global NameListError: event (c: connection, direction: string, invokeID: int, request: GetNameList_Request, response: Confirmed_ErrorPDU);

    global VariableAccessAttributes: event(c: connection, direction: string, invokeID: int, request: GetVariableAccessAttributes_Request, response: GetVariableAccessAttributes_Response);
    global VariableAccessAttributesError: event(c: connection, direction: string, invokeID: int, request: GetVariableAccessAttributes_Request, response: Confirmed_ErrorPDU);

    global NamedVariableListAttributes: event(c: connection, direction: string, invokeID: int, request: GetNamedVariableListAttributes_Request, response: GetNamedVariableListAttributes_Response);
    global NamedVariableListAttributesError: event(c: connection, direction: string, invokeID: int, request: GetNamedVariableListAttributes_Request, response: Confirmed_ErrorPDU);
}

# =====================================================================
# 将通用 MMSpdu 映射为其所包含的具体 PDU 类型。
# =====================================================================
event mms::mms_pdu(c: connection, is_orig: bool, pdu: MMSpdu) {
    local direction = is_orig ? "orig_to_resp" : "resp_to_orig";

    # Initiate 阶段（MMS 会话建立，非底层 TCP 连接）。
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
    # Confirmed 请求：按服务类型分发，携带 invokeID。
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
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ obtainFile) {
            event obtainFileRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ obtainFile
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ fileOpen) {
            event fileOpenRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ fileOpen
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ fileRead) {
            event fileReadRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ fileRead
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ fileClose) {
            event fileCloseRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ fileClose
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ fileDelete) {
            event fileDeleteRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ fileDelete
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ fileDirectory) {
            event fileDirectoryRequest(
                c,
                direction,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ fileDirectory
            );
        }
    # Confirmed 响应：按服务类型分发；多数服务凭 invokeID 与请求配对
    # （identify 除外，IdentifyResponse 不携带 invokeID）。
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
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ fileOpen) {
            event fileOpenResponse(
                c,
                direction,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ fileOpen
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ fileClose) {
            event fileCloseResponse(
                c,
                direction,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ fileClose
            );
        }

    # Confirmed 错误 PDU。
    } else if(pdu ?$ confirmed_ErrorPDU) {
        event confirmedErrorPDU_evt(
            c,
            direction,
            pdu $ confirmed_ErrorPDU $ invokeID,
            pdu $ confirmed_ErrorPDU
        );
    # Reject PDU：没有 invokeID 缓存可配对，直接输出到通用错误日志。
    } else if(pdu ?$ rejectPDU) {
        event RejectPDU_evt(
            c,
            direction,
            pdu $ rejectPDU
        );
    # Cancel / Conclude 错误：写入通用错误日志。
    } else if(pdu ?$ cancel_ErrorPDU) {
        event CancelErrorPDU_evt(
            c,
            direction,
            pdu $ cancel_ErrorPDU
        );
    } else if(pdu ?$ conclude_ErrorPDU) {
        event ConcludeErrorPDU_evt(
            c,
            direction,
            pdu $ conclude_ErrorPDU
        );
    # Unconfirmed PDU 中的 informationReport（无 invokeID；其他 unconfirmed 服务未实现）。
    } else if(pdu ?$ unconfirmed_PDU) {
        event informationReport_evt(
            c,
            direction,
            pdu $ unconfirmed_PDU $ unconfirmedService $ informationReport
        );
    }

}

# =====================================================================
# 将 InformationReport PDU 映射为 VariableReport / VariableListReport 等事件。
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

# 配对处理器依赖上面导出的事件，因此等事件声明和 mms_pdu 分发器可见后再加载。
@load ./pairing
