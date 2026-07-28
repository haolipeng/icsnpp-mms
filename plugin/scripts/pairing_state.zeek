module mms;

# MMS 配对模块持有的连接级请求缓存。
redef record connection += {
    mms_read_requests: table[int] of Read_Request &default=table();
    mms_read_confirmed_error_requests: table[int] of Read_Request &default=table();
    mms_write_requests: table[int] of Write_Request &default=table();
    mms_name_list_requests: table[int] of GetNameList_Request &default=table();
    mms_get_variable_access_attributes_request: table[int] of GetVariableAccessAttributes_Request &default=table();
    mms_get_named_variable_list_attributes_request: table[int] of GetNamedVariableListAttributes_Request &default=table();
    mms_file_open_requests: table[int] of FileOpen_Request &optional;
    mms_file_close_requests: table[int] of FileClose_Request &optional;
};
