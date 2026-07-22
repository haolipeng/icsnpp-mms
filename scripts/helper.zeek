module mms;

export {
    type MMS_EndpointFields: record {
        src_ip:    addr;
        dst_ip:    addr;
        src_port:  port;
        dst_port:  port;
    };

    type MMS_ResultFields: record {
        result:        string;
        error_code:    string;
        diag:          string &optional;
        parse_status:  string;
        parse_error:   string;
    };

    type MMS_ObjectPathFields: record {
        object_path: string;
        ld:          string &optional;
        ln:          string &optional;
        do:          string &optional;
        da:          string &optional;
    };

    # Parse status is the coarse parsing quality level. Parse error is the
    # concrete reason that explains a non-ok or non-applicable status.
    const mms_parse_status_values: set[string] = {
        "ok",
        "partial",
        "failed",
        "not_applicable"
    };

    const mms_parse_error_values: set[string] = {
        "none",
        "mms_parse_error",
        "mms_constraint_error",
        "pres_parse_error",
        "request_response_unmatched",
        "file_handle_unmatched",
        "iso_stack_incomplete",
        "unknown_parse_error"
    };

    const mms_high_risk_operations: set[string] = {
        "write",
        "file_open",
        "file_delete",
        "obtain_file",
        "start",
        "stop",
        "reset",
        "kill"
    } &redef;

    global mms_endpoint_fields: function(id: conn_id): MMS_EndpointFields;
    global mms_result_fields: function(
        result: string &default="success",
        error_code: string &default="none",
        diag: string &default="",
        parse_status: string &default="ok",
        parse_error: string &default="none"
    ): MMS_ResultFields;
    global mms_is_high_risk_operation: function(operation: string): bool;
    global mms_object_path_fields: function(name: ObjectName): MMS_ObjectPathFields;
}

function mms_endpoint_fields(id: conn_id): MMS_EndpointFields {
    return [
        $src_ip=id$orig_h,
        $dst_ip=id$resp_h,
        $src_port=id$orig_p,
        $dst_port=id$resp_p
    ];
}

function mms_result_fields(
    result: string &default="success",
    error_code: string &default="none",
    diag: string &default="",
    parse_status: string &default="ok",
    parse_error: string &default="none"
): MMS_ResultFields {
    if ( parse_status !in mms_parse_status_values )
        Reporter::fatal(fmt("invalid MMS parse_status: %s", parse_status));

    if ( parse_error !in mms_parse_error_values )
        Reporter::fatal(fmt("invalid MMS parse_error: %s", parse_error));

    local fields: MMS_ResultFields = [
        $result=result,
        $error_code=error_code,
        $parse_status=parse_status,
        $parse_error=parse_error
    ];

    if ( |diag| > 0 )
        fields$diag = diag;

    return fields;
}

function mms_is_high_risk_operation(operation: string): bool {
    return operation in mms_high_risk_operations;
}

function remove_ns(val: string): string {
    local parts = split_string(val, /::/);
    local len = |parts|;
    if(len < 2)
        return val;
    return parts[len - 1];
}

function nice_ParameterCBB(vec: ParameterSupportOptions): string {
    local str = "";
    for(i in vec) {
        str += remove_ns(cat(vec[i]));
        if(i < |vec|-1) str += ",";
    }
    return clean(str);
}

function nice_servicesSupported(vec: ServiceSupportOptions): string {
    local str = "";
    for(i in vec) {
        str += remove_ns(cat(vec[i]));
        if(i < |vec|-1) str += ",";
    }
    return clean(str);
}

function data_to_string(data: Data): string {
    local val: string="";
    local val_t: string="";

    if(data?$array) {
        val+="[";
        for(i in data$array) {
            if(i!=0)
                val+=",";
            val+=data_to_string(data $ array[i]);
        }
        val+="]";
        val_t = "array";

        return "{\"type\": \""+val_t+"\", \"values\": "+val+"}";
    }

    if (data?$structure) {
        val+="[";
        for(i in data $ structure) {
            if(i!=0)
                val+=",";
            val+=data_to_string(data$structure[i]);
        }
        val+="]";
        val_t = "structure";

        return "{\"type\": \""+val_t+"\", \"fields\": "+val+"}";
    }

    if(data?$boolean) {
        val = to_json(fmt("%s", data$boolean));
        val_t = "boolean";
    } else if(data?$bit_string) {
        val = to_json("0x" + string_to_ascii_hex(data$bit_string));
        val_t = "bit_string";
    } else if(data?$integer) {
        val = to_json(fmt("%d", data$integer));
        val_t = "integer";
    } else if(data?$unsigned) {
        val = to_json(fmt("%d", data$unsigned));
        val_t = "unsigned";
    } else if(data?$floating_point) {
        val = to_json("0x" + string_to_ascii_hex(data$floating_point));
        val_t = "floating_point";
    } else if(data?$octet_string) {
        val = to_json("0x" + string_to_ascii_hex(data$octet_string));
        val_t = "octet_string";
    } else if(data?$visible_string) {
        val = to_json(data$visible_string);
        val_t = "visible_string";
    } else if(data?$binary_time) {
        val = to_json("0x" + string_to_ascii_hex(data$binary_time));
        val_t = "binary_time";
    } else if(data?$mMSString) {
        val = to_json(data$mMSString);
        val_t = "mms_string";
    } else if(data?$utc_time) {
        val = to_json("0x" + string_to_ascii_hex(data$utc_time));
        val_t = "utc_time";
    } else {
        val = "\"<unknown>\"";
        val_t = "visible_string";
    }

    return "{\"type\": \""+val_t+"\", \"value\": "+val+"}";
}

function objectName_to_string(name: ObjectName): string {
    if(name ?$ vmd_specific) {
        return name $ vmd_specific;
    } else if (name ?$ aa_specific) {
        return name $ aa_specific + " (aa)";
    } else if (name ?$ domain_specific) {
        return  name $ domain_specific $ domainId + "::" + name $ domain_specific $ itemId;
    } else {
        return "<unknown>";
    }
}

function mms_object_path_fields(name: ObjectName): MMS_ObjectPathFields {
    if(name ?$ vmd_specific)
        return [$object_path="vmd:" + name$vmd_specific];

    if(name ?$ aa_specific)
        return [$object_path="aa:" + name$aa_specific];

    if(name ?$ domain_specific) {
        local domain_id = name$domain_specific$domainId;
        local item_id = name$domain_specific$itemId;
        local fields: MMS_ObjectPathFields = [
            $object_path="domain:" + domain_id + "/" + item_id
        ];

        local parts = split_string(item_id, /\$/);
        if(|parts| >= 3) {
            fields$ld = domain_id;
            fields$ln = parts[0];
            fields$do = parts[1];

            local da = "";
            for(i in parts) {
                if(i < 2)
                    next;
                if(|da| > 0)
                    da += ".";
                da += parts[i];
            }
            fields$da = da;
        }

        return fields;
    }

    return [$object_path="<unknown>"];
}

function typeSpecification_to_string(ts: TypeSpecification, fieldName: string &default=""): string {

    local val_f: string="";
    local val_t: string="";
    local val_n: string=fieldName;
    local val_l: string="";

    if(ts ?$ array) {
        val_t = "array";
        val_f += typeSpecification_to_string(ts$array$elementType);
        val_l = cat(ts$array$numberOfElements);

        return "{\"name\": \""+val_n+"\", \"type\": \""+val_t+"\", \"len\": "+val_l+", \"fields\": ["+val_f+"]}";
    }

    if(ts ?$ structure) {
        val_t = "structure";
        for(i in ts$structure$components) {
            local comp = ts$structure$components[i];
            if(i!=0)
                val_f+=",";
            val_f += typeSpecification_to_string(comp$componentType, comp$componentName);
        }

        return "{\"name\": \""+val_n+"\", \"type\": \""+val_t+"\", \"fields\": ["+val_f+"]}";
    }

    if(ts ?$ boolean) {
        val_t = "boolean";
    } else if(ts ?$ bit_string) {
        val_t = "bit_string";
    } else if(ts ?$ integer) {
        val_t = "integer";
    } else if(ts ?$ unsigned) {
        val_t = "unsigned";
    } else if(ts ?$ octet_string) {
        val_t = "octet_string";
    } else if(ts ?$ visible_string) {
        val_t = "visible_string";
    } else {
        val_t = "<unknown>";
    }

    return "{\"name\": \""+val_n+"\", \"type\": \""+val_t+"\"}";
}


function errorClass_to_string(err: ServiceError): string {
    local cls = err$errorClass;
    local str = "";

    if(cls?$vmd_state) {
        str = cat(cls$vmd_state);
    } else if (cls?$application_reference) {
        str = cat(cls$access);
    } else if (cls?$definition) {
        str = cat(cls$definition);
    } else if (cls?$resource) {
        str = cat(cls$resource);
    } else if (cls?$service) {
        str = cat(cls$service);
    } else if (cls?$service_preempt) {
        str = cat(cls$service_preempt);
    } else if (cls?$time_resolution) {
        str = cat(cls$time_resolution);
    } else if (cls?$access) {
        str = cat(cls$access);
    } else if (cls?$initiate) {
        str = cat(cls$initiate);
    } else if (cls?$conclude) {
        str = cat(cls$conclude);
    } else if (cls?$_cancel) {
        str = cat(cls$_cancel);
    } else if (cls?$_file) {
        str = cat(cls$_file);
    } else if (cls?$others) {
        str = cat(cls$others);
    } else {
        str = "<unknown>";
    }

    return remove_ns(str);
}
