# @TEST-EXEC-FAIL: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/helper.zeek" %INPUT 2> invalid.err
# @TEST-EXEC: sed -n 's/^fatal error .*: \(invalid MMS .*\)$/\1/p' invalid.err > output
# @TEST-EXEC: btest-diff output

module mms;

event zeek_init() {
    local result_fields = mms_result_fields(
        "success",
        "none",
        "",
        "maybe",
        "none");

    print result_fields$parse_status;
}
