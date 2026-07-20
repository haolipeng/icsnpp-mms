# @TEST-EXEC-FAIL: zeek -b "$PACKAGE/../plugin/scripts/__preload__.zeek" "$PACKAGE/helper.zeek" %INPUT 2> invalid.err
# @TEST-EXEC: sed -n 's/^fatal error .*: \(invalid MMS .*\)$/\1/p' invalid.err > output
# @TEST-EXEC: btest-diff output

module mms;

event zeek_init()
    {
    local outcome = mms_outcome_fields(
        "success",
        "none",
        "",
        "ok",
        "mystery");

    print outcome$parse_error;
    }
