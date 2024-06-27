package lib.datetime

import rego.v1

ns_in_day := 86400000000000

zero_time_string := "0001-01-01T00:00:00Z"

time_is_never(string_value) := string_value == zero_time_string

time_diff_gt_days(value, days) := (time.now_ns() - time.parse_rfc3339_ns(value)) > days_to_ns(days)

time_diff_lt_days(value, days) := (time.now_ns() - time.parse_rfc3339_ns(value)) < days_to_ns(days)

days_to_ns(days) := days * ns_in_day
