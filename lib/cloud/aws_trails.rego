# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.aws.trails

import rego.v1

multiregion_log_trails := [
trail |
	some trail in input.aws.cloudtrail.trails
	trail.ismultiregion.value
	trail.islogging.value
]

trails_without_filter(patterns) := trails if {
	trails := [
	trail |
		some trail in multiregion_log_trails
		loggroup := _has_loggroup_for_trail(trail)
		not _has_log_filter(loggroup, patterns)
	]
}

trails_without_alarm_for_filter(patterns) := trails if {
	trails := [
	trail |
		some trail in multiregion_log_trails
		loggroup := _has_loggroup_for_trail(trail)
		filter := _has_log_filter(loggroup, patterns)
		not _has_alarm_for_filter(filter)
	]
}

_has_alarm_for_filter(filter) if {
	some alarm in input.aws.cloudwatch.alarms
	alarm.metricname.value == filter.filtername.value
}

_has_loggroup_for_trail(trail) := loggroup if {
	some loggroup in input.aws.cloudwatch.loggroups
	loggroup.arn.value == trail.cloudwatchlogsloggrouparn.value
}

_has_log_filter(loggroup, patterns) := filter if {
	not is_array(patterns)
	some filter in loggroup.metricfilters
	contains(_cleanup_pattern(filter.filterpattern.value), _cleanup_pattern(patterns))
}

_has_log_filter(loggroup, patterns) := filter if {
	is_array(patterns)
	some filter in loggroup.metricfilters
	some pattern in patterns
	contains(_cleanup_pattern(filter.filterpattern.value), _cleanup_pattern(pattern))
}

_cleanup_pattern(pattern) := regex.replace(pattern, "[\n\t\r ]+", "")
