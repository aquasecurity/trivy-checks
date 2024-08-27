# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.aws.iam

import rego.v1

import data.lib.datetime

is_user_logged_in(user) if {
	not datetime.is_never(user.lastaccess.value)
}

user_has_mfa_devices(user) if count(user.mfadevices) > 0

user_is_inactive(user, days) if {
	is_user_logged_in(user)
	datetime.time_diff_gt_days(user.lastaccess.value, days)
}

key_is_unused(key, days) if {
	key.active.value
	datetime.time_diff_gt_days(key.lastaccess.value, days)
}

is_root_user(user) := user.name.value == "root"
