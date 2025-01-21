package lib.cmdutil_test

import rego.v1

import data.lib.cmdutil

cmd := ["apk", "-q", "add", "--no-cache", "bash"]

test_is_tool if {
	cmdutil.is_tool(cmd, "apk")
	not cmdutil.is_tool(cmd, "apt")
}

test_is_command if {
	cmdutil.is_command(cmd, "add")
	not cmdutil.is_command(cmd, "apk")
	not cmdutil.is_command(cmd, "bash")
}

test_has_flag if {
	cmdutil.has_flag(cmd, "--no-cache")
	not cmdutil.has_flag(cmd, "--foo")
}
