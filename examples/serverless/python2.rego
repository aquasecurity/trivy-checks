# METADATA
# title: Avoid using Python 2 as provider runtime
# description: |
#   Python 2 is deprecated and no longer receives security updates.
#   Using any version of Python 2 as the runtime for your provider poses significant risks,
#   including exposure to vulnerabilities and lack of support for modern libraries.
#
#   Ensure that you use a supported runtime version, such as Python 3.x,
#   to maintain the security and reliability of your serverless application.
# scope: package
# related_resources:
#   - https://www.python.org/doc/sunset-python-2/
# custom:
#   id: USR-SERVERLESS-0001
#   avd_id: USR-SERVERLESS-0001
#   provider: generic
#   severity: HIGH
#   short_code: avoid-python2
#   recommended_action: Update your provider runtime to a supported Python 3.x version.
#   input:
#     selector:
#       - type: yaml
package user.serverless.avoid_python2

import rego.v1

deny contains res if {
	startswith(input.provider.runtime, "python2")
	res := result.new(
		sprintf("Python 2 (%s) should not be the default provider runtime.", [input.provider.runtime]),
		{},
	)
}
