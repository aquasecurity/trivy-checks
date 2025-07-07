# METADATA
# title: No threat detections are set
# description: |
#   SQL Server can alert for security issues including SQL Injection, vulnerabilities, access anomalies and data exfiltration. Ensure none of these are disabled to benefit from the best protection
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0028
#   avd_id: AVD-AZU-0028
#   provider: azure
#   service: database
#   severity: MEDIUM
#   short_code: all-threat-alerts-enabled
#   recommended_action: Use all provided threat alerts
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   examples: checks/cloud/azure/database/all_threat_alerts_enabled.yaml
package builtin.azure.database.azure0028

import rego.v1

deny contains res if {
	some server in input.azure.database.mssqlservers
	some policy in server.securityalertpolicies
	count(policy.disabledalerts) > 0
	res := result.new(
		"Server has a security alert policy which disables alerts.",
		policy.disabledalerts[0],
	)
}
