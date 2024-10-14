# METADATA
# title: SSL connections to a SQL database instance should be enforced.
# description: |
#   In-transit data should be encrypted so that if traffic is intercepted data will not be exposed in plaintext to attackers.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/sql/docs/mysql/configure-ssl-instance
# custom:
#   id: AVD-GCP-0015
#   avd_id: AVD-GCP-0015
#   provider: google
#   service: sql
#   severity: HIGH
#   short_code: encrypt-in-transit-data
#   recommended_action: Enforce SSL for all connections
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
#     good_examples: checks/cloud/google/sql/encrypt_in_transit_data.yaml
#     bad_examples: checks/cloud/google/sql/encrypt_in_transit_data.yaml
package builtin.google.sql.google0015

import rego.v1

import data.lib.cloud.value

ssl_mode_trusted_client_certificate_required := "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"

deny contains res if {
	some instance in input.google.sql.instances
	not is_ssl_enforced(instance.settings.ipconfiguration)
	res := result.new(
		"Database instance does not require TLS for all connections.",
		instance.settings.ipconfiguration,
	)
}

# sslMode=ENCRYPTED_ONLY also allows SSL/TLS encrypted connections,
# but the client certificate is not validated as in the case of `requiretls`.
# https://cloud.google.com/sql/docs/postgres/admin-api/rest/v1beta4/instances#sslmode
is_ssl_enforced(ipconf) if {
	ipconf.sslmode.value == ssl_mode_trusted_client_certificate_required
}

# "sslMode" has been added to replace "requireSsl", but we still have to support
# the deprecated attribute for users using an older version of the provider
is_ssl_enforced(ipconf) if {
	not has_ssl_mode(ipconf)
	ipconf.requiretls.value == true
}

has_ssl_mode(ipconf) if not value.is_empty(ipconf.sslmode)
