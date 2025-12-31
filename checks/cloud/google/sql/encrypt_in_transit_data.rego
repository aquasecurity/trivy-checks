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
#   id: GCP-0015
#   long_id: google-sql-encrypt-in-transit-data
#   aliases:
#     - AVD-GCP-0015
#     - encrypt-in-transit-data
#   provider: google
#   service: sql
#   severity: HIGH
#   recommended_action: Enforce SSL for all connections
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   examples: checks/cloud/google/sql/encrypt_in_transit_data.yaml
package builtin.google.sql.google0015

import rego.v1

import data.lib.cloud.value

ssl_encrypted_only := "ENCRYPTED_ONLY"
ssl_trusted_cert_required := "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"

valid_ssl_modes := {
	ssl_encrypted_only,
	ssl_trusted_cert_required,
}

deny contains res if {
	some instance in input.google.sql.instances
	not is_ssl_enforced(instance.settings.ipconfiguration)
	res := result.new(
		"Database instance does not require TLS for all connections.",
		instance.settings.ipconfiguration,
	)
}

# https://docs.cloud.google.com/sql/docs/postgres/admin-api/rest/v1/instances#DatabaseInstance.SslMode
is_ssl_enforced(ipconf) if {
	value.is_known(ipconf.sslmode)
	ipconf.sslmode.value in valid_ssl_modes
}

# "sslMode" has been added to replace "requireSsl", but we still have to support
# the deprecated attribute for users using an older version of the provider
is_ssl_enforced(ipconf) if {
	ssl_mode_is_missing(ipconf)
	value.is_true(ipconf.requiretls)
}

ssl_mode_is_missing(ipconf) if not ipconf.sslmode
ssl_mode_is_missing(ipconf) if value.is_empty(ipconf.sslmode)
