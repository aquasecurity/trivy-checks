# METADATA
# title: Sensitive Port Is Exposed To Entire Network
# description: |
#   Sensitive legacy ports like Telnet or POP3 should not be open to broad networks.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule
# custom:
#   id: AZU-0074
#   long_id: azure-network-sensitive-port-is-exposed-to-entire-network
#   aliases:
#     - AVD-AZU-0074
#     - sensitive-port-is-exposed-to-entire-network
#     - azure-sensitive-port-is-exposed-to-entire-network
#   provider: azure
#   service: network
#   severity: HIGH
#   minimum_trivy_version: 0.68.0
#   recommended_action: Remove NSG rules allowing legacy or unencrypted protocols on broad scopes.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: azure
#   examples: checks/cloud/azure/network/sensitive_port_exposed_to_network.yaml
package builtin.azure.network.azure0074

import rego.v1

import data.lib.net

# Sensitive ports that should not be exposed to broad networks:
# 20    - FTP data transfer
# 21    - FTP command control
# 23    - Telnet (unencrypted remote access)
# 25    - SMTP (Simple Mail Transfer Protocol)
# 53    - DNS (Domain Name System)
# 110   - POP3 (Post Office Protocol v3)
# 135   - Windows RPC endpoint mapper
# 139   - NetBIOS Session Service
# 143   - IMAP (Internet Message Access Protocol)
# 161   - SNMP (Simple Network Management Protocol)
# 389   - LDAP (Lightweight Directory Access Protocol)
# 636   - LDAPS (LDAP over SSL/TLS)
# 993   - IMAPS (IMAP over SSL/TLS)
# 995   - POP3S (POP3 over SSL/TLS)
# 1433  - Microsoft SQL Server
# 1521  - Oracle database
# 3306  - MySQL database
# 5432  - PostgreSQL database
# 6379  - Redis database
sensitive_ports := {20, 21, 23, 25, 53, 110, 135, 139, 143, 161, 389, 636, 993, 995, 1433, 1521, 3306, 5432, 6379}

deny contains res if {
	some group in input.azure.network.securitygroups
	some rule in group.rules
	rule.allow.value
	not rule.outbound.value
	lower(rule.protocol.value) != "icmp"
	some ports in rule.destinationports
	some sensitive_port in sensitive_ports
	net.is_port_range_include(ports.start.value, ports.end.value, sensitive_port)
	some ip in rule.sourceaddresses
	net.cidr_allows_all_ips(ip.value)
	res := result.new(
		sprintf("Security group rule allows unrestricted ingress to sensitive port %d from any IP address.", [sensitive_port]),
		ip,
	)
}

port_range_includes(from, to, port) if {
	from.value <= port
	port <= to.value
}
