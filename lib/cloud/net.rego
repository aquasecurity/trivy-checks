# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.net

import rego.v1

ssh_port := 22

rdp_port := 3389

all_ips := {"0.0.0.0/0", "0000:0000:0000:0000:0000:0000:0000:0000/0", "::/0"}

# "-1" or "all" equivalent to all protocols
# https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
# https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#protocol
all_protocols := {"-1", "all"}

# "6" is ID of TCP
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
is_tcp_protocol(protocol) if protocol in {"tcp", "6"}

is_tcp_protocol(protocol) if protocol in all_protocols

# "17" is ID of UDP
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
is_udp_protocol(protocol) if protocol in {"udp", "17"}

is_udp_protocol(protocol) if protocol in all_protocols

is_tcp_or_udp_protocol(protocol) if is_tcp_protocol(protocol)

is_tcp_or_udp_protocol(protocol) if is_udp_protocol(protocol)

# protocol "-1" allows traffic on all ports, regardless of any port range you specify.
# https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
is_ssh_or_rdp_port(rule) if rule.protocol.value in {"-1"}

is_ssh_or_rdp_port(rule) if is_port_range_include(rule.fromport.value, rule.toport.value, ssh_port)

is_ssh_or_rdp_port(rule) if is_port_range_include(rule.fromport.value, rule.toport.value, rdp_port)

is_port_range_include(from, to, port) if {
	from <= port
	port <= to
}

# check if CIDR defines an IP block containing all possible IP addresses
cidr_allows_all_ips(cidr) if cidr in all_ips
