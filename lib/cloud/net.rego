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

all_ips := {"0.0.0.0/0", "0000:0000:0000:0000:0000:0000:0000:0000/0", "::/0", "*"}

# Some providers accept a keyword in place of a CIDR. Azure network security groups
# use the "Internet" service tag to mean the public internet address space.
# https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview
all_ips_keywords := {"internet", "any"}

# "-1" or "all" equivalent to all protocols
# https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
# https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#protocol
all_protocols := {"-1", "all"}

# "6" is ID of TCP
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
is_tcp_protocol(p) if protocol(p) in {"tcp", "6"}

is_tcp_protocol(p) if protocol(p) in all_protocols

# "17" is ID of UDP
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
is_udp_protocol(p) if protocol(p) in {"udp", "17"}

is_udp_protocol(p) if protocol(p) in all_protocols

is_tcp_or_udp_protocol(p) if is_tcp_protocol(p)

is_tcp_or_udp_protocol(p) if is_udp_protocol(p)

# protocol "-1" allows traffic on all ports, regardless of any port range you specify.
# https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
is_ssh_or_rdp_port(rule) if protocol(rule.protocol.value) in {"-1", "all"}

is_ssh_or_rdp_port(rule) if is_port_range_include(rule.fromport.value, rule.toport.value, ssh_port)

is_ssh_or_rdp_port(rule) if is_port_range_include(rule.fromport.value, rule.toport.value, rdp_port)

is_port_range_include(from, to, port) if {
	from <= port
	port <= to
}

# check if CIDR defines an IP block containing all possible IP addresses
cidr_allows_all_ips(cidr) if cidr in all_ips

cidr_allows_all_ips(cidr) if lower(cidr) in all_ips_keywords

# check if CIDRs together cover every IPv4 or every IPv6 address,
# e.g. 0.0.0.0/1 and 128.0.0.0/1
cidrs_cover_all_ips(cidrs) if {
	"0.0.0.0/0" in net.cidr_merge(valid_cidrs(cidrs, false))
}

cidrs_cover_all_ips(cidrs) if {
	"::/0" in net.cidr_merge(valid_cidrs(cidrs, true))
}

# valid_cidrs returns the values that are valid CIDRs of one IP version.
# IPv4 and IPv6 are merged separately because net.cidr_merge drops IPv4 ranges
# when the input mixes both, and values such as service tags or bare IPs are
# skipped because they would make the merge undefined or classful.
valid_cidrs(cidrs, ipv6) := [cidr |
	some cidr in cidrs
	net.cidr_is_valid(cidr)
	contains(cidr, ":") == ipv6
]

# all_ips_sources returns the sources to report for a rule that allows all IP addresses:
# the sources that allow all IP addresses on their own, or else the first source
# when the sources together cover every IPv4 or every IPv6 address
all_ips_sources(sources) := matched if {
	matched := {source |
		some source in sources
		cidr_allows_all_ips(source.value)
	}
	count(matched) > 0
} else := {sources[0]} if {
	cidrs_cover_all_ips([source.value | some source in sources])
} else := set()

protocol(v) := lower(v) if is_string(v)

protocol(v) := lower(format_int(v, 10)) if is_number(v)
