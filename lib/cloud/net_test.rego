package lib.net_test

import rego.v1

import data.lib.net

test_cidr_allows_all_ips_for_cidr if {
	net.cidr_allows_all_ips("0.0.0.0/0")
	net.cidr_allows_all_ips("::/0")
	net.cidr_allows_all_ips("*")
}

test_cidr_allows_all_ips_for_keyword if {
	net.cidr_allows_all_ips("internet")
	net.cidr_allows_all_ips("Internet")
	net.cidr_allows_all_ips("INTERNET")
	net.cidr_allows_all_ips("any")
	net.cidr_allows_all_ips("Any")
}

test_cidr_allows_all_ips_for_restricted_address if {
	not net.cidr_allows_all_ips("10.0.0.0/16")
	not net.cidr_allows_all_ips("1.2.3.4/32")
	not net.cidr_allows_all_ips("VirtualNetwork")
	not net.cidr_allows_all_ips("AzureCloud")
}
