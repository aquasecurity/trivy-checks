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

test_cidrs_cover_all_ips_for_split_ranges if {
	net.cidrs_cover_all_ips(["0.0.0.0/1", "128.0.0.0/1"])
	net.cidrs_cover_all_ips(["::/1", "8000::/1"])
	net.cidrs_cover_all_ips(["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1"])
	net.cidrs_cover_all_ips(["10.0.0.0/8", "0.0.0.0/1", "128.0.0.0/1"])
}

test_cidrs_cover_all_ips_for_partial_ranges if {
	not net.cidrs_cover_all_ips(["0.0.0.0/1"])
	not net.cidrs_cover_all_ips(["0.0.0.0/1", "8000::/1"])
	not net.cidrs_cover_all_ips(["0.0.0.0/1", "128.0.0.0/2"])
	not net.cidrs_cover_all_ips(["VirtualNetwork", "AzureCloud"])
	not net.cidrs_cover_all_ips([])
}

test_all_ips_sources_for_all_ips_source if {
	sources := [{"value": "10.0.0.0/8"}, {"value": "0.0.0.0/0"}]
	net.all_ips_sources(sources) == {{"value": "0.0.0.0/0"}}
}

test_all_ips_sources_for_split_ranges if {
	sources := [{"value": "0.0.0.0/1"}, {"value": "128.0.0.0/1"}]
	net.all_ips_sources(sources) == {{"value": "0.0.0.0/1"}}
}

test_all_ips_sources_for_restricted_sources if {
	sources := [{"value": "0.0.0.0/1"}, {"value": "10.0.0.0/8"}]
	net.all_ips_sources(sources) == set()
	net.all_ips_sources([]) == set()
}

test_cidrs_cover_all_ips_for_mixed_ip_versions if {
	net.cidrs_cover_all_ips(["0.0.0.0/1", "128.0.0.0/1", "::/1"])
	net.cidrs_cover_all_ips(["::/1", "8000::/1", "10.0.0.0/8"])
	not net.cidrs_cover_all_ips(["0.0.0.0/1", "::/1"])
}

test_cidrs_cover_all_ips_next_to_non_cidr_values if {
	net.cidrs_cover_all_ips(["0.0.0.0/1", "VirtualNetwork", "128.0.0.0/1"])
	net.cidrs_cover_all_ips(["0.0.0.0/1", "", "128.0.0.0/1", "*"])
	not net.cidrs_cover_all_ips(["10.0.0.1", "128.0.0.0/1"])
}

test_cidrs_cover_all_ips_for_zero_prefix_with_host_bits if {
	net.cidrs_cover_all_ips(["10.1.2.3/0"])
}
