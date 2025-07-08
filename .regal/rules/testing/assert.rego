package custom.regal.rules.assert

eq(expected, got) if not _not_eq(expected, got)

_not_eq(expected, got) if {
	expected != got
	print(sprintf("assert_eq:\n Got %v\n Expected %v", [got, expected]))
}
