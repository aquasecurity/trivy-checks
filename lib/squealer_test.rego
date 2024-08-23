package lib.squealer_test

import rego.v1

import data.lib.test

test_squealer_secret_not_found if {
	res := squealer.scan_string(`export GREETING="Hello there"`)
	res.transgressionFound == false
}

test_squealer_secret_found if {
	res := squealer.scan_string(`export DATABASE_PASSWORD=\"SomeSortOfPassword\"`)
	res.transgressionFound == true
}
