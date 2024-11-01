package lib.cloud.metadata_test

import rego.v1

import data.lib.cloud.metadata

test_obj_by_path_happy if {
	bar := with_meta({"value": 1})
	obj := with_meta({"foo": with_meta({"bar": bar})})

	metadata.obj_by_path(obj, ["foo", "bar"]) == bar
}

test_obj_by_path_when_target_not_found_then_return_last_found if {
	foo := with_meta({"bar": with_meta({"value": 1})})
	obj := with_meta({"foo": foo})

	metadata.obj_by_path(obj, ["foo", "baz"]) == foo
}

test_obj_by_path_when_target_not_found_then_return_obj if {
	foo := with_meta({"bar": with_meta({"value": 1})})
	obj := with_meta({"foo": foo})

	metadata.obj_by_path(obj, "baz") == obj
}

test_obj_by_path_skip_without_metadata if {
	obj := with_meta({"foo": {"bar": with_meta({"value": 1})}})

	metadata.obj_by_path(obj, ["foo", "baz"]) == obj
}

test_obj_by_path_happy_iac_type if {
	bar := {"value": 1, "fskey": "somekey"}
	obj := with_meta({"foo": with_meta({"bar": bar})})

	metadata.obj_by_path(obj, ["foo", "bar"]) == bar
}

with_meta(obj) := object.union(obj, {"__defsec_metadata": {}})
