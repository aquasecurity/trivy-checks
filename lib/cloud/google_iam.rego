# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.google.iam

import rego.v1

all_members contains member if {
	some key in {"projects", "folders", "organizations"}
	some member in input.google.iam[key][_].members
	isManaged(member)
}

all_bindings contains binding if {
	some key in {"projects", "folders", "organizations"}
	some binding in input.google.iam[key][_].bindings
	isManaged(binding)
}

# Return a list of members for the given resource, e.g. projects, folders, organizations
members(resource) := members if {
	members := [member |
		some member in input.google.iam[resource][_].members
		isManaged(member)
	]
}

# Return a list of bindings for the given resource, e.g. projects, folders, organizations
bindings(resource) := bindings if {
	bindings := [binding |
		some binding in input.google.iam[resource][_].bindings
		isManaged(binding)
	]
}

is_service_account(member) := startswith(member, "serviceAccount:")

owner_role := "roles/owner"

editor_role := "roles/editor"

is_role_privileged(role) if role in {owner_role, editor_role}

is_role_privileged(role) if endswith(lower(role), "admin")

is_member_default_service_account(member) if endswith(member, "-compute@developer.gserviceaccount.com")

is_member_default_service_account(member) if endswith(member, "@appspot.gserviceaccount.com")

service_account_user_role := "roles/iam.serviceAccountUser"

service_account_token_creator_role := "roles/iam.serviceAccountTokenCreator"

privileged_access_roles := {
	service_account_user_role,
	service_account_token_creator_role,
}

is_privileged_access_role(role) := role in privileged_access_roles

# Return a list of roles for the given resource, e.g. projects, folders, organizations
roles(resource) := roles if {
	roles := [role |
		some k in {"members", "bindings"}
		some roleable in input.google.iam[resource][_][k]
		isManaged(roleable)
		role := roleable.role
	]
}
