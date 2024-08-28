# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.azure.database

import rego.v1

all_servers := servers(["mssqlservers", "mysqlservers", "mariadbservers", "postgresqlservers"])

servers(types) := servers if {
	servers := [db.server |
		some dbkey in types
		some db in input.azure.database[dbkey]
		isManaged(db.server)
	]
}
