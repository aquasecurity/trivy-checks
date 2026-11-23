# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.azure.database

import rego.v1

server_types := ["mssqlservers", "mysqlservers", "mariadbservers", "postgresqlservers"]

all_servers := servers(server_types)

# all_firewall_rules contains the firewall rules of all servers, including
# orphan rules whose server is unknown.
all_firewall_rules := [rule |
	some dbkey in server_types
	some db in input.azure.database[dbkey]
	some rule in db.server.firewallrules
]

servers(types) := [db.server |
	some dbkey in types
	some db in input.azure.database[dbkey]
	isManaged(db.server)
]
