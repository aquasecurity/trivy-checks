# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.google.database

import rego.v1

sql_server_family := "SQLSERVER"

postgres_family := "POSTGRES"

mysql_family := "MYSQL"

is_sql_server(instance) := is_database_family(instance, sql_server_family)

is_postgres(instance) := is_database_family(instance, postgres_family)

is_mysql(instance) := is_database_family(instance, mysql_family)

is_database_family(instance, family) if {
	parts := split(instance.databaseversion.value, "_")
	count(parts) > 1
	parts[0] == family
}
