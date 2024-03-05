package database

var terraformEnableAuditGoodExamples = []string{
	`
 resource "azurerm_sql_server" "good_example" {
   name                         = "mssqlserver"
   resource_group_name          = azurerm_resource_group.example.name
   location                     = azurerm_resource_group.example.location
   version                      = "12.0"
   administrator_login          = "mradministrator"
   administrator_login_password = "tfsecRocks"
 }

 resource "azurerm_mssql_server_extended_auditing_policy" "example" {
  server_id                               = azurerm_sql_server.good_example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = true
  retention_in_days                       = 6
 }
 `,
}

var terraformEnableAuditBadExamples = []string{
	`
 resource "azurerm_sql_server" "bad_example" {
   name                         = "mssqlserver"
   resource_group_name          = azurerm_resource_group.example.name
   location                     = azurerm_resource_group.example.location
   version                      = "12.0"
   administrator_login          = "mradministrator"
   administrator_login_password = "tfsecRocks"
 }
 `,
}

var terraformEnableAuditLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_extended_auditing_policy`,
}

var terraformEnableAuditRemediationMarkdown = ``
