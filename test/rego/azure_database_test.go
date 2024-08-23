package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(azureDatabaseTestCases)
}

var azureDatabaseTestCases = testCases{
	"AVD-AZU-0028": {
		{
			name: "MS SQL server alerts for SQL injection disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								DisabledAlerts: []trivyTypes.StringValue{
									trivyTypes.String("Sql_Injection", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server all alerts enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								DisabledAlerts: []trivyTypes.StringValue{},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0027": {
		{
			name: "MS SQL server extended audit policy not configured",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata:                 trivyTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server extended audit policy configured",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        trivyTypes.NewTestMetadata(),
								RetentionInDays: trivyTypes.Int(6, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0020": {
		{
			name: "MariaDB server SSL not enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             trivyTypes.NewTestMetadata(),
							EnableSSLEnforcement: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server SSL not enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             trivyTypes.NewTestMetadata(),
							EnableSSLEnforcement: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server SSL not enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             trivyTypes.NewTestMetadata(),
							EnableSSLEnforcement: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MariaDB server SSL enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             trivyTypes.NewTestMetadata(),
							EnableSSLEnforcement: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MySQL server SSL enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             trivyTypes.NewTestMetadata(),
							EnableSSLEnforcement: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "PostgreSQL server SSL enforced",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:             trivyTypes.NewTestMetadata(),
							EnableSSLEnforcement: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0022": {
		{
			name: "MySQL server public access enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  trivyTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MariaDB server public access enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  trivyTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server public access enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  trivyTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server public access enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  trivyTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server public access disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  trivyTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MariaDB server public access disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  trivyTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MS SQL server public access disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  trivyTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "PostgreSQL server public access disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  trivyTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0029": {
		{
			name: "MySQL server firewall allows public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: trivyTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									StartIP:  trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
									EndIP:    trivyTypes.String("255.255.255.255", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server firewall allows single public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: trivyTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									StartIP:  trivyTypes.String("8.8.8.8", trivyTypes.NewTestMetadata()),
									EndIP:    trivyTypes.String("8.8.8.8", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MS SQL server firewall allows public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: trivyTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									StartIP:  trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
									EndIP:    trivyTypes.String("255.255.255.255", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server firewall allows public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: trivyTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									StartIP:  trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
									EndIP:    trivyTypes.String("255.255.255.255", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MariaDB server firewall allows public internet access",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: trivyTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									StartIP:  trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
									EndIP:    trivyTypes.String("255.255.255.255", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server firewall allows access to Azure services",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: trivyTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									StartIP:  trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
									EndIP:    trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MS SQL server firewall allows access to Azure services",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: trivyTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									StartIP:  trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
									EndIP:    trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "PostgreSQL server firewall allows access to Azure services",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: trivyTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									StartIP:  trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
									EndIP:    trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MariaDB server firewall allows access to Azure services",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: trivyTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									StartIP:  trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
									EndIP:    trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0021": {
		{
			name: "PostgreSQL server connection throttling disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:             trivyTypes.NewTestMetadata(),
							ConnectionThrottling: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server connection throttling enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:             trivyTypes.NewTestMetadata(),
							ConnectionThrottling: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0024": {
		{
			name: "PostgreSQL server checkpoint logging disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       trivyTypes.NewTestMetadata(),
							LogCheckpoints: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server checkpoint logging enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       trivyTypes.NewTestMetadata(),
							LogCheckpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0019": {
		{
			name: "PostgreSQL server connection logging disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       trivyTypes.NewTestMetadata(),
							LogConnections: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server connection logging enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       trivyTypes.NewTestMetadata(),
							LogConnections: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0025": {
		{
			name: "MS SQL server auditing policy with retention period of 30 days",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        trivyTypes.NewTestMetadata(),
								RetentionInDays: trivyTypes.Int(30, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server auditing policy with retention period of 90 days",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        trivyTypes.NewTestMetadata(),
								RetentionInDays: trivyTypes.Int(90, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0026": {
		{
			name: "MS SQL server minimum TLS version 1.0",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("1.0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MySQL server minimum TLS version 1.0",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("TLS1_0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.0",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("TLS1_0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL server minimum TLS version 1.2",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("1.2", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "MySQL server minimum TLS version 1.2",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("TLS1_2", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.2",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("TLS1_2", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0018": {
		{
			name: "No email address provided for threat alerts",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								EmailAddresses: []trivyTypes.StringValue{},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Email address provided for threat alerts",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								EmailAddresses: []trivyTypes.StringValue{
									trivyTypes.String("sample@email.com", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0023": {
		{
			name: "MS SQL Server alert account admins disabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:           trivyTypes.NewTestMetadata(),
								EmailAccountAdmins: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "MS SQL Server alert account admins enabled",
			input: state.State{Azure: azure.Azure{Database: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:           trivyTypes.NewTestMetadata(),
								EmailAccountAdmins: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
