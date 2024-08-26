package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(googleSqlTestCases)
}

var googleSqlTestCases = testCases{
	"AVD-GCP-0024": {
		{
			name: "Database instance backups disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						IsReplica: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Database instance backups enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						IsReplica: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Read replica does not require backups",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						IsReplica: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0014": {
		{
			name: "Instance temp files logging disabled for all files",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        trivyTypes.NewTestMetadata(),
								LogTempFileSize: trivyTypes.Int(-1, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance temp files logging disabled for files smaller than 100KB",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        trivyTypes.NewTestMetadata(),
								LogTempFileSize: trivyTypes.Int(100, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance temp files logging enabled for all files",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        trivyTypes.NewTestMetadata(),
								LogTempFileSize: trivyTypes.Int(0, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0015": {
		{
			name: "DB instance TLS not required",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								RequireTLS: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DB instance TLS required",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								RequireTLS: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0026": {
		{
			name: "DB instance local file read access enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("MYSQL_5_6", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:    trivyTypes.NewTestMetadata(),
								LocalInFile: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DB instance local file read access disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("MYSQL_5_6", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:    trivyTypes.NewTestMetadata(),
								LocalInFile: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0023": {
		{
			name: "Instance contained database authentication enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("SQLSERVER_2017_STANDARD", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                        trivyTypes.NewTestMetadata(),
								ContainedDatabaseAuthentication: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance contained database authentication disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("SQLSERVER_2017_STANDARD", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                        trivyTypes.NewTestMetadata(),
								ContainedDatabaseAuthentication: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0019": {
		{
			name: "Instance cross database ownership chaining enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("SQLSERVER_2017_STANDARD", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                 trivyTypes.NewTestMetadata(),
								CrossDBOwnershipChaining: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance cross database ownership chaining disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("SQLSERVER_2017_STANDARD", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                 trivyTypes.NewTestMetadata(),
								CrossDBOwnershipChaining: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0017": {
		{
			name: "Instance settings set with IPv4 enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								EnableIPv4: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled but public CIDR in authorized networks",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								EnableIPv4: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name trivyTypes.StringValue
									CIDR trivyTypes.StringValue
								}{
									{
										CIDR: trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled and private CIDR",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								EnableIPv4: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name trivyTypes.StringValue
									CIDR trivyTypes.StringValue
								}{
									{
										CIDR: trivyTypes.String("10.0.0.1/24", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0025": {
		{
			name: "Instance checkpoint logging disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       trivyTypes.NewTestMetadata(),
								LogCheckpoints: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance checkpoint logging enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       trivyTypes.NewTestMetadata(),
								LogCheckpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0016": {
		{
			name: "Instance connections logging disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       trivyTypes.NewTestMetadata(),
								LogConnections: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance connections logging enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       trivyTypes.NewTestMetadata(),
								LogConnections: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0022": {
		{
			name: "Instance disconnections logging disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:          trivyTypes.NewTestMetadata(),
								LogDisconnections: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance disconnections logging enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:          trivyTypes.NewTestMetadata(),
								LogDisconnections: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0018": {
		{
			name: "Instance minimum log severity set to PANIC",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       trivyTypes.NewTestMetadata(),
								LogMinMessages: trivyTypes.String("PANIC", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance minimum log severity set to ERROR",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       trivyTypes.NewTestMetadata(),
								LogMinMessages: trivyTypes.String("ERROR", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0020": {
		{
			name: "Instance lock waits logging disabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:     trivyTypes.NewTestMetadata(),
								LogLockWaits: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance lock waits logging enabled",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:     trivyTypes.NewTestMetadata(),
								LogLockWaits: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0021": {
		{
			name: "Instance logging enabled for all statements",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                trivyTypes.NewTestMetadata(),
								LogMinDurationStatement: trivyTypes.Int(0, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance logging disabled for all statements",
			input: state.State{Google: google.Google{SQL: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                trivyTypes.NewTestMetadata(),
								LogMinDurationStatement: trivyTypes.Int(-1, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
