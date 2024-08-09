package test

import (
	"context"
	"testing"

	checks "github.com/aquasecurity/trivy-checks"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/accessanalyzer"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/athena"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/codebuild"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/config"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/documentdb"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	ruleTypes "github.com/aquasecurity/trivy/pkg/iac/types/rules"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scanState(t *testing.T, regoScanner *rego.Scanner, s state.State, checkID string, expected bool) {
	results, err := regoScanner.ScanInput(context.TODO(), rego.Input{
		Contents: s.ToRego(),
	})
	require.NoError(t, err)

	var found bool
	for _, result := range results {
		if result.Status() == scan.StatusFailed && result.Rule().AVDID == checkID {
			found = true
		}
	}

	if expected {
		assert.True(t, found, "Rule should have been found")
	} else {
		assert.False(t, found, "Rule should not have been found")
	}
}

func TestAWSRegoChecks(t *testing.T) {
	type testCase struct {
		name     string
		input    state.State
		expected bool
	}

	tests := map[string][]testCase{
		"AVD-AWS-0175": {
			// TODO: Trivy does not export empty structures into Rego
			// {

			// 	name:     "No analyzers enabled",
			// 	input:    state.State{AWS: aws.AWS{AccessAnalyzer: accessanalyzer.AccessAnalyzer{}}},
			// 	expected: true,
			// },
			{
				name: "Analyzer disabled",
				input: state.State{AWS: aws.AWS{AccessAnalyzer: accessanalyzer.AccessAnalyzer{
					Analyzers: []accessanalyzer.Analyzer{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ARN:      trivyTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", trivyTypes.NewTestMetadata()),
							Name:     trivyTypes.String("test", trivyTypes.NewTestMetadata()),
							Active:   trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: true,
			},
			{
				name: "Analyzer enabled",
				input: state.State{AWS: aws.AWS{AccessAnalyzer: accessanalyzer.AccessAnalyzer{
					Analyzers: []accessanalyzer.Analyzer{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ARN:      trivyTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", trivyTypes.NewTestMetadata()),
							Name:     trivyTypes.String("test", trivyTypes.NewTestMetadata()),
							Active:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					}}},
				},
				expected: false,
			},
		},
		"AVD-AWS-0006": {
			{
				name: "AWS Athena database unencrypted",
				input: state.State{AWS: aws.AWS{Athena: athena.Athena{
					Databases: []athena.Database{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: athena.EncryptionConfiguration{
								Metadata: trivyTypes.NewTestMetadata(),
								Type:     trivyTypes.String(athena.EncryptionTypeNone, trivyTypes.NewTestMetadata()),
							},
						},
					}}},
				},
				expected: true,
			},
			{
				name: "AWS Athena workgroup unencrypted",
				input: state.State{AWS: aws.AWS{Athena: athena.Athena{
					Workgroups: []athena.Workgroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: athena.EncryptionConfiguration{
								Metadata: trivyTypes.NewTestMetadata(),
								Type:     trivyTypes.String(athena.EncryptionTypeNone, trivyTypes.NewTestMetadata()),
							},
						},
					}}},
				},
				expected: true,
			},
			{
				name: "AWS Athena database and workgroup encrypted",
				input: state.State{AWS: aws.AWS{Athena: athena.Athena{
					Databases: []athena.Database{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: athena.EncryptionConfiguration{
								Metadata: trivyTypes.NewTestMetadata(),
								Type:     trivyTypes.String(athena.EncryptionTypeSSEKMS, trivyTypes.NewTestMetadata()),
							},
						},
					},
					Workgroups: []athena.Workgroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: athena.EncryptionConfiguration{
								Metadata: trivyTypes.NewTestMetadata(),
								Type:     trivyTypes.String(athena.EncryptionTypeSSEKMS, trivyTypes.NewTestMetadata()),
							},
						},
					}}},
				},
				expected: false,
			},
		},
		"AVD-AWS-0007": {
			{
				name: "AWS Athena workgroup doesn't enforce configuration",
				input: state.State{AWS: aws.AWS{Athena: athena.Athena{
					Workgroups: []athena.Workgroup{
						{
							Metadata:             trivyTypes.NewTestMetadata(),
							EnforceConfiguration: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: true,
			},
			{
				name: "AWS Athena workgroup enforces configuration",
				input: state.State{AWS: aws.AWS{Athena: athena.Athena{
					Workgroups: []athena.Workgroup{
						{
							Metadata:             trivyTypes.NewTestMetadata(),
							EnforceConfiguration: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0014": {
			{
				name: "AWS CloudTrail not enabled across all regions",
				input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:      trivyTypes.NewTestMetadata(),
							IsMultiRegion: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: true,
			},
			{
				name: "AWS CloudTrail enabled across all regions",
				input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:      trivyTypes.NewTestMetadata(),
							IsMultiRegion: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0016": {
			{
				name: "AWS CloudTrail without logfile validation",
				input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                trivyTypes.NewTestMetadata(),
							EnableLogFileValidation: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: true,
			},
			{
				name: "AWS CloudTrail with logfile validation enabled",
				input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                trivyTypes.NewTestMetadata(),
							EnableLogFileValidation: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0015": {
			{
				name: "AWS CloudTrail without CMK",
				input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: true,
			},
			{
				name: "AWS CloudTrail with CMK",
				input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0162": {
			{
				name: "Trail has cloudwatch configured",
				input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:logs:us-east-1:123456789012:log-group:my-log-group", trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: false,
			},
			{
				name: "Trail does not have cloudwatch configured",
				input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: true,
			},
		},
		"AVD-AWS-0161": {
			{
				name: "Trail has bucket with no public access",
				input: state.State{AWS: aws.AWS{
					CloudTrail: cloudtrail.CloudTrail{
						Trails: []cloudtrail.Trail{
							{
								Metadata:   trivyTypes.NewTestMetadata(),
								BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
							},
						},
					},
					S3: s3.S3{
						Buckets: []s3.Bucket{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Name:     trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
								ACL:      trivyTypes.String("private", trivyTypes.NewTestMetadata()),
							},
						},
					},
				}},
				expected: false,
			},
			{
				name: "Trail has bucket with public access",
				input: state.State{AWS: aws.AWS{
					CloudTrail: cloudtrail.CloudTrail{
						Trails: []cloudtrail.Trail{
							{
								Metadata:   trivyTypes.NewTestMetadata(),
								BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
							},
						},
					},
					S3: s3.S3{
						Buckets: []s3.Bucket{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Name:     trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
								ACL:      trivyTypes.String("public-read", trivyTypes.NewTestMetadata()),
							},
						},
					},
				}},
				expected: true,
			},
		},
		"AVD-AWS-0163": {
			{
				name: "Trail has bucket with logging enabled",
				input: state.State{AWS: aws.AWS{
					CloudTrail: cloudtrail.CloudTrail{
						Trails: []cloudtrail.Trail{
							{
								Metadata:   trivyTypes.NewTestMetadata(),
								BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
							},
						},
					},
					S3: s3.S3{
						Buckets: []s3.Bucket{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Name:     trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
								Logging: s3.Logging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				}},
				expected: false,
			},
			{
				name: "Trail has bucket without logging enabled",
				input: state.State{AWS: aws.AWS{
					CloudTrail: cloudtrail.CloudTrail{
						Trails: []cloudtrail.Trail{
							{
								Metadata:   trivyTypes.NewTestMetadata(),
								BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
							},
						},
					},
					S3: s3.S3{
						Buckets: []s3.Bucket{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Name:     trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
								Logging: s3.Logging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				}},
				expected: true,
			},
		},
		"AVD-AWS-0018": {
			{
				name: "AWS Codebuild project with unencrypted artifact",
				input: state.State{AWS: aws.AWS{CodeBuild: codebuild.CodeBuild{
					Projects: []codebuild.Project{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ArtifactSettings: codebuild.ArtifactSettings{
								Metadata:          trivyTypes.NewTestMetadata(),
								EncryptionEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: true,
			},
			{
				name: "AWS Codebuild project with unencrypted secondary artifact",
				input: state.State{AWS: aws.AWS{CodeBuild: codebuild.CodeBuild{
					Projects: []codebuild.Project{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ArtifactSettings: codebuild.ArtifactSettings{
								Metadata:          trivyTypes.NewTestMetadata(),
								EncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
							SecondaryArtifactSettings: []codebuild.ArtifactSettings{
								{
									Metadata:          trivyTypes.NewTestMetadata(),
									EncryptionEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				}}},
				expected: true,
			},
			{
				name: "AWS Codebuild with encrypted artifacts",
				input: state.State{AWS: aws.AWS{CodeBuild: codebuild.CodeBuild{
					Projects: []codebuild.Project{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ArtifactSettings: codebuild.ArtifactSettings{
								Metadata:          trivyTypes.NewTestMetadata(),
								EncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
							SecondaryArtifactSettings: []codebuild.ArtifactSettings{
								{
									Metadata:          trivyTypes.NewTestMetadata(),
									EncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0019": {
			{
				name: "AWS Config aggregator source with all regions set to false",
				input: state.State{AWS: aws.AWS{Config: config.Config{
					ConfigurationAggregrator: config.ConfigurationAggregrator{
						Metadata:         trivyTypes.NewTestMetadata(),
						SourceAllRegions: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
				}},
				expected: true,
			},
			{
				name: "AWS Config aggregator source with all regions set to true",
				input: state.State{AWS: aws.AWS{Config: config.Config{
					ConfigurationAggregrator: config.ConfigurationAggregrator{
						Metadata:         trivyTypes.NewTestMetadata(),
						SourceAllRegions: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0020": {
			{
				name: "DocDB Cluster not exporting logs",
				input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
					Clusters: []documentdb.Cluster{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EnabledLogExports: []trivyTypes.StringValue{
								trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: true,
			},
			{
				name: "DocDB Cluster exporting audit logs",
				input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
					Clusters: []documentdb.Cluster{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EnabledLogExports: []trivyTypes.StringValue{
								trivyTypes.String(documentdb.LogExportAudit, trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: false,
			},
			{
				name: "DocDB Cluster exporting profiler logs",
				input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
					Clusters: []documentdb.Cluster{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EnabledLogExports: []trivyTypes.StringValue{
								trivyTypes.String(documentdb.LogExportProfiler, trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0021": {
			{
				name: "DocDB unencrypted storage",
				input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
					Clusters: []documentdb.Cluster{
						{
							Metadata:         trivyTypes.NewTestMetadata(),
							StorageEncrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: true,
			},
			{
				name: "DocDB encrypted storage",
				input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
					Clusters: []documentdb.Cluster{
						{
							Metadata:         trivyTypes.NewTestMetadata(),
							StorageEncrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0022": {
			{
				name: "DocDB Cluster encryption missing KMS key",
				input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
					Clusters: []documentdb.Cluster{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: true,
			},
			{
				name: "DocDB Instance encryption missing KMS key",
				input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
					Clusters: []documentdb.Cluster{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
							Instances: []documentdb.Instance{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				}}},
				expected: true,
			},
			{
				name: "DocDB Cluster and Instance encrypted with proper KMS keys",
				input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
					Clusters: []documentdb.Cluster{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
							Instances: []documentdb.Instance{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									KMSKeyID: trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0023": {
			{
				name: "Cluster with SSE disabled",
				input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
					DAXClusters: []dynamodb.DAXCluster{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ServerSideEncryption: dynamodb.ServerSideEncryption{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: true,
			},
			{
				name: "Cluster with SSE enabled",
				input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
					DAXClusters: []dynamodb.DAXCluster{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ServerSideEncryption: dynamodb.ServerSideEncryption{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0024": {
			{
				name: "Cluster with point in time recovery disabled",
				input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
					DAXClusters: []dynamodb.DAXCluster{
						{
							Metadata:            trivyTypes.NewTestMetadata(),
							PointInTimeRecovery: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: true,
			},
			{
				name: "Cluster with point in time recovery enabled",
				input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
					DAXClusters: []dynamodb.DAXCluster{
						{
							Metadata:            trivyTypes.NewTestMetadata(),
							PointInTimeRecovery: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
				expected: false,
			},
		},
		"AVD-AWS-0025": {
			{
				name: "Cluster encryption missing KMS key",
				input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
					Tables: []dynamodb.Table{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ServerSideEncryption: dynamodb.ServerSideEncryption{
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Metadata: trivyTypes.NewTestMetadata(),
								KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: true,
			},
			{
				name: "Cluster encryption using default KMS key",
				input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
					Tables: []dynamodb.Table{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ServerSideEncryption: dynamodb.ServerSideEncryption{
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Metadata: trivyTypes.NewTestMetadata(),
								KMSKeyID: trivyTypes.String(dynamodb.DefaultKMSKeyID, trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: true,
			},
			{
				name: "Cluster encryption using proper KMS key",
				input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
					Tables: []dynamodb.Table{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ServerSideEncryption: dynamodb.ServerSideEncryption{
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Metadata: trivyTypes.NewTestMetadata(),
								KMSKeyID: trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: false,
			},
			{
				name: "KMS key exist, but SSE is not enabled",
				input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
					Tables: []dynamodb.Table{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							ServerSideEncryption: dynamodb.ServerSideEncryption{
								Enabled:  trivyTypes.BoolDefault(false, trivyTypes.NewTestMetadata()),
								Metadata: trivyTypes.NewTestMetadata(),
								KMSKeyID: trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
							},
						},
					},
				}}},
				expected: true,
			},
		},
	}

	regoScanner := rego.NewScanner(trivyTypes.SourceCloud)
	err := regoScanner.LoadPolicies(true, false, checks.EmbeddedPolicyFileSystem, []string{"."}, nil)
	require.NoError(t, err)

	missedIDs, _ := lo.Difference(getMigratedChecksIDs(), lo.Keys(tests))
	assert.Emptyf(t, missedIDs, "Checks %v not covered", missedIDs)

	for id, cases := range tests {
		t.Run(id, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					scanState(t, regoScanner, tc.input, id, tc.expected)
				})
			}
		})
	}
}

func getMigratedChecksIDs() []string {
	allChecks := rules.GetRegistered()

	goChecksIDs := lo.FilterMap(allChecks, func(r ruleTypes.RegisteredRule, _ int) (string, bool) {
		return r.AVDID, r.Check != nil
	})

	regoChecksMap := lo.SliceToMap(lo.Filter(allChecks, func(r ruleTypes.RegisteredRule, _ int) bool {
		return r.Check == nil
	}), func(r ruleTypes.RegisteredRule) (string, any) {
		return r.AVDID, struct{}{}
	})

	return lo.Filter(goChecksIDs, func(avdID string, _ int) bool {
		_, exists := regoChecksMap[avdID]
		return exists
	})
}
