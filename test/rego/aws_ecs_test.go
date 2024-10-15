package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsEcsTestCases)
}

var awsEcsTestCases = testCases{
	"AVD-AWS-0034": {
		{
			name: "Cluster with disabled container insights",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				Clusters: []ecs.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 trivyTypes.NewTestMetadata(),
							ContainerInsightsEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with enabled container insights",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				Clusters: []ecs.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 trivyTypes.NewTestMetadata(),
							ContainerInsightsEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0035": {
		{
			name: "ECS task definition unencrypted volume",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Volumes: []ecs.Volume{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
									Metadata:                 trivyTypes.NewTestMetadata(),
									TransitEncryptionEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECS task definition encrypted volume",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Volumes: []ecs.Volume{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
									Metadata:                 trivyTypes.NewTestMetadata(),
									TransitEncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0036": {
		// {
		// 	name: "Task definition with plaintext sensitive information",
		// 	input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
		// 		TaskDefinitions: []ecs.TaskDefinition{
		// 			{
		// 				Metadata: trivyTypes.NewTestMetadata(),
		// 				ContainerDefinitions: []ecs.ContainerDefinition{
		// 					{
		// 						Metadata:  trivyTypes.NewTestMetadata(),
		// 						Name:      trivyTypes.String("my_service", trivyTypes.NewTestMetadata()),
		// 						Image:     trivyTypes.String("my_image", trivyTypes.NewTestMetadata()),
		// 						CPU:       trivyTypes.Int(2, trivyTypes.NewTestMetadata()),
		// 						Memory:    trivyTypes.Int(256, trivyTypes.NewTestMetadata()),
		// 						Essential: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
		// 						Environment: []ecs.EnvVar{
		// 							{
		// 								Name:  "ENVIRONMENT",
		// 								Value: "development",
		// 							},
		// 							{
		// 								Name:  "DATABASE_PASSWORD",
		// 								Value: "password123",
		// 							},
		// 						},
		// 					},
		// 				},
		// 			},
		// 		},
		// 	}}},
		// 	expected: true,
		// },
		{
			name: "Task definition without sensitive information",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ContainerDefinitions: []ecs.ContainerDefinition{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								Name:      trivyTypes.String("my_service", trivyTypes.NewTestMetadata()),
								Image:     trivyTypes.String("my_image", trivyTypes.NewTestMetadata()),
								CPU:       trivyTypes.String("2", trivyTypes.NewTestMetadata()),
								Memory:    trivyTypes.String("256", trivyTypes.NewTestMetadata()),
								Essential: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Environment: []ecs.EnvVar{
									{
										Name:  "ENVIRONMENT",
										Value: "development",
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
}
