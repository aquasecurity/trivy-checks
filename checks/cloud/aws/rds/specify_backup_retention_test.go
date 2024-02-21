package rds

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckBackupRetentionSpecified(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Cluster with 1 retention day (default)",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						ReplicationSourceARN:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: trivyTypes.Int(1, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Instance with 1 retention day (default)",
			input: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						ReplicationSourceARN:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: trivyTypes.Int(1, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Cluster with 5 retention days",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						ReplicationSourceARN:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: trivyTypes.Int(5, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "RDS Instance with 5 retention days",
			input: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						ReplicationSourceARN:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: trivyTypes.Int(5, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.RDS = test.input
			results := CheckBackupRetentionSpecified.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckBackupRetentionSpecified.LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
