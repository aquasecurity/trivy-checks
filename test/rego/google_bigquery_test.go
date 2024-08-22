package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/bigquery"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(googleBigQueryTestCases)
}

var googleBigQueryTestCases = testCases{
	"AVD-GCP-0046": {
		{
			name: "positive result",
			input: state.State{Google: google.Google{BigQuery: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AccessGrants: []bigquery.AccessGrant{
							{
								SpecialGroup: trivyTypes.String(
									bigquery.SpecialGroupAllAuthenticatedUsers,
									trivyTypes.NewTestMetadata(),
								),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{Google: google.Google{BigQuery: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AccessGrants: []bigquery.AccessGrant{
							{
								SpecialGroup: trivyTypes.String(
									"anotherGroup",
									trivyTypes.NewTestMetadata(),
								),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
