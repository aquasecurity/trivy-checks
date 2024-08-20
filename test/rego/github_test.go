package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/github"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var githubTestCases = testCases{
	"AVD-GIT-0004": {
		{
			name: "Require signed commits enabled for branch",
			input: state.State{GitHub: github.GitHub{BranchProtections: []github.BranchProtection{
				{
					Metadata:             trivyTypes.NewTestMetadata(),
					RequireSignedCommits: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
		{
			name: "Require signed commits disabled for repository",
			input: state.State{GitHub: github.GitHub{BranchProtections: []github.BranchProtection{
				{
					Metadata:             trivyTypes.NewTestMetadata(),
					RequireSignedCommits: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
	},
	"AVD-GIT-0003": {
		{
			name: "Vulnerability alerts enabled for repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata:            trivyTypes.NewTestMetadata(),
					VulnerabilityAlerts: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					Archived:            trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
		{
			name: "Vulnerability alerts disabled for repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata:            trivyTypes.NewTestMetadata(),
					VulnerabilityAlerts: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					Archived:            trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Vulnerability alerts disabled for archived repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata:            trivyTypes.NewTestMetadata(),
					VulnerabilityAlerts: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					Archived:            trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-GIT-0002": {
		{
			name: "Github actions environment secret has plain text value",
			input: state.State{GitHub: github.GitHub{EnvironmentSecrets: []github.EnvironmentSecret{
				{
					Metadata:       trivyTypes.NewTestMetadata(),
					PlainTextValue: trivyTypes.String("sensitive secret string", trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Github actions environment secret has no plain text value",
			input: state.State{GitHub: github.GitHub{EnvironmentSecrets: []github.EnvironmentSecret{
				{
					Metadata:       trivyTypes.NewTestMetadata(),
					PlainTextValue: trivyTypes.String("", trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-GIT-0001": {
		{
			name: "Public repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata: trivyTypes.NewTestMetadata(),
					Public:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Private repository",
			input: state.State{GitHub: github.GitHub{Repositories: []github.Repository{
				{
					Metadata: trivyTypes.NewTestMetadata(),
					Public:   trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
}
