package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/securitycenter"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(azureSecurityCenterTestCases)
}

var azureSecurityCenterTestCases = testCases{
	"AVD-AZU-0044": {
		{
			name: "Security center alert nofifications disabled",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata:                 trivyTypes.NewTestMetadata(),
						EnableAlertNotifications: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security center alert nofifications enabled",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata:                 trivyTypes.NewTestMetadata(),
						EnableAlertNotifications: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0045": {
		{
			name: "Security center set with free subscription",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tier:     trivyTypes.String(securitycenter.TierFree, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security center set with standard subscription",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tier:     trivyTypes.String(securitycenter.TierStandard, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0046": {
		{
			name: "Contact's phone number missing",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Phone:    trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Contact's phone number provided",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Phone:    trivyTypes.String("+1-555-555-5555", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
