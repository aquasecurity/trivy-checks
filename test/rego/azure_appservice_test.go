package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(azureAppServiceTestCases)
}

var azureAppServiceTestCases = testCases{
	"AVD-AZU-0002": {
		{
			name: "App service identity not registered",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Identity: struct{ Type trivyTypes.StringValue }{
							Type: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "App service identity registered",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Identity: struct{ Type trivyTypes.StringValue }{
							Type: trivyTypes.String("UserAssigned", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0003": {
		{
			name: "App service authentication disabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Authentication: struct{ Enabled trivyTypes.BoolValue }{
							Enabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "App service authentication enabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Authentication: struct{ Enabled trivyTypes.BoolValue }{
							Enabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0005": {
		{
			name: "HTTP2 disabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       trivyTypes.BoolValue
							MinimumTLSVersion trivyTypes.StringValue
						}{
							EnableHTTP2: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "HTTP2 enabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       trivyTypes.BoolValue
							MinimumTLSVersion trivyTypes.StringValue
						}{
							EnableHTTP2: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0004": {
		{
			name: "Function app doesn't enforce HTTPS",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				FunctionApps: []appservice.FunctionApp{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						HTTPSOnly: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Function app enforces HTTPS",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				FunctionApps: []appservice.FunctionApp{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						HTTPSOnly: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0001": {
		{
			name: "App service client certificate disabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						EnableClientCert: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "App service client certificate enabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						EnableClientCert: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0006": {
		{
			name: "Minimum TLS version TLS1_0",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       trivyTypes.BoolValue
							MinimumTLSVersion trivyTypes.StringValue
						}{
							EnableHTTP2:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							MinimumTLSVersion: trivyTypes.String("1.0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Minimum TLS version TLS1_2",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       trivyTypes.BoolValue
							MinimumTLSVersion trivyTypes.StringValue
						}{
							EnableHTTP2:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							MinimumTLSVersion: trivyTypes.String("1.2", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
