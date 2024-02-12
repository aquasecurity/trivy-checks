package compute

import (
	"github.com/aquasecurity/trivy-policies/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckUseSshKeys = rules.Register(
	scan.Rule{
		AVDID:       "AVD-DIG-0004",
		Provider:    providers.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "use-ssh-keys",
		Summary:     "SSH Keys are the preferred way to connect to your droplet, no keys are supplied",
		Impact:      "Logging in with username and password is easier to compromise",
		Resolution:  "Use ssh keys for login",
		Explanation: `When working with a server, you’ll likely spend most of your time in a terminal session connected to your server through SSH. A more secure alternative to password-based logins, SSH keys use encryption to provide a secure way of logging into your server and are recommended for all users.`,
		Links: []string{
			"https://www.digitalocean.com/community/tutorials/understanding-the-ssh-encryption-and-connection-process",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseSshKeysGoodExamples,
			BadExamples:         terraformUseSshKeysBadExamples,
			Links:               terraformUseSshKeysLinks,
			RemediationMarkdown: terraformUseSshKeysRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, droplet := range s.DigitalOcean.Compute.Droplets {
			if droplet.Metadata.IsUnmanaged() {
				continue
			}
			if len(droplet.SSHKeys) == 0 {
				results.Add(
					"Droplet does not have an SSH key specified.",
					&droplet,
				)
			} else {
				results.AddPassed(&droplet)
			}
		}
		return
	},
)
