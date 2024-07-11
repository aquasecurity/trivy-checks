package ec2

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

const (
	sshPort = 22
	rdpPort = 3389
)

var CheckNoPublicIngressSgr = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0107",
		Aliases:   []string{"aws-vpc-no-public-ingress-sgr"},
		Provider:  providers.AWSProvider,
		Service:   "ec2",
		ShortCode: "no-public-ingress-sgr",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"4.1", "4.2"},
			framework.CIS_AWS_1_4: {"5.2"},
		},
		Summary:    "Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22 or port 3389.",
		Impact:     "Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.",
		Resolution: "Set a more restrictive CIDR range",
		Explanation: `Security groups provide stateful filtering of ingress and egress network traffic to AWS
resources. It is recommended that no security group allows unrestricted ingress access to
remote server administration ports, such as SSH to port 22 and RDP to port 3389.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressSgrGoodExamples,
			BadExamples:         terraformNoPublicIngressSgrBadExamples,
			Links:               terraformNoPublicIngressSgrLinks,
			RemediationMarkdown: terraformNoPublicIngressSgrRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIngressSgrGoodExamples,
			BadExamples:         cloudFormationNoPublicIngressSgrBadExamples,
			Links:               cloudFormationNoPublicIngressSgrLinks,
			RemediationMarkdown: cloudFormationNoPublicIngressSgrRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.EC2.SecurityGroups {
			for _, rule := range group.IngressRules {
				if !(rule.Protocol.IsOneOf("-1", "all") ||
					isSSHOrRDP(rule.FromPort.Value(), rule.ToPort.Value())) {
					continue
				}
				var failed bool
				for _, cidr := range rule.CIDRs {
					if isAllIPAddress(cidr.Value()) {
						failed = true
						results.Add(
							"Security group rule allows ingress from 0.0.0.0/0 or ::/0 to port 22 or port 3389.",
							cidr,
						)
					}
				}
				if !failed {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)

func isSSHOrRDP(from, to int) bool {
	return containsPort(from, to, sshPort) || containsPort(from, to, rdpPort)
}

func isAllIPAddress(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "0000:0000:0000:0000:0000:0000:0000:0000/0" || cidr == "::/0"
}

func containsPort(from, to, port int) bool {
	return from <= port && port <= to
}
