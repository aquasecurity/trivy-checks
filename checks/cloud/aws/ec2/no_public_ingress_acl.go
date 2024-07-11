package ec2

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicIngress = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0105",
		Aliases:   []string{"aws-vpc-no-public-ingress-acl"},
		Provider:  providers.AWSProvider,
		Service:   "ec2",
		ShortCode: "no-public-ingress-acl",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_4: {"5.1"},
		},
		Summary:    "Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389.",
		Impact:     "Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.",
		Resolution: "Set a more restrictive CIDR range",
		Explanation: `The Network Access Control List (NACL) function provide stateless filtering of ingress and
egress network traffic to AWS resources. It is recommended that no NACL allows
unrestricted ingress access to remote server administration ports, such as SSH to port 22
and RDP to port 3389.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressAclGoodExamples,
			BadExamples:         terraformNoPublicIngressAclBadExamples,
			Links:               terraformNoPublicIngressAclLinks,
			RemediationMarkdown: terraformNoPublicIngressAclRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIngressAclGoodExamples,
			BadExamples:         cloudFormationNoPublicIngressAclBadExamples,
			Links:               cloudFormationNoPublicIngressAclLinks,
			RemediationMarkdown: cloudFormationNoPublicIngressAclRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, acl := range s.AWS.EC2.NetworkACLs {
			for _, rule := range acl.Rules {
				if !rule.Type.EqualTo(ec2.TypeIngress) ||
					!rule.Action.EqualTo(ec2.ActionAllow) ||
					!(rule.Protocol.IsOneOf("-1", "all") ||
						isSSHOrRDP(rule.FromPort.Value(), rule.ToPort.Value())) {
					continue
				}
				var fail bool
				for _, cidr := range rule.CIDRs {
					if isAllIPAddress(cidr.Value()) {
						fail = true
						results.Add(
							"Network ACL rule allows ingress from public internet.",
							cidr,
						)
					}
				}
				if !fail {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
