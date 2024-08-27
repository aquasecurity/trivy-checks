package cloudwatch

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

var CheckRequireOrgChangesAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0174",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-org-changes-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for organisation changes",
		Impact:     "Lack of observability into critical organisation changes",
		Resolution: "Create an alarm to alert on organisation changes",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {
				"4.15",
			},
		},
		Explanation: `
Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or
intentional modifications that may lead to unauthorized access or other security breaches.
This monitoring technique helps you to ensure that any unexpected changes performed
within your AWS Organizations can be investigated and any unwanted changes can be
rolled back.
`,
		Links: []string{
			"https://docs.aws.amazon.com/organizations/latest/userguide/orgs_security_incident-response.html",
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, trail := range s.AWS.CloudTrail.MultiRegionTrails() {
			logGroup := s.AWS.CloudWatch.GetLogGroupByArn(trail.CloudWatchLogsLogGroupArn.Value())
			if logGroup == nil || trail.IsLogging.IsFalse() {
				continue
			}

			var metricFilter cloudwatch.MetricFilter
			var found bool
			for _, filter := range logGroup.MetricFilters {
				if filter.FilterPattern.Contains(`$.eventSource = organizations.amazonaws.com`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
				if filter.FilterPattern.Contains(`$.eventSource = "organizations.amazonaws.com"`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudwatch has no organisation changes log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudwatch has organisation changes alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}
		return
	},
)
