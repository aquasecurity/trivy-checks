package sam

var cloudFormationEnableApiAccessLoggingGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Serverless::Api
    Properties:
      Name: Good SAM API example
      StageName: Prod
      TracingEnabled: false
      Domain:
        SecurityPolicy: TLS_1_2
      AccessLogSetting:
        DestinationArn: gateway-logging
        Format: json
`,
}

var cloudFormationEnableApiAccessLoggingBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Serverless::Api
    Properties:
      Name: Bad SAM API example
      StageName: Prod
      TracingEnabled: false
`,
}

var cloudFormationEnableApiAccessLoggingLinks = []string{}

var cloudFormationEnableApiAccessLoggingRemediationMarkdown = ``
