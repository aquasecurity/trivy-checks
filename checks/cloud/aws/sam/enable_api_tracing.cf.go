package sam

var cloudFormationEnableApiTracingGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Serverless::Api
    Properties:
      Name: Good SAM API example
      StageName: Prod
      TracingEnabled: true
`,
}

var cloudFormationEnableApiTracingBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Serverless::Api
    Properties:
      Name: Bad SAM API example
      StageName: Prod
      TracingEnabled: false
`, `---
Resources:
  BadExample:
    Type: AWS::Serverless::Api
    Properties:
      Name: Bad SAM API example
      StageName: Prod
`,
}

var cloudFormationEnableApiTracingLinks = []string{}

var cloudFormationEnableApiTracingRemediationMarkdown = ``
