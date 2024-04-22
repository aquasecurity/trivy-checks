package sam

var cloudFormationApiUseSecureTlsPolicyGoodExamples = []string{
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
`,
}

var cloudFormationApiUseSecureTlsPolicyBadExamples = []string{
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

var cloudFormationApiUseSecureTlsPolicyLinks = []string{}

var cloudFormationApiUseSecureTlsPolicyRemediationMarkdown = ``
