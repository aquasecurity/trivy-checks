package sam

var cloudFormationEnableHttpApiAccessLoggingGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Serverless::HttpApi
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Activey
      AccessLogSettings:
        DestinationArn: gateway-logging
        Format: json
`,
}

var cloudFormationEnableHttpApiAccessLoggingBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Serverless::HttpApi
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Passthrough
`,
}

var cloudFormationEnableHttpApiAccessLoggingLinks = []string{}

var cloudFormationEnableHttpApiAccessLoggingRemediationMarkdown = ``
