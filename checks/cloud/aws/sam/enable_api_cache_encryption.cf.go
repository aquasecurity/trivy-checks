package sam

var cloudFormationEnableApiCacheEncryptionGoodExamples = []string{
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
      MethodSettings:
        CacheDataEncrypted: true
`,
}

var cloudFormationEnableApiCacheEncryptionBadExamples = []string{
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
      TracingEnabled: false
      MethodSettings:
        CacheDataEncrypted: false
`,
}

var cloudFormationEnableApiCacheEncryptionLinks = []string{}

var cloudFormationEnableApiCacheEncryptionRemediationMarkdown = ``
