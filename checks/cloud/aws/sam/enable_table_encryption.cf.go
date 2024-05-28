package sam

var cloudFormationEnableTableEncryptionGoodExamples = []string{
	`---
Resources:
  GoodFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: GoodTable
      SSESpecification:
        SSEEnabled: true
`,
}

var cloudFormationEnableTableEncryptionBadExamples = []string{
	`---
Resources:
  BadFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: Bad Table
      SSESpecification:
        SSEEnabled: false
`, `---
Resources:
  BadFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: Bad Table
`,
}

var cloudFormationEnableTableEncryptionLinks = []string{}

var cloudFormationEnableTableEncryptionRemediationMarkdown = ``
