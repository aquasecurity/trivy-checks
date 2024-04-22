package s3

var cloudFormationEnableVersioningGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Enabled
`,
}

var cloudFormationEnableVersioningBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableVersioningLinks = []string{}

var cloudFormationEnableVersioningRemediationMarkdown = ``
