package s3

var cloudFormationNoPublicAccessWithAclGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
`,
}

var cloudFormationNoPublicAccessWithAclBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: AuthenticatedRead
`,
}

var cloudFormationNoPublicAccessWithAclLinks = []string{}

var cloudFormationNoPublicAccessWithAclRemediationMarkdown = ``
