package s3

var cloudFormationIgnorePublicAclsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
`,
}

var cloudFormationIgnorePublicAclsBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: AuthenticatedRead
`,
}

var cloudFormationIgnorePublicAclsLinks = []string{}

var cloudFormationIgnorePublicAclsRemediationMarkdown = ``
