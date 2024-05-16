package s3

var cloudFormationSpecifyPublicAccessBlockGoodExamples = []string{
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

var cloudFormationSpecifyPublicAccessBlockBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: AuthenticatedRead
`,
}

var cloudFormationSpecifyPublicAccessBlockLinks = []string{}

var cloudFormationSpecifyPublicAccessBlockRemediationMarkdown = ``
