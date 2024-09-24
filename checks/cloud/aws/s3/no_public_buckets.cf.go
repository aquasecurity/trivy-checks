package s3

var cloudFormationNoPublicBucketsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
`,
}

var cloudFormationNoPublicBucketsBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: AuthenticatedRead
`,
}

var cloudFormationNoPublicBucketsLinks = []string{}

var cloudFormationNoPublicBucketsRemediationMarkdown = ``
