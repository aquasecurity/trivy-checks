package s3

var cloudFormationEnableBucketEncryptionGoodExamples = []string{
	`
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
            ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
`,
}

var cloudFormationEnableBucketEncryptionBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableBucketEncryptionLinks = []string{}

var cloudFormationEnableBucketEncryptionRemediationMarkdown = ``
