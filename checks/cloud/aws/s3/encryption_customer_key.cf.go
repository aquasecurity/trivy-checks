package s3

var cloudFormationCheckEncryptionCustomerKeyGoodExamples = []string{
	`
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
            ServerSideEncryptionByDefault:
              KMSMasterKeyID: kms-arn
              SSEAlgorithm: aws:kms
`,
}

var cloudFormationCheckEncryptionCustomerKeyBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: false
            ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
`,
}

var cloudFormationCheckEncryptionCustomerKeyLinks = []string{}

var cloudFormationCheckEncryptionCustomerKeyRemediationMarkdown = ``
