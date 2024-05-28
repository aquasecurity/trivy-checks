package cloudtrail

var cloudFormationEncryptionCustomerManagedKeyGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true
      KmsKeyId: "alias/CloudtrailKey"
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"
`,
}

var cloudFormationEncryptionCustomerManagedKeyBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: false     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"
`,
}

var cloudFormationEncryptionCustomerManagedKeyLinks = []string{
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-kmskeyid",
}
