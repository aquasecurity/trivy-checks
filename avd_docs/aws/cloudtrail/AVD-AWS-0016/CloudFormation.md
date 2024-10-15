
Turn on log validation for Cloudtrail

```yaml
Resources:
  GoodExample:
    Properties:
      EnableLogFileValidation: true
      IsLogging: true
      IsMultiRegionTrail: true
      S3BucketName: CloudtrailBucket
      S3KeyPrefix: /trailing
      TrailName: Cloudtrail
    Type: AWS::CloudTrail::Trail

```


