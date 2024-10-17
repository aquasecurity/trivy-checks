
Turn on log validation for Cloudtrail

```yaml
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      EnableLogFileValidation: true
      IsLogging: true
      IsMultiRegionTrail: true
      S3BucketName: CloudtrailBucket
      S3KeyPrefix: /trailing
      TrailName: Cloudtrail
```


