
Enable Cloudtrail in all regions

```yaml
Resources:
    GoodExample:
        Properties:
            IsLogging: true
            IsMultiRegionTrail: true
            S3BucketName: CloudtrailBucket
            S3KeyPrefix: /trailing
            TrailName: Cloudtrail
        Type: AWS::CloudTrail::Trail

```


