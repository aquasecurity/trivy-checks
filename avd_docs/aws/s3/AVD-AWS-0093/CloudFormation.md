
Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)

```yaml
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
```


