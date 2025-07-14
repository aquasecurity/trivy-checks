
Use SSE-KMS with a customer managed key (CMK)

```yaml
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
```


