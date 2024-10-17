
Use customer managed keys

```yaml
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: alias/ecr-key
      ImageScanningConfiguration:
        ScanOnPush: false
      ImageTagImmutability: IMMUTABLE
      RepositoryName: test-repository
```


