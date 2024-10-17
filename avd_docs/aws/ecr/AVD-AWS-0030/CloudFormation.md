
Enable ECR image scanning

```yaml
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: alias/ecr-key
      ImageScanningConfiguration:
        ScanOnPush: true
      ImageTagImmutability: IMMUTABLE
      RepositoryName: test-repository
```


