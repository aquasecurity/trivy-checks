
Only use immutable images in ECR

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
      ImageTagMutability: IMMUTABLE
      RepositoryName: test-repository
```


