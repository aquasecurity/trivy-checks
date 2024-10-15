
Only use immutable images in ECR

```yaml
Resources:
  GoodExample:
    Properties:
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: alias/ecr-key
      ImageScanningConfiguration:
        ScanOnPush: false
      ImageTagMutability: IMMUTABLE
      RepositoryName: test-repository
    Type: AWS::ECR::Repository

```


