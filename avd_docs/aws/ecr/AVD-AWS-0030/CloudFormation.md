
Enable ECR image scanning

```yaml
Resources:
    GoodExample:
        Properties:
            EncryptionConfiguration:
                EncryptionType: KMS
                KmsKey: alias/ecr-key
            ImageScanningConfiguration:
                ScanOnPush: true
            ImageTagImmutability: IMMUTABLE
            RepositoryName: test-repository
        Type: AWS::ECR::Repository
```


