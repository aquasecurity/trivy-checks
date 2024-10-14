
Use customer managed keys

```yaml
Resources:
    GoodExample:
        Properties:
            EncryptionConfiguration:
                EncryptionType: KMS
                KmsKey: alias/ecr-key
            ImageScanningConfiguration:
                ScanOnPush: false
            ImageTagImmutability: IMMUTABLE
            RepositoryName: test-repository
        Type: AWS::ECR::Repository
```


