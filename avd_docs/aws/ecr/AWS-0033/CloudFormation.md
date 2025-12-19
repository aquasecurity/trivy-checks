
Use customer managed keys

```yaml
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: alias/ecr-key
      RepositoryName: test-repository
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-encryptionconfiguration

