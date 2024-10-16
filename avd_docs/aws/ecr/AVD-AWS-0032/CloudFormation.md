
Do not allow public access in the policy

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
      RepositoryPolicyText:
        Statement:
          - Action:
              - ecr:GetDownloadUrlForLayer
              - ecr:BatchGetImage
              - ecr:BatchCheckLayerAvailability
              - ecr:PutImage
              - ecr:InitiateLayerUpload
              - ecr:UploadLayerPart
              - ecr:CompleteLayerUpload
            Effect: Allow
            Principal:
              AWS:
                - arn:aws:iam::123456789012:user/Alice
            Sid: AllowPushPull
        Version: "2012-10-17"
```


