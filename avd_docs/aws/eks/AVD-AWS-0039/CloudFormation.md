
Enable encryption of EKS secrets

```yaml
Resources:
  GoodExample:
    Type: AWS::EKS::Cluster
    Properties:
      EncryptionConfig:
        - Provider:
            KeyArn: alias/eks-kms
          Resources:
            - secrets
      Name: goodExample
```


