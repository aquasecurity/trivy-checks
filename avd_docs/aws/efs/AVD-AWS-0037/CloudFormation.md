
Enable encryption for EFS

```yaml
Resources:
  GoodExample:
    Type: AWS::EFS::FileSystem
    Properties:
      Encrypted: true
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html#cfn-efs-filesystem-encrypted

