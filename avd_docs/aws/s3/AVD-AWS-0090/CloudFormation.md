
Enable versioning to protect against accidental/malicious removal or modification

```yaml---
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Enabled

```


