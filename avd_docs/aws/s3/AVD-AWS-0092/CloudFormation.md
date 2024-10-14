
Don't use canned ACLs or switch to private acl

```yaml
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
```


