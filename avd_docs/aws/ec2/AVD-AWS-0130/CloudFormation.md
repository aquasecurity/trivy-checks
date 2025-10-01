
Enable HTTP token requirement for IMDS

```yaml
Resources:
  GoodExample:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      MetadataOptions:
        HttpEndpoint: enabled
        HttpTokens: required
```


