
Use the most modern TLS/SSL policies available

```yaml
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainEndpointOptions:
        TLSSecurityPolicy: Policy-Min-TLS-1-2-2019-07
```


