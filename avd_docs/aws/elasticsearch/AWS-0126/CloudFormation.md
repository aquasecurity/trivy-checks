
Use the most modern TLS/SSL policies available

```yaml
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainEndpointOptions:
        TLSSecurityPolicy: Policy-Min-TLS-1-2-2019-07
```
```yaml
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainEndpointOptions:
        TLSSecurityPolicy: Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08
```

