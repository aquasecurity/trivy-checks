
Enforce the use of HTTPS for ElasticSearch

```yaml
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainEndpointOptions:
        EnforceHTTPS: true
```


