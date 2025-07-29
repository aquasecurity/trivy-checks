
Enable encrypted node to node communication

```yaml
Resources:
  GoodExample:
    Type: AWS::OpenSearchService::Domain
    Properties:
      NodeToNodeEncryptionOptions:
        Enabled: true
```
```yaml
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      NodeToNodeEncryptionOptions:
        Enabled: true
```


