
Use the most modern TLS/SSL policies available

```yaml
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainEndpointOptions:
        TLSSecurityPolicy: Policy-Min-TLS-1-2-2019-07
      DomainName: test
      EBSOptions:
        EBSEnabled: true
        Iops: "0"
        VolumeSize: "20"
        VolumeType: gp2
      ElasticsearchClusterConfig:
        DedicatedMasterCount: "3"
        DedicatedMasterEnabled: true
        DedicatedMasterType: m3.medium.elasticsearch
        InstanceCount: "2"
        InstanceType: m3.medium.elasticsearch
        ZoneAwarenessEnabled: true
      ElasticsearchVersion: "7.10"
      EncryptionAtRestOptions:
        Enabled: true
        KmsKeyId: alias/kmskey
```


