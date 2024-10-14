
Enforce the use of HTTPS for ElasticSearch

```yaml
Resources:
    GoodExample:
        Properties:
            DomainEndpointOptions:
                EnforceHTTPS: true
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
        Type: AWS::Elasticsearch::Domain
```


