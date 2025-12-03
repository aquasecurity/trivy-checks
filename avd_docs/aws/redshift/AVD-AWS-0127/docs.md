
Redshift clusters that are created without subnet details will be created in EC2 classic mode, meaning that they will be outside of a known VPC and running in tenant.
In order to benefit from the additional security features achieved with using an owned VPC, the subnet should be set.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html


