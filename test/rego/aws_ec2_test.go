package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsEc2TestCases)
}

var awsEc2TestCases = testCases{
	"AVD-AWS-0124": {
		{
			name: "AWS VPC security group rule has no description",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC security group rule has description",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								Description: trivyTypes.String("some description", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0099": {
		{
			name: "AWS VPC security group with no description provided",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC security group with default description",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("Managed by Terraform", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC security group with proper description",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("some proper description", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0008": {
		{
			name: "Autoscaling unencrypted root block device",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  trivyTypes.NewTestMetadata(),
							Encrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Autoscaling unencrypted EBS block device",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EBSBlockDevices: []*ec2.BlockDevice{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								Encrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Autoscaling encrypted root and EBS block devices",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  trivyTypes.NewTestMetadata(),
							Encrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
						EBSBlockDevices: []*ec2.BlockDevice{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								Encrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0130": {
		{
			name: "Launch configuration with optional tokens",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     trivyTypes.NewTestMetadata(),
							HttpTokens:   trivyTypes.String("optional", trivyTypes.NewTestMetadata()),
							HttpEndpoint: trivyTypes.String("enabled", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch template with optional tokens",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: trivyTypes.NewTestMetadata(),
							MetadataOptions: ec2.MetadataOptions{
								Metadata:     trivyTypes.NewTestMetadata(),
								HttpTokens:   trivyTypes.String("optional", trivyTypes.NewTestMetadata()),
								HttpEndpoint: trivyTypes.String("enabled", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch configuration with required tokens",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     trivyTypes.NewTestMetadata(),
							HttpTokens:   trivyTypes.String("required", trivyTypes.NewTestMetadata()),
							HttpEndpoint: trivyTypes.String("enabled", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0129": {
		{
			name: "Launch template with sensitive info in user data",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: trivyTypes.NewTestMetadata(),
							UserData: trivyTypes.String(`
							export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
							export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
							export AWS_DEFAULT_REGION=us-west-2
							`, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch template with no sensitive info in user data",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: trivyTypes.NewTestMetadata(),
							UserData: trivyTypes.String(`
							export GREETING=hello
							`, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0131": {
		{
			name: "encrypted block device",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						RootBlockDevice: &ec2.BlockDevice{
							Encrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "unencrypted block device",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						RootBlockDevice: &ec2.BlockDevice{
							Encrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0026": {
		{
			name: "unencrypted EBS volume",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "encrypted EBS volume",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0027": {
		{
			name: "EC2 volume missing KMS key",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EC2 volume encrypted with KMS key",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0028": {
		{
			name: "positive result",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     trivyTypes.NewTestMetadata(),
							HttpTokens:   trivyTypes.String("optional", trivyTypes.NewTestMetadata()),
							HttpEndpoint: trivyTypes.String("enabled", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     trivyTypes.NewTestMetadata(),
							HttpTokens:   trivyTypes.String("required", trivyTypes.NewTestMetadata()),
							HttpEndpoint: trivyTypes.String("disabled", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0101": {
		{
			name: "default AWS VPC",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						IsDefault: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "vpc but not default AWS VPC",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						IsDefault: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name:     "no default AWS VPC",
			input:    state.State{AWS: aws.AWS{EC2: ec2.EC2{}}},
			expected: false,
		},
	},
	"AVD-AWS-0102": {
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("-1", trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String("allow", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("all", trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String("allow", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with tcp protocol",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("tcp", trivyTypes.NewTestMetadata()),
								Type:     trivyTypes.String("egress", trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String("allow", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0104": {
		{
			name: "AWS VPC security group rule with wildcard address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								CIDRs: []trivyTypes.StringValue{
									trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC security group rule with private address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								CIDRs: []trivyTypes.StringValue{
									trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0105": {
		{
			name: "AWS VPC network ACL rule with wildcard address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Type:     trivyTypes.String(ec2.TypeIngress, trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String(ec2.ActionAllow, trivyTypes.NewTestMetadata()),
								Protocol: trivyTypes.StringTest("tcp"),
								FromPort: trivyTypes.IntTest(22),
								ToPort:   trivyTypes.IntTest(22),
								CIDRs: []trivyTypes.StringValue{
									trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with private address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Type:     trivyTypes.String(ec2.TypeIngress, trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String(ec2.ActionAllow, trivyTypes.NewTestMetadata()),
								CIDRs: []trivyTypes.StringValue{
									trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0107": {
		{
			name: "AWS VPC ingress security group rule with wildcard address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								CIDRs: []trivyTypes.StringValue{
									trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
								},
								Protocol: trivyTypes.StringTest("tcp"),
								FromPort: trivyTypes.IntTest(22),
								ToPort:   trivyTypes.IntTest(22),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC ingress security group rule with private address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								CIDRs: []trivyTypes.StringValue{
									trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0164": {
		{
			name: "Subnet with public access",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Subnets: []ec2.Subnet{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						MapPublicIpOnLaunch: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Subnet without public access",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Subnets: []ec2.Subnet{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						MapPublicIpOnLaunch: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0009": {
		{
			name: "Launch configuration with public access",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						AssociatePublicIP: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch configuration without public access",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						AssociatePublicIP: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0029": {
		{
			name: "positive result",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						UserData: trivyTypes.String(`<<EOF
						export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
						export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
						export AWS_DEFAULT_REGION=us-west-2
						EOF`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						UserData: trivyTypes.String(`<<EOF
						export GREETING=hello
						EOF`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0122": {
		{
			name: "Launch configuration with sensitive info in user data",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						UserData: trivyTypes.String(`
						export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
						export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
						export AWS_DEFAULT_REGION=us-west-2
						`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch configuration with no sensitive info in user data",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						UserData: trivyTypes.String(`
						export GREETING=hello
						`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0178": {
		{
			name: "VPC without flow logs enabled",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						ID:              trivyTypes.String("vpc-12345678", trivyTypes.NewTestMetadata()),
						FlowLogsEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "VPC with flow logs enabled",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						ID:              trivyTypes.String("vpc-12345678", trivyTypes.NewTestMetadata()),
						FlowLogsEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0173": {
		{
			name: "default sg restricts all",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityGroups: []ec2.SecurityGroup{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								IsDefault:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								IngressRules: nil,
								EgressRules:  nil,
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "default sg allows ingress",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityGroups: []ec2.SecurityGroup{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsDefault: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								IngressRules: []ec2.SecurityGroupRule{
									{},
								},
								EgressRules: nil,
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "default sg allows egress",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityGroups: []ec2.SecurityGroup{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								IsDefault:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								IngressRules: nil,
								EgressRules: []ec2.SecurityGroupRule{
									{},
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
}
