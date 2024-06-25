package builtin.aws.eks.aws0041_test

import rego.v1

import data.builtin.aws.eks.aws0041 as check
import data.lib.test

test_deny_eks_cluster_with_public_access_and_public_cidr if {
    inp := {
        "aws": {
            "eks": {
                "clusters": [
                    {
                        "publicaccesenabled": {
                            "value": true
                        },
                        "publicaccescidrs": [
                            {
                                "value": "0.0.0.0/0"
                            }
                        ]
                    }
                ]
            }
        }
    }

    test.assert_equal_message("Cluster allows access from a public CIDR: 0.0.0.0/0" ,check.deny) with input as inp
}

test_allow_eks_cluster_without_public_access_and_public_cidr if {
    inp := {
        "aws": {
            "eks": {
                "clusters": [
                    {
                        "publicaccesenabled": {
                            "value": false
                        },
                        "publicaccescidrs": [
                            {
                                "value": "0.0.0.0/0"
                            }
                        ]
                    }
                ]
            }
        }
    }

    test.assert_empty(check.deny) with input as inp
}

test_allow_eks_cluster_without_public_access_and_public_cidr if {
    inp := {
        "aws": {
            "eks": {
                "clusters": [
                    {
                        "publicaccesenabled": {
                            "value": false
                        },
                        "publicaccescidrs": [
                            {
                                "value": "0.0.0.0/0"
                            }
                        ]
                    }
                ]
            }
        }
    }

    test.assert_empty(check.deny) with input as inp
}