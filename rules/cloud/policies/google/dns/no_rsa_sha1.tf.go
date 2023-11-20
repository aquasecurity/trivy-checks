package dns

var terraformNoRsaSha1GoodExamples = []string{
	`
resource "google_dns_managed_zone" "example-zone" {
  name     = "example-zone"
  dns_name = "example-${random_id.rnd.hex}.com."

  dnssec_config {
    state = "on"
    default_key_specs {
      algorithm = "rsasha512"
      key_type  = "keySigning"
    }
	default_key_specs {
      algorithm = "rsasha512"
      key_type  = "zoneSigning"
    }
  }
}
 `,
}

var terraformNoRsaSha1BadExamples = []string{
	`
resource "google_dns_managed_zone" "example-zone" {
  name     = "example-zone"
  dns_name = "example-${random_id.rnd.hex}.com."

  dnssec_config {
    state = "on"
    default_key_specs {
      algorithm = "rsasha1"
      key_type  = "keySigning"
    }
	default_key_specs {
      algorithm = "rsasha1"
      key_type  = "zoneSigning"
    }
  }
}
 `,
}

var terraformNoRsaSha1Links = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#algorithm`,
}

var terraformNoRsaSha1RemediationMarkdown = ``
