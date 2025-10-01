
Reference a managed key rather than include the key in raw format.

```hcl
resource "google_compute_disk" "good_example" {
  disk_encryption_key {
    kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
  }
}
```
```hcl
resource "google_compute_instance" "bad_example" {
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      source_snapshot_encryption_key {
        kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
      }
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link

