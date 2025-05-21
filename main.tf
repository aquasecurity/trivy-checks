resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_12"
  region           = "us-central1"
  settings {
    backup_configuration {
      enabled = true
    }
  }
}

resource "google_sql_database_instance" "new_instance_sql_replica" {
  name                 = "replica"
  database_version     = "POSTGRES_12"
  region               = "us-central1"
  master_instance_name = google_sql_database_instance.db.name
  replica_configuration {
    connect_retry_interval  = 0
    failover_target         = false
    master_heartbeat_period = 0
  }
}
