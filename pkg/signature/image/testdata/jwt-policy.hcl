path "transit/sign/endpoint/sha2-256" {
  capabilities = ["update"]
}

path "transit/keys/endpoint" {
  capabilities = ["read"]
  required_parameters = []
  allowed_parameters = {}
}
