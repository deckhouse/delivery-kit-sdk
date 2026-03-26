path "transit/sign/*" {
  capabilities = ["update"]
}

path "transit/keys/*" {
  capabilities = ["read"]
  required_parameters = []
  allowed_parameters = {}
}
