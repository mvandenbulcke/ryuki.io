# Read-only policy for the in-process platform-api secret resolver. This policy
# is deliberately distinct from every VSO materializer policy.
path "secret/data/ryuki-platform/platform-api/*" {
  capabilities = ["read"]
}

path "secret/metadata/ryuki-platform/platform-api/*" {
  capabilities = ["read"]
}
