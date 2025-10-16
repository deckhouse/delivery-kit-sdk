# Vault Key Loader

This package implements loading keys from Vault server.

## General configuration

| Environment Variable       | Description                                                                                                    |
|----------------------------|----------------------------------------------------------------------------------------------------------------|
| VAULT_ADDR                 | [Address of Vault server](https://developer.hashicorp.com/vault/docs/commands#configure-environment-variables) | 
| TRANSIT_SECRET_ENGINE_PATH | [Path of transit engine](https://developer.hashicorp.com/vault/api-docs/secret/transit) (default `/transit`)   |

## Authentication methods

Before requesting server with "sing" / "verify" operations
you need to get an **access token** via one of next authentication methods.

| Name                 | Description                          | Environment Variables              | URI (default)     | Renewal token | Refreshing token   |
|----------------------|--------------------------------------|------------------------------------|-------------------|---------------|--------------------|
| Static Token         | Explicitly sets access token         | `VAULT_TOKEN`                      | Not used          | Not used      | Not used           |
| App Role             | Sets credentials to get access token | `VAULT_ROLE_ID`, `VAULT_SECRET_ID` | `/auth/ar/login`  | Not used      | On every operation |
| JSON Web Token (JWT) | Sets credentials to get access token | `VAULT_JWT`, `VAULT_ROLE`          | `/auth/jwt/login` | Not used      | On every operation |

If auth method use default URI it could be configured with `VAULT_LOGIN_NAMESPACE` environment variable. 

For example, JWT auth method uses `/auth/jwt/login` by default. 
So setting `VAULT_LOGIN_NAMESPACE=github` we change the URI to `/auth/github/login`.

### Examples

- [Static Token configuration](https://github.com/deckhouse/delivery-kit-sdk/blob/f92488100f2bcfa61ecd8744ee58c04342e3d7d8/pkg/signature/image/manifest_vault_test.go#L48)
- [App Role configuration](https://github.com/deckhouse/delivery-kit-sdk/blob/f92488100f2bcfa61ecd8744ee58c04342e3d7d8/pkg/signature/image/manifest_vault_test.go#L249)
- [JSON Web Token configuration](https://github.com/deckhouse/delivery-kit-sdk/blob/f92488100f2bcfa61ecd8744ee58c04342e3d7d8/pkg/signature/image/manifest_vault_test.go#L203)
