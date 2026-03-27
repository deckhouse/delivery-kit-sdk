# Changelog

## [1.1.0](https://github.com/deckhouse/delivery-kit-sdk/compare/v1.0.0...v1.1.0) (2026-03-27)


### Features

* **signtature:** support ED25519 with Vault Transit signing ([7f3fd53](https://github.com/deckhouse/delivery-kit-sdk/commit/7f3fd5367af71da80117e748af50bbef57409920))


### Bug Fixes

* **signver:** rename vault auth envs ([#63](https://github.com/deckhouse/delivery-kit-sdk/issues/63)) ([0cbac82](https://github.com/deckhouse/delivery-kit-sdk/commit/0cbac82233339efc3b9daf29574820a6a3a55d5b))

## 1.0.0 (2025-10-16)

### Features

* **signature**: support Vault as a remote signing provider
* **signature, file**: support signing and verifying ELF binaries
* **signature, image**: support signing and verifying image manifest
* **integrity**: add dm-verity root hash calculation for image layer
* **integrity**: add utility functions for EROFS-related operations
