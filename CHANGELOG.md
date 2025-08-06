# Changelog

## 1.0.0 (2025-08-06)


### Features

* add signature/elf/custom package ([ea57713](https://github.com/deckhouse/delivery-kit-sdk/commit/ea57713503e7c4a3a02ad86bca2e758372cb5bbd))
* elf/signature package ([a4edd42](https://github.com/deckhouse/delivery-kit-sdk/commit/a4edd422b1ff54e8e2ed68bc72e687cc3449e904))
* **integrity:** add ComputeVerityRootHashForLayerFile func to calculate root hash of existing layer file ([#24](https://github.com/deckhouse/delivery-kit-sdk/issues/24)) ([f055a34](https://github.com/deckhouse/delivery-kit-sdk/commit/f055a346ce5f2a449ea945f84329fc55f1775496))
* **integrity:** format hash device image in CreateHashImageFile ([#32](https://github.com/deckhouse/delivery-kit-sdk/issues/32)) ([14fa76a](https://github.com/deckhouse/delivery-kit-sdk/commit/14fa76a971becbac55fd9804e49cc51305594fe9))
* **integrity:** Publish some EROFS-related utility functions ([#27](https://github.com/deckhouse/delivery-kit-sdk/issues/27)) ([b4acd48](https://github.com/deckhouse/delivery-kit-sdk/commit/b4acd48d1f499955d54602282017891b888c0213))
* **signature, image:** add config digest to manifest payload hash ([1001a11](https://github.com/deckhouse/delivery-kit-sdk/commit/1001a117d1e2a63dff5e92ba6b218f3df0c31173))
* **signature:** decompose cert chain verification ([8b72e17](https://github.com/deckhouse/delivery-kit-sdk/commit/8b72e17584025f109f341766c00f269f93385730))
* **signature:** support base64 for key, cert and chain ([49f729e](https://github.com/deckhouse/delivery-kit-sdk/commit/49f729e76f99de7c28c9b28dfc11cb7b50c89ed8))
* **signature:** use img.config for payload hash calculation ([bb47231](https://github.com/deckhouse/delivery-kit-sdk/commit/bb47231d2793c8fe5a83ff5b58f8cf62b5e0d383))
* **signature:** verify image manifest using verifier ([#7](https://github.com/deckhouse/delivery-kit-sdk/issues/7)) ([bfe9651](https://github.com/deckhouse/delivery-kit-sdk/commit/bfe9651c99d0e2421c33ce77ef05c52f1e0855e3))
* **signver:** support hashivault provider ([3a109be](https://github.com/deckhouse/delivery-kit-sdk/commit/3a109be720336ef59b4d0d79dd094d6c948d7bd4))


### Bug Fixes

* change ELF signature section and note name ([421aa56](https://github.com/deckhouse/delivery-kit-sdk/commit/421aa56ccc77ea12541b4690aade3a5d0ad38b26))
* change ELF signature section and note name ([dd3bbfa](https://github.com/deckhouse/delivery-kit-sdk/commit/dd3bbfa70a24fbb51f01c4bba8ad9a53c771547b))
* **elf-signature-custom:** always force resigning ([1cf95ed](https://github.com/deckhouse/delivery-kit-sdk/commit/1cf95ed2c907555be6194cdaa20b73f93c2535e2))
* **elf-signature-custom:** always force resigning ([2eb11b7](https://github.com/deckhouse/delivery-kit-sdk/commit/2eb11b7e3bbb53ed48bc5427407f3a4a3aac9477))
* error `failed to get data chunk for section .bss` ([5e09627](https://github.com/deckhouse/delivery-kit-sdk/commit/5e096275245f397fd2f93ec09c20b759f7cec1b0))
* error `failed to get data chunk for section .bss` ([#30](https://github.com/deckhouse/delivery-kit-sdk/issues/30)) ([e3643e8](https://github.com/deckhouse/delivery-kit-sdk/commit/e3643e80ddcc5e0938b075f0f1cc56f29da54434))
* **integrity, dmverity:** fix verity partition with fixed size 4mb ([43eacc0](https://github.com/deckhouse/delivery-kit-sdk/commit/43eacc030ba155b1eba174377dd19c5aed31c788))
* **integrity:** fix validateMkfsVersion function logic ([#31](https://github.com/deckhouse/delivery-kit-sdk/issues/31)) ([f4a1d03](https://github.com/deckhouse/delivery-kit-sdk/commit/f4a1d03ce518780bfedbb6a915ab1dbd8e5be86e))
* **integrity:** require mkfs.erofs from 1.8.6 to 1.8.10 to fix AUFS whiteout support ([be3442c](https://github.com/deckhouse/delivery-kit-sdk/commit/be3442c5eac69b0982f21db9580e577ccedb278f))
* **integrity:** respect AUFS special files by adding --aufs to mkfs.erofs ([#34](https://github.com/deckhouse/delivery-kit-sdk/issues/34)) ([fea5b76](https://github.com/deckhouse/delivery-kit-sdk/commit/fea5b763298b3831600985346f72ea0d02c426e5))
* **signature, image:** make cert and chain optional ([e29ac9e](https://github.com/deckhouse/delivery-kit-sdk/commit/e29ac9eb02a7ecd349ca119e41f6c0e52c561b66))
* **signature, manifest:** fix asn.1 encoding error ([#38](https://github.com/deckhouse/delivery-kit-sdk/issues/38)) ([5cb8fb5](https://github.com/deckhouse/delivery-kit-sdk/commit/5cb8fb52a5a7651bfa2fb7ac3309ba1cefaa04ab))
* **signature, manifest:** fix asn.1 encoding error ([#41](https://github.com/deckhouse/delivery-kit-sdk/issues/41)) ([c424a01](https://github.com/deckhouse/delivery-kit-sdk/commit/c424a01ff731ac45ffb83cc2c4b317c0a1d93fcc))
* **signature:** fix consistency of payload ([31475ba](https://github.com/deckhouse/delivery-kit-sdk/commit/31475bab0822bd8807e46a7c5bf94a4661ea3da7))
* **signature:** fix typo in anno names ([901b609](https://github.com/deckhouse/delivery-kit-sdk/commit/901b609b4d1e18f45dfd79eb9b929ee01defcffc))
* **signature:** require root cert on verify ([c61dfc8](https://github.com/deckhouse/delivery-kit-sdk/commit/c61dfc8c8bfe935b9d533f715bd668b3cb839650))
