# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0-alpha (2025-06-10)

<csr-id-983110c4dbb41eb7f0fba2c06f561b68718d0f29/>
<csr-id-0eb5bd48b598709dd0fc54adb424f5f41ce52e92/>
<csr-id-47138489bc9567674b57d61b0d105ff6c1c7cb6c/>
<csr-id-ab6701666e3b05bd783ce0309025e842fa83e4c1/>
<csr-id-d786fae33b01cd0863f29b70810dfcc847f2542b/>
<csr-id-ec58fe1828d0560525c80cd1dc4013915b0ac54e/>

### Chore

 - <csr-id-983110c4dbb41eb7f0fba2c06f561b68718d0f29/> move shared dependencies to workspace crate
 - <csr-id-0eb5bd48b598709dd0fc54adb424f5f41ce52e92/> adjust changelogs for cargo-smart-release

### New Features

 - <csr-id-52efe010264bdd5978111e148190359b9383d53e/> derive eq in DkgPublicKey

### Other

 - <csr-id-47138489bc9567674b57d61b0d105ff6c1c7cb6c/> introduce refreshing api in ferveo
 - <csr-id-ab6701666e3b05bd783ce0309025e842fa83e4c1/> Made ferveo-common wasm compatible (a tiny change). Fixes a world of pain upstream in Anoma
 - <csr-id-d786fae33b01cd0863f29b70810dfcc847f2542b/> Formatting
 - <csr-id-ec58fe1828d0560525c80cd1dc4013915b0ac54e/> Removed the announce phase from the dkg

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 96 commits contributed to the release over the course of 1356 calendar days.
 - 7 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 4 unique issues were worked on: [#68](https://github.com/nucypher/ferveo/issues/68), [#70](https://github.com/nucypher/ferveo/issues/70), [#71](https://github.com/nucypher/ferveo/issues/71), [#72](https://github.com/nucypher/ferveo/issues/72)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#68](https://github.com/nucypher/ferveo/issues/68)**
    - Simplify validator sets in dkg state machine ([`73b729a`](https://github.com/nucypher/ferveo/commit/73b729a523b391d40e7a9fe4cbbcdb17557cf089))
 * **[#70](https://github.com/nucypher/ferveo/issues/70)**
    - Dkg State Machine refactor ([`8594316`](https://github.com/nucypher/ferveo/commit/85943169e27d7dbbdce835d6563ac4d838a410e1))
 * **[#71](https://github.com/nucypher/ferveo/issues/71)**
    - Added serialization/deserialization to the dkg state machine ([`653be13`](https://github.com/nucypher/ferveo/commit/653be13c8a9d7de2e98ac76eca3aadf8f8cadf4a))
 * **[#72](https://github.com/nucypher/ferveo/issues/72)**
    - Refactor subproductdomain ([`2d8026b`](https://github.com/nucypher/ferveo/commit/2d8026b2299fd9b67c77fb3b4e565ff9f4e6505b))
 * **Uncategorized**
    - Release ferveo-common-nucypher-temp4 v0.4.0-alpha, subproductdomain-nucypher-temp4 v0.4.0-alpha, ferveo-tdec-temp4 v0.4.0-alpha, ferveo-nucypher-temp4 v0.4.0-alpha ([`b962402`](https://github.com/nucypher/ferveo/commit/b96240209bea70d43016a66301af9bf5fe5a8970))
    - Cargo stuff ([`888535c`](https://github.com/nucypher/ferveo/commit/888535c2b932f855e6080ad388f5a800644cc607))
    - Merge pull request #189 from piotr-roslaniec/workspace-deps ([`be98542`](https://github.com/nucypher/ferveo/commit/be9854252fdff297d99a63eb443a473ecfd41f5a))
    - Move shared dependencies to workspace crate ([`983110c`](https://github.com/nucypher/ferveo/commit/983110c4dbb41eb7f0fba2c06f561b68718d0f29))
    - Merge pull request #175 from piotr-roslaniec/rewrite-refreshing ([`2c97934`](https://github.com/nucypher/ferveo/commit/2c97934251c04754b8c5353492823e3a97dc53a9))
    - Introduce refreshing api in ferveo ([`4713848`](https://github.com/nucypher/ferveo/commit/47138489bc9567674b57d61b0d105ff6c1c7cb6c))
    - Merge pull request #166 from nucypher/chores ([`7350d91`](https://github.com/nucypher/ferveo/commit/7350d91708af55b5aa939a3f7e9cd62e7de7359a))
    - Derive eq in DkgPublicKey ([`52efe01`](https://github.com/nucypher/ferveo/commit/52efe010264bdd5978111e148190359b9383d53e))
    - Release ferveo-common-pre-release v0.1.1, group-threshold-cryptography-pre-release v0.2.0, ferveo-pre-release v0.3.0, safety bump ferveo-pre-release v0.3.0 ([`9c1970b`](https://github.com/nucypher/ferveo/commit/9c1970bb2d9bc36983b041b779a99cb0e95b6ec1))
    - Fix changelogs for cargo-smart-release ([`fe4ec4e`](https://github.com/nucypher/ferveo/commit/fe4ec4ec7667f513b6ebb4bd604303e6ff53a425))
    - Merge pull request #149 from cygnusv/thin ([`f44e1be`](https://github.com/nucypher/ferveo/commit/f44e1be4fe9a0a165d8b0b50ad29bb7f6818f672))
    - Clippy stuff ([`4337c3c`](https://github.com/nucypher/ferveo/commit/4337c3c312719987405f620f2e377cf493ece6d3))
    - Merge pull request #138 from nucypher/development ([`434fd5d`](https://github.com/nucypher/ferveo/commit/434fd5d07b54e72d120e9aa06cbc3e47848e6bcf))
    - Release ferveo-common-pre-release v0.1.0, subproductdomain-pre-release v0.1.0, group-threshold-cryptography-pre-release v0.1.0, ferveo-pre-release v0.2.0 ([`ffb9b21`](https://github.com/nucypher/ferveo/commit/ffb9b21619d0f5dc0fb309bf2f493d3c0c25e1f0))
    - Adjust changelogs for cargo-smart-release ([`0eb5bd4`](https://github.com/nucypher/ferveo/commit/0eb5bd48b598709dd0fc54adb424f5f41ce52e92))
    - Release 0.1.0 crate versions ([`c02e305`](https://github.com/nucypher/ferveo/commit/c02e3050b7a9dcf0260a5eb4e42ff74f3788c3bf))
    - Release ferveo-common-pre-release@0.1.0-alpha.1 ([`2725ba4`](https://github.com/nucypher/ferveo/commit/2725ba455e2ae169af5be64c5f2261ec0c5ea648))
    - Merge pull request #136 from nucypher/pk-static-bytes ([`2b64c2e`](https://github.com/nucypher/ferveo/commit/2b64c2e8e5e594acffde734b65d212fde3df99e9))
    - Remove unused crate ([`4939e79`](https://github.com/nucypher/ferveo/commit/4939e79fd336a08547984d66dd0f7a256ab9dcf7))
    - Feat! use static arrays in ferveo public key serialization ([`f9ac1d7`](https://github.com/nucypher/ferveo/commit/f9ac1d70b0fc7df286438fa817537c31cb9e7682))
    - Merge pull request #119 from nucypher/nucypher-core-integration ([`52c1f27`](https://github.com/nucypher/ferveo/commit/52c1f27627798fa266d2e5079f5121cc71e8e284))
    - Merge pull request #118 from nucypher/expose-bindings-from-main-crate ([`11d6cea`](https://github.com/nucypher/ferveo/commit/11d6ceaf26f45c76dec0c5a9fcf5eae5301502d3))
    - Fix wasm locals exceeded ([`ac91e83`](https://github.com/nucypher/ferveo/commit/ac91e8359df44b72e5863da74ac71fe54f8eba81))
    - Release pre-release crates ([`8df87ff`](https://github.com/nucypher/ferveo/commit/8df87ff36ac81bd9e60013cda892d31ddf402868))
    - Apply changes for nucypher-core integration ([`b69949c`](https://github.com/nucypher/ferveo/commit/b69949ca53b24d7f5fc4e71f3a0d7ca8e5d8d034))
    - Update crates to 2021 edition #111 ([`591c05e`](https://github.com/nucypher/ferveo/commit/591c05e64ef9d2f7218418b6aa9d33181c60c88f))
    - Move utils ([`98c49d1`](https://github.com/nucypher/ferveo/commit/98c49d18cee607395ffb65ad0e1dd8e863d28f94))
    - Move wasm bindings ([`7cfe558`](https://github.com/nucypher/ferveo/commit/7cfe55819ca4ae619c46cb63b0668225591931cd))
    - Merge remote-tracking branch 'upstream/main' into zeroize ([`c9b230a`](https://github.com/nucypher/ferveo/commit/c9b230aa011cc537d7d5dcee84cd63a595b471cc))
    - Merge pull request #109 from piotr-roslaniec/static-arrays ([`e75e8b8`](https://github.com/nucypher/ferveo/commit/e75e8b86e228b5456a613d1f4ffd03d2540e23b1))
    - Remove unused packages ([`24d8fb4`](https://github.com/nucypher/ferveo/commit/24d8fb451e244e0ad9287e1ae30b72ffeeb5254b))
    - Ensure dkg pk is serialized to 48 bytes ([`5570c0d`](https://github.com/nucypher/ferveo/commit/5570c0d5bb2ee7a64eac78861c4999d9c98f455a))
    - Merge pull request #102 from piotr-roslaniec/local-verification-wasm ([`aacdf04`](https://github.com/nucypher/ferveo/commit/aacdf0462d73720e97c1d7924fc49e3d252a691a))
    - Js bindings fail to correctly decrypt the ciphertext ([`ae79060`](https://github.com/nucypher/ferveo/commit/ae790601f691a7727489dbd8606dcd6ed0e4106d))
    - Update wasm bindings ([`9215238`](https://github.com/nucypher/ferveo/commit/9215238e30987c13cbe66d4c05b118f9ff49d815))
    - Js bindings fail to correctly decrypt the ciphertext ([`3e7db72`](https://github.com/nucypher/ferveo/commit/3e7db72e5878bfc54b0324c4c79a2a058fc9e0e9))
    - Update wasm bindings ([`1cc7036`](https://github.com/nucypher/ferveo/commit/1cc7036007c05c231f241047ef01e394b8710205))
    - Merge pull request #93 from piotr-roslaniec/local-verification ([`a6ff917`](https://github.com/nucypher/ferveo/commit/a6ff91794d5a8ddd2b9ffcb7b398f58039017a96))
    - Update python bindings ([`a77fc7a`](https://github.com/nucypher/ferveo/commit/a77fc7ac4aa4e2b5bd9a45faa44e40792fc8b65e))
    - Merge branch 'main' into local-verification ([`dd1eccf`](https://github.com/nucypher/ferveo/commit/dd1eccf1575d98d5bec2486452d3aa435faa02da))
    - Merge pull request #100 from piotr-roslaniec/expose-dkg-pk-size ([`bd72ef5`](https://github.com/nucypher/ferveo/commit/bd72ef560fc85defbce29e4de9a8d9bc676239f5))
    - Expose size of dkg public key in bindings ([`661780c`](https://github.com/nucypher/ferveo/commit/661780ce1292ed562828b2ad526de4f4b864e6ac))
    - Merge pull request #95 from piotr-roslaniec/implicit-ordering ([`9fded5b`](https://github.com/nucypher/ferveo/commit/9fded5bbd7b85985644844d31cf391dce52aea97))
    - Sort validator by their address ([`f6cf412`](https://github.com/nucypher/ferveo/commit/f6cf4125f3d2a767eeb98df1db8bd4b69ccdc222))
    - Refactor for 1.64.0 msrv ([`a23500c`](https://github.com/nucypher/ferveo/commit/a23500ca3918cf9456709340b00e1a54f651bb05))
    - Fix examples ([`2d96a30`](https://github.com/nucypher/ferveo/commit/2d96a30778b44335680c508538dc254114439451))
    - Refactor internal ordering tracking ([`6bb4746`](https://github.com/nucypher/ferveo/commit/6bb4746ab1b2c7b0cd3ae7336fb5d8e5415b1abe))
    - Establish the correct ordering with sorting ([`0fd1859`](https://github.com/nucypher/ferveo/commit/0fd1859a2d8dc8ece2fdd576d5fa3e5845ffb53a))
    - Merge pull request #75 from nucypher/release-ferveo-py ([`2529f74`](https://github.com/nucypher/ferveo/commit/2529f743fe6f07935938cbef81faa0230e478f87))
    - Test keypair generation ([`d2b6c30`](https://github.com/nucypher/ferveo/commit/d2b6c30d3c39d79ef17b8649a0410e32236b12ae))
    - Add Keypair::from_secure_randomness method ([`62755ed`](https://github.com/nucypher/ferveo/commit/62755ed05e241adf2187f52ac2586cd32e416ca1))
    - Merge pull request #56 from nucypher/ferveo-light-tdec ([`8fa25b6`](https://github.com/nucypher/ferveo/commit/8fa25b66bf32585b2ef406bbec3999fd9ce75225))
    - Merge pull request #62 from nucypher/client-server-api ([`3a6e3c4`](https://github.com/nucypher/ferveo/commit/3a6e3c4b59c192289f86c0e37f119b29ccd3d620))
    - Merge pull request #67 from nucypher/arkworks-0.4 ([`bd78f97`](https://github.com/nucypher/ferveo/commit/bd78f9741246a2118bf6e3fdf48c72d6adf51b9e))
    - Merge pull request #68 from nucypher/error-handling ([`093f17e`](https://github.com/nucypher/ferveo/commit/093f17e22f606b33a468bd62ad37cf22f3dda265))
    - Merge branch 'error-handling' into tpke-wasm-api-example ([`707f460`](https://github.com/nucypher/ferveo/commit/707f460666acc2781d6dcfa49e0f75f1159f466f))
    - Merge branch 'error-handling' into release-ferveo-py ([`d2a0ca0`](https://github.com/nucypher/ferveo/commit/d2a0ca045beb4dd298f2c06b20b313456a1e81f9))
    - Sketch error handling in ferveo ([`a68d2d9`](https://github.com/nucypher/ferveo/commit/a68d2d9b62414fd06afa234f240508d1c41e68a8))
    - Refactor serialization ([`b9535fe`](https://github.com/nucypher/ferveo/commit/b9535fefae0795f4b43f726378c5c65d0e776937))
    - Trim external apis ([`0b95048`](https://github.com/nucypher/ferveo/commit/0b9504833ff4025236d9821c5bdc40e66f6774d6))
    - Replace unwrap calls with result type ([`a9b4331`](https://github.com/nucypher/ferveo/commit/a9b4331c3755a0bb0dc0ca5cc355a892dc13d7d3))
    - Remove unused crates ([`f876b85`](https://github.com/nucypher/ferveo/commit/f876b85732a31970a421f1a75c54a2a17aa48e95))
    - Update arkworks to 0.4.0 - first pass ([`b1999b8`](https://github.com/nucypher/ferveo/commit/b1999b86a2b04c719ec29b1263612de88a0cfd49))
    - Fix import style ([`6d92b01`](https://github.com/nucypher/ferveo/commit/6d92b010139b915da1a89ffa686bf24871c7afd1))
    - Simple tdec on client side fails ([`7257843`](https://github.com/nucypher/ferveo/commit/7257843a9722f4a63bfbe82fcfbaf2088711dfb6))
    - Add ferveo-python example ([`fd47f97`](https://github.com/nucypher/ferveo/commit/fd47f97510fad4132712dc58714c19fc0fd0d7e4))
    - Merge branch 'main' into use-sha256 ([`fa1c1a8`](https://github.com/nucypher/ferveo/commit/fa1c1a8bf2b338cb379a481d8b042c45af23c470))
    - Merge pull request #27 from nucypher/dkg-pvss-flow ([`e842b8a`](https://github.com/nucypher/ferveo/commit/e842b8a5bb2cafe2e768ca29e5f0210f969ea748))
    - Documents and refactor code ([`6fb4c89`](https://github.com/nucypher/ferveo/commit/6fb4c890cef5c1ca077d301bf4e3e12c78584d39))
    - Remove unused code ([`002d407`](https://github.com/nucypher/ferveo/commit/002d407d1f592af1de836af1f5030b9baa423b90))
    - Rename TendermintValidator to ExternalValidator ([`8bd2888`](https://github.com/nucypher/ferveo/commit/8bd2888a95ec91686ce8e62da1533459dc159469))
    - Remove ValidatorSet ([`60e4c6f`](https://github.com/nucypher/ferveo/commit/60e4c6f26c6cc2041ba66cd6697db3bae66ff04e))
    - Simple threshold decryption works ([`d3c76cd`](https://github.com/nucypher/ferveo/commit/d3c76cde43f13a9a7c24d24511acbd980b5b6e44))
    - Initial removal of share partitioning ([`ab2857d`](https://github.com/nucypher/ferveo/commit/ab2857d7d30627753ca2ae2a3550284d73d56fec))
    - Documents and refactor code ([`8f7308b`](https://github.com/nucypher/ferveo/commit/8f7308b380483349dc744cc6665b7f7bc9412ded))
    - Remove unused code ([`fb05e62`](https://github.com/nucypher/ferveo/commit/fb05e62fdb784b5b68b80040677a01386eb61141))
    - Rename TendermintValidator to ExternalValidator ([`995fdce`](https://github.com/nucypher/ferveo/commit/995fdcedf42ee3bacdd66689852fcc2f3d5f9794))
    - Remove ValidatorSet ([`4f62c70`](https://github.com/nucypher/ferveo/commit/4f62c704156c9929754bf16a5fd801bf9908ba3f))
    - Simple threshold decryption works ([`856790c`](https://github.com/nucypher/ferveo/commit/856790c48d882c87275ddf6d87bbeb1a31ad559b))
    - Initial removal of share partitioning ([`9d38f62`](https://github.com/nucypher/ferveo/commit/9d38f62f5ae7f4a4b25e149e84aad77a02bc4a03))
    - Merge pull request #10 from piotr-roslaniec/wasm-bindings ([`f26552d`](https://github.com/nucypher/ferveo/commit/f26552db645e095fb4df6732aa38e1fff1401d72))
    - Update after rebase ([`b8b2392`](https://github.com/nucypher/ferveo/commit/b8b2392de11068acde07895dc9b6897a742b9b2d))
    - Add wasm setup ([`ca2e46e`](https://github.com/nucypher/ferveo/commit/ca2e46e67637ce34d531da03124523fb567b7002))
    - Merge pull request #8 from piotr-roslaniec/aad#1 ([`41b5408`](https://github.com/nucypher/ferveo/commit/41b54081c2061126fa8d661207e13aa74406733f))
    - Address some clippy warnings ([`e8087d2`](https://github.com/nucypher/ferveo/commit/e8087d23ec6d1845585016259e51cc173160bb92))
    - Merge pull request #76 from anoma/bat/ferveo-common-canonical-serialize ([`8363c33`](https://github.com/nucypher/ferveo/commit/8363c33d1cf79f93ce9fa89d4b5fe998a5a78c26))
    - Made ferveo-common wasm compatible (a tiny change). Fixes a world of pain upstream in Anoma ([`ab67016`](https://github.com/nucypher/ferveo/commit/ab6701666e3b05bd783ce0309025e842fa83e4c1))
    - Merge pull request #73 from anoma/bat/announcement-refactor ([`9786ac0`](https://github.com/nucypher/ferveo/commit/9786ac0c9d70f0b73fb2303405db730c98e06440))
    - Formatting ([`d786fae`](https://github.com/nucypher/ferveo/commit/d786fae33b01cd0863f29b70810dfcc847f2542b))
    - Removed the announce phase from the dkg ([`ec58fe1`](https://github.com/nucypher/ferveo/commit/ec58fe1828d0560525c80cd1dc4013915b0ac54e))
    - Merge pull request #65 from anoma/joe/20210922 ([`d6d603f`](https://github.com/nucypher/ferveo/commit/d6d603fbe82706525a194f42cbab9c3431dd7cc4))
    - Latest ferveo ([`0f17c3b`](https://github.com/nucypher/ferveo/commit/0f17c3be5cfa55b5f878defcb74ab2b4e13c3190))
</details>

## 0.1.1 (2023-08-28)

Maintenance release

## v0.1.0 (2023-07-07)

<csr-id-ab6701666e3b05bd783ce0309025e842fa83e4c1/>
<csr-id-d786fae33b01cd0863f29b70810dfcc847f2542b/>
<csr-id-ec58fe1828d0560525c80cd1dc4013915b0ac54e/>
<csr-id-0eb5bd48b598709dd0fc54adb424f5f41ce52e92/>

### Other

 - <csr-id-ab6701666e3b05bd783ce0309025e842fa83e4c1/> Made ferveo-common wasm compatible (a tiny change). Fixes a world of pain upstream in Anoma
 - <csr-id-d786fae33b01cd0863f29b70810dfcc847f2542b/> Formatting
 - <csr-id-ec58fe1828d0560525c80cd1dc4013915b0ac54e/> Removed the announce phase from the dkg

### Chore

 - <csr-id-0eb5bd48b598709dd0fc54adb424f5f41ce52e92/> adjust changelogs for cargo-smart-release

