# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0-alpha (2025-06-10)

<csr-id-983110c4dbb41eb7f0fba2c06f561b68718d0f29/>
<csr-id-802e7121d5eb5a31617bf88c4e14fe79d45e68e3/>
<csr-id-58002f50155df31a11b9d58d94750a2ed1076102/>
<csr-id-47138489bc9567674b57d61b0d105ff6c1c7cb6c/>
<csr-id-0ef7de4c9b4442e2c6125d457de9420146be50b7/>
<csr-id-8b26396cc26ceeddca52dc37ac9461f0bb93ecfe/>
<csr-id-4a8375d1873560241ae8eea96230a42635ed1764/>
<csr-id-6e3369d11cfd4ec751775e1eee82f8192b51943e/>
<csr-id-315d2b4cc2825e13820d9c64639490c44b538385/>

### Chore

 - <csr-id-983110c4dbb41eb7f0fba2c06f561b68718d0f29/> move shared dependencies to workspace crate
 - <csr-id-802e7121d5eb5a31617bf88c4e14fe79d45e68e3/> remove duplicated field
 - <csr-id-58002f50155df31a11b9d58d94750a2ed1076102/> rename ferveo-tpke package to ferveo-tdec

### Bug Fixes

 - <csr-id-975dae0d5f8d1a2e5c061fbc8d11b1cc73c867d7/> not using subset of participants in precomputed variant

### Other

 - <csr-id-47138489bc9567674b57d61b0d105ff6c1c7cb6c/> introduce refreshing api in ferveo

### Refactor

 - <csr-id-0ef7de4c9b4442e2c6125d457de9420146be50b7/> rename public key share to public key
 - <csr-id-8b26396cc26ceeddca52dc37ac9461f0bb93ecfe/> avoid using crypto primitives directly, part 1

### Test

 - <csr-id-4a8375d1873560241ae8eea96230a42635ed1764/> fix tests sensitive to message ordering

### Other (BREAKING)

 - <csr-id-6e3369d11cfd4ec751775e1eee82f8192b51943e/> remove fast variant
 - <csr-id-315d2b4cc2825e13820d9c64639490c44b538385/> remove state from dkg, part 1

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 38 commits contributed to the release over the course of 580 calendar days.
 - 10 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release ferveo-common-nucypher-temp4 v0.4.0-alpha, subproductdomain-nucypher-temp4 v0.4.0-alpha, ferveo-tdec-temp4 v0.4.0-alpha, ferveo-nucypher-temp4 v0.4.0-alpha ([`b962402`](https://github.com/nucypher/ferveo/commit/b96240209bea70d43016a66301af9bf5fe5a8970))
    - Cargo stuff ([`888535c`](https://github.com/nucypher/ferveo/commit/888535c2b932f855e6080ad388f5a800644cc607))
    - Refactor domain points ([`7320560`](https://github.com/nucypher/ferveo/commit/7320560a0524248ae1683f3623ee4b9e0f2c74e1))
    - Merge pull request #186 from cygnusv/spongebob ([`bc64858`](https://github.com/nucypher/ferveo/commit/bc6485811b40b1025115159a2504f49fac4789a8))
    - Link some TODOs and FIXMEs with issues ([`f7a0065`](https://github.com/nucypher/ferveo/commit/f7a00658cd121c2c1304d3ea628240765053515d))
    - Remove generator inverse from API ([`bf1cf0f`](https://github.com/nucypher/ferveo/commit/bf1cf0fd965edb3e7530ccefab428d1dad08c9dd))
    - Remove unnecessary code in context.rs ([`0efb567`](https://github.com/nucypher/ferveo/commit/0efb567655f681d6f007fe1624c7d60515d0423b))
    - Code areas marked for refactor or removal ([`35eb653`](https://github.com/nucypher/ferveo/commit/35eb65318e24e689bb5370895b75aa7ab2827eaa))
    - Consider encrypt_in_place for AEAD ([`ee98c24`](https://github.com/nucypher/ferveo/commit/ee98c249c0bba582af26d304d329e69676e97d45))
    - Consider using multipairings ([`a3f607d`](https://github.com/nucypher/ferveo/commit/a3f607dcf5961973ad365f5bb5ed14d5272d3547))
    - Use PublicKeys instead of internal G2 type when possible ([`8296118`](https://github.com/nucypher/ferveo/commit/8296118807587b04a6773c9edb2116635c1a349a))
    - Explicitly rename DKG PublicKeys to avoid confusion with Validator PKs ([`dceac71`](https://github.com/nucypher/ferveo/commit/dceac71f876f4f5f487aa3538697efa35a64d861))
    - Add TODO about using explicit imports (see #194) ([`cff8dfd`](https://github.com/nucypher/ferveo/commit/cff8dfd2940a70d595d959b417f7cec16c57a4eb))
    - Assorted cleanup ([`b3df880`](https://github.com/nucypher/ferveo/commit/b3df8808f391cb1710be507725277e3ad08a6bdc))
    - PrivateKeys are never blinded directly ([`b8a4c5c`](https://github.com/nucypher/ferveo/commit/b8a4c5ca0ec40bc14a541c087f8b2e85cc0c8297))
    - Tidy up imports in several places ([`8a52e07`](https://github.com/nucypher/ferveo/commit/8a52e07e2883794fa945be04d82af6301a48bf19))
    - Pass Keypairs as input to unblind BlindedKeyShares ([`bad0d3b`](https://github.com/nucypher/ferveo/commit/bad0d3bf1aad626c4b6af7cf0ffa8f83654728f1))
    - Some tests fixed: share updating should be done on top of blinded shares ([`ec9e368`](https://github.com/nucypher/ferveo/commit/ec9e3687799526c2567321cfa981e823e150204a))
    - Yay! Tests work when blinding is deactivated, so the problem is unblinding ([`ba6cd93`](https://github.com/nucypher/ferveo/commit/ba6cd93670403ac0ea4a64e87cb49c535b46dcaa))
    - Clarifying some refresh tests ([`1020d00`](https://github.com/nucypher/ferveo/commit/1020d007afd8472bde2da93d16a9a5d58df80b24))
    - Distinction between ShareCommitments and TDec PublicKeys ([`0cfa02e`](https://github.com/nucypher/ferveo/commit/0cfa02e836796a894ea0cecec70bce34ffae30e4))
    - Merge pull request #189 from piotr-roslaniec/workspace-deps ([`be98542`](https://github.com/nucypher/ferveo/commit/be9854252fdff297d99a63eb443a473ecfd41f5a))
    - Move shared dependencies to workspace crate ([`983110c`](https://github.com/nucypher/ferveo/commit/983110c4dbb41eb7f0fba2c06f561b68718d0f29))
    - Merge pull request #187 from piotr-roslaniec/remove-fast-variant ([`b72a338`](https://github.com/nucypher/ferveo/commit/b72a33803852bfaf444d6c2c4a278f93f334ab89))
    - Remove fast variant ([`6e3369d`](https://github.com/nucypher/ferveo/commit/6e3369d11cfd4ec751775e1eee82f8192b51943e))
    - Merge pull request #185 from piotr-roslaniec/aggregate-from-subset ([`299a471`](https://github.com/nucypher/ferveo/commit/299a471d2ee658ca374c3400ccac8fd24bb8d1a1))
    - Merge pull request #183 from piotr-roslaniec/remove-dkg-state ([`aa69b36`](https://github.com/nucypher/ferveo/commit/aa69b364a57c511f96f8c2f1b1f0c36ab2309e50))
    - Not using subset of participants in precomputed variant ([`975dae0`](https://github.com/nucypher/ferveo/commit/975dae0d5f8d1a2e5c061fbc8d11b1cc73c867d7))
    - Fix tests sensitive to message ordering ([`4a8375d`](https://github.com/nucypher/ferveo/commit/4a8375d1873560241ae8eea96230a42635ed1764))
    - Merge pull request #175 from piotr-roslaniec/rewrite-refreshing ([`2c97934`](https://github.com/nucypher/ferveo/commit/2c97934251c04754b8c5353492823e3a97dc53a9))
    - Rename public key share to public key ([`0ef7de4`](https://github.com/nucypher/ferveo/commit/0ef7de4c9b4442e2c6125d457de9420146be50b7))
    - Remove state from dkg, part 1 ([`315d2b4`](https://github.com/nucypher/ferveo/commit/315d2b4cc2825e13820d9c64639490c44b538385))
    - Introduce refreshing api in ferveo ([`4713848`](https://github.com/nucypher/ferveo/commit/47138489bc9567674b57d61b0d105ff6c1c7cb6c))
    - Avoid using crypto primitives directly, part 1 ([`8b26396`](https://github.com/nucypher/ferveo/commit/8b26396cc26ceeddca52dc37ac9461f0bb93ecfe))
    - Merge pull request #171 from piotr-roslaniec/python-versions ([`de9cf36`](https://github.com/nucypher/ferveo/commit/de9cf36ad88a0242e43bbc6339eb840b6d97d88c))
    - Remove duplicated field ([`802e712`](https://github.com/nucypher/ferveo/commit/802e7121d5eb5a31617bf88c4e14fe79d45e68e3))
    - Merge pull request #166 from nucypher/chores ([`7350d91`](https://github.com/nucypher/ferveo/commit/7350d91708af55b5aa939a3f7e9cd62e7de7359a))
    - Rename ferveo-tpke package to ferveo-tdec ([`58002f5`](https://github.com/nucypher/ferveo/commit/58002f50155df31a11b9d58d94750a2ed1076102))
</details>

## 0.2.0 (2023-08-28)

### New Features (BREAKING)

 - <csr-id-1800d3c5db164947c7cae35433fb8e3ad2650b66/> add ciphertext header to ciphertext api

## v0.1.0 (2023-07-07)

<csr-id-ca43921af214903e2d1345bb05b5f9c6e1987919/>

### Chore

 - <csr-id-ca43921af214903e2d1345bb05b5f9c6e1987919/> adjust changelogs for cargo-smart-release

