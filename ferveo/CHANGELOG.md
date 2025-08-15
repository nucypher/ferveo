# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 (2025-08-15)

### Chore

 - <csr-id-983110c4dbb41eb7f0fba2c06f561b68718d0f29/> move shared dependencies to workspace crate
 - <csr-id-dc2f1675b32f9550bf9333091e8f06ad130397e9/> fix a bad rebase
 - <csr-id-f98a417091644cf7b99b7c4702fadb0629a9d0cf/> relax dkg ceremony constraints
 - <csr-id-72b8484010979d5564dff9f89556f0e1564911e1/> document todos
 - <csr-id-d547a81743fc21679cc2e2d199c7e2f97424fe5d/> remove unused code
 - <csr-id-280c37e8eda75a982b0c281f8da655f149c035df/> remove unused code
 - <csr-id-e79b4e5b05f83d16e23388edb04f2fed4674a355/> document benchmark todos
 - <csr-id-87c5f34fd44dfefe85f345c324535868a70df30a/> fix unused import breaking release compilation
 - <csr-id-0e6c03ee643af057ddae5c275d33879019776c5b/> fix false-positives in cargo machete check
 - <csr-id-749a846bb9a5c129bbc0cf7ff25a84ca6dbdb8a5/> remove unused curves
 - <csr-id-58002f50155df31a11b9d58d94750a2ed1076102/> rename ferveo-tpke package to ferveo-tdec
 - <csr-id-de4cde2db6ac5f87f7675e8956bb4c71f067bb4f/> rename tpke dir to ferveo-tpke
 - <csr-id-99632e8af6477a1e8d46d198fb7144a5c015a49f/> fix linter on stable
 - <csr-id-0eb5bd48b598709dd0fc54adb424f5f41ce52e92/> adjust changelogs for cargo-smart-release

### New Features

 - <csr-id-6670da7df8e0ff8c2210900cdb44a18dfd220892/> enforce canonical share indices instead of validator ordering
 - <csr-id-830cbc859b23c0bf43373bf47c18aedbb54943a2/> add share_index field to validator
 - <csr-id-40cf1c380f682fd99ebeafae8ae296befb3fb81e/> rename group_threshold_cryptography_pre_release crate to ferveo_tpke
 - <csr-id-52efe010264bdd5978111e148190359b9383d53e/> derive eq in DkgPublicKey
 - <csr-id-50511fff3c9829d6f2004360be93b67730f66f1f/> replace FerveoVariant static methods with class atributed
 - <csr-id-e8d05981ee2cc983966c037babeebe5ba0134ffc/> expose ferveo variant in bindings
 - <csr-id-e51656260f2ec8c607add8a63e6832786915b201/> expose missing method

### Bug Fixes

 - <csr-id-975dae0d5f8d1a2e5c061fbc8d11b1cc73c867d7/> not using subset of participants in precomputed variant
 - <csr-id-e903c1ba6f84c9656aa5777b62a0885362c6fa08/> add missing exception definition
 - <csr-id-aebaab39e18a1c114e2aaae62ec9061d49f7a78a/> prevent precomputed shares from being created with inapprioriate variant
 - <csr-id-b8fd959943c604eb0152e6715a13095501b906bb/> allow double allocation when using SecretBox
 - <csr-id-be900653a80e3570300f5a126af98660ab59a7d2/> python typings don't match runtime
 - <csr-id-99ebfecdb7967c4858f918d27ce13cc635c329ac/> dkg serialization in wasm bindings

### Other

 - <csr-id-0117a87d8fd753b60d55570c6587a81d5cfd6051/> introduce refreshing api in ferveo
 - <csr-id-93807a2c92a271e7c0f8ebc31c76604d805fbd7c/> remove deprecated exceptions
 - <csr-id-47138489bc9567674b57d61b0d105ff6c1c7cb6c/> introduce refreshing api in ferveo
 - <csr-id-81bc1cbb7c51db655db859684f29f86150bba072/> relax dkg ceremony constraints
 - <csr-id-e6a7f6e55a34d892e664160f1f8cffe6e88c79da/> prevent panics during transcript aggregation
 - <csr-id-caef6ef73dd43a9952d783fcf18abb893b36635f/> When announcing an aggregation, the resulting key should also be announced and checked so that it can be included on chain
 - <csr-id-159475028209948eb40388458a24b0a086afc311/> Strengthened state guards against aggregation. Necessary for preparing blocks easily
 - <csr-id-d3fb002e52774cd14bff0d1187a2634fad6eea51/> Fixing up the benchmarks to reflect the refactor in dkg
 - <csr-id-d786fae33b01cd0863f29b70810dfcc847f2542b/> Formatting
 - <csr-id-09f26b39ddc71d9a4b1f226e2dafbdb4c51a7caa/> Added retry logic to the dkg
 - <csr-id-ec58fe1828d0560525c80cd1dc4013915b0ac54e/> Removed the announce phase from the dkg

### Refactor

 - <csr-id-b67aef9622d3b7a936ba3f930fb13609ae55a409/> hide g_inv from internat apis
 - <csr-id-ba12d6b861447d4f2017cee37fe075651d114534/> update serde serialization
 - <csr-id-0ef7de4c9b4442e2c6125d457de9420146be50b7/> rename public key share to public key
 - <csr-id-cfa8c990aa166623d4c596f2a4eb5638ab8a8848/> avoid using crypto primitives directly, part 2
 - <csr-id-8b26396cc26ceeddca52dc37ac9461f0bb93ecfe/> avoid using crypto primitives directly, part 1
 - <csr-id-514221ebb052f6757c49c0c7ed2ff097fb878b34/> hide dkg fields in the internal api
 - <csr-id-3d987585e28c5543107af5cb3705af28fae88461/> move a test to a dkg test module
 - <csr-id-4bb41585cd6f93e58bbd047c27fd3e68ab9e723e/> refactor aggregate method params
 - <csr-id-4af8017fa6921c14080dab7790f519cd9394a7d5/> unify share creating methods
 - <csr-id-935be2dc056a8d295fff8c2e937fc23f8fa80f7e/> replace dkg validator with validator
 - <csr-id-52f441cae1ac8ed6c88743082bd2434f3cad9012/> deduplicate test utils
 - <csr-id-66d25aecb5a3e29784f6d2ef1a7977ce4a2d406a/> use test_case crate to deduplicate tests
 - <csr-id-06ae244941d8eb93aff63a4ff1e5088c3deccd1b/> refactor dkg params into a seperate struct

### Test

 - <csr-id-4a8375d1873560241ae8eea96230a42635ed1764/> fix tests sensitive to message ordering
 - <csr-id-9aca6aeeef0f88b5d9968829944caf6aec068398/> document domain point determinism
 - <csr-id-6fd65bd506a0502da39ea4fa292e5fc1669abc27/> update tests for dkgs with relaxed constraints

### New Features (BREAKING)

 - <csr-id-1800d3c5db164947c7cae35433fb8e3ad2650b66/> add ciphertext header to ciphertext api
 - <csr-id-8b6e6f5834d7b736a1d7baf3ddbfa7c60837b9bb/> hide dkg public params from bindings

### Bug Fixes (BREAKING)

 - <csr-id-7388027cb6c77357e8b4d24a891e24a9b4ea2031/> rename wasm method

### Other (BREAKING)

 - <csr-id-6e3369d11cfd4ec751775e1eee82f8192b51943e/> remove fast variant
 - <csr-id-c9f1adc19198464d99d5759391e6b967ab505a70/> remove state from dkg, part 2
 - <csr-id-315d2b4cc2825e13820d9c64639490c44b538385/> remove state from dkg, part 1

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 447 commits contributed to the release.
 - 60 commits were understood as [conventional](https://www.conventionalcommits.org).
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
    - Merge pull request #188 from nucypher/rocknroll ([`1e66268`](https://github.com/nucypher/ferveo/commit/1e66268dfbfbf76566b4bcf6c25a9852692bb380))
    - Merge pull request #211 from derekpierre/mrkrabs ([`763e06b`](https://github.com/nucypher/ferveo/commit/763e06bb2375e2ded95b409e282ae1f491e16d59))
    - Merge pull request #205 from cygnusv/mrkrabs ([`bb51e96`](https://github.com/nucypher/ferveo/commit/bb51e963f552d2ced387d0ac5c4b311f13715eb4))
    - Update cargo.toml of all ferveo packages for public release. ([`d21ea18`](https://github.com/nucypher/ferveo/commit/d21ea1826f81f47ee88a64dcb98678560e691e57))
    - Update cargo.toml of all ferveo packages for test release. ([`000dc17`](https://github.com/nucypher/ferveo/commit/000dc1715c31f2a32f2366feb6ca652b57d40130))
    - Fix formatting based on cargo fmt check. ([`a43e9f1`](https://github.com/nucypher/ferveo/commit/a43e9f1c918994c75958c227f90d4476578eeae6))
    - Sq reminder to randomize ([`9596f58`](https://github.com/nucypher/ferveo/commit/9596f587a50d938e52edb7879db1ba77f981cb03))
    - Sq update wasm ([`c4eaa4a`](https://github.com/nucypher/ferveo/commit/c4eaa4a76f3d93075cefea9d1d19066466ba3b6d))
    - Update wasm-bindgen ([`19e228b`](https://github.com/nucypher/ferveo/commit/19e228b70920b359d93175dfcc5470062832102c))
    - Update cargo.toml of all ferveo packages ([`4e03d43`](https://github.com/nucypher/ferveo/commit/4e03d43255c2fceb729bf2227bff396a25d700c5))
    - Add cargo-smart-release as a dev dependency ([`72c8f1f`](https://github.com/nucypher/ferveo/commit/72c8f1f40eb030ef00c780838985d6a3c3f5c7a2))
    - Update authors ([`380e984`](https://github.com/nucypher/ferveo/commit/380e9840f0b491da002ff02b863230f5824b500e))
    - During refresh, validate share update against the target validator public key ([`9f9fd64`](https://github.com/nucypher/ferveo/commit/9f9fd64e3273191c4a67a3b1205f13b05591fed9))
    - Python binding tests for handover ([`f9ac7c2`](https://github.com/nucypher/ferveo/commit/f9ac7c295e409c8ec265257cea59e71b5d3c6b12))
    - Reminder to randomize ETH addresses in tests ([`5a6d072`](https://github.com/nucypher/ferveo/commit/5a6d0726ab51541ac78b8f0bbea906a75aa93855))
    - Refactor tests in python bindings ([`c8e4c08`](https://github.com/nucypher/ferveo/commit/c8e4c08d2119709fd0f0baf45e8b6d4cfb3971e4))
    - Handover in python bindings ([`833c2b5`](https://github.com/nucypher/ferveo/commit/833c2b5f444cb9ff860dc0783ec7068c4a24e304))
    - High-level API for finalizing handover ([`281c354`](https://github.com/nucypher/ferveo/commit/281c354b939ea43faec7501f9170b594f44d6b1a))
    - Make HandoverTranscript serializable ([`9b9fec1`](https://github.com/nucypher/ferveo/commit/9b9fec12eb61b2d539fab920112035bc7895f498))
    - Unused type ([`1b61817`](https://github.com/nucypher/ferveo/commit/1b6181712fb3cc45c6136136df95ffdaf40ff246))
    - Function to generate handover transcript at the API level ([`b2944e1`](https://github.com/nucypher/ferveo/commit/b2944e1c35442ed038c9eb0218b783efdeb64b08))
    - Function to generate handover transcripts at the DKG level ([`58c3c4d`](https://github.com/nucypher/ferveo/commit/58c3c4dd1314983771206144ae151bce05a17e77))
    - Rename to finalize_handover() at PVSS level ([`f247e58`](https://github.com/nucypher/ferveo/commit/f247e58d610c010f38d17e7ffcce62ba2ab2e2d2))
    - Comments ([`f2566ca`](https://github.com/nucypher/ferveo/commit/f2566ca8f801decf41c50f38dcaa91cdd021ba1a))
    - Use aggregate.get_share_for_validator() ([`2f87562`](https://github.com/nucypher/ferveo/commit/2f87562ac912dd3d7dca2c33d7473cbdd40a41aa))
    - Refactor domain points ([`70ac464`](https://github.com/nucypher/ferveo/commit/70ac4642ad2545114a4ff2a982a11ce764112fd0))
    - Bye bye, PubliclyVerifiableParams ([`24db93f`](https://github.com/nucypher/ferveo/commit/24db93f46672e0edd44270eb1981b492fd1c891e))
    - PubliclyVerifiableDKG now internally maps Validators by index, not address ([`67ea2b7`](https://github.com/nucypher/ferveo/commit/67ea2b71f2c587d69615bf6ef9a30c28ad51ca15))
    - Remove annoying debug message ([`5284d92`](https://github.com/nucypher/ferveo/commit/5284d923faf7ac2ac02671cc46f82f40e93459cb))
    - Merge pull request #198 from cygnusv/gary ([`969a118`](https://github.com/nucypher/ferveo/commit/969a1182582969922202293d4f492c9cce5a651d))
    - Some additional test clarifications ([`f0f342b`](https://github.com/nucypher/ferveo/commit/f0f342bf58dbfe3c2b5f473ad50ca63ebb30c468))
    - High-level test showing handover using the PVSS API ([`cdf2c2f`](https://github.com/nucypher/ferveo/commit/cdf2c2f14236c9f4aa42dccbb727911f9dabbfd6))
    - Additional pvss-level checks before and after handover ([`7b5ff45`](https://github.com/nucypher/ferveo/commit/7b5ff45b709a6ce9b13124e15093d29918684780))
    - Simplify do_verify_full and do_verify_aggregation API ([`eccc0e3`](https://github.com/nucypher/ferveo/commit/eccc0e304a411f896d6e83d744581dd271ec843a))
    - Function to validate single share from transcript components ([`9980328`](https://github.com/nucypher/ferveo/commit/9980328a0da5036e672e250ed621d787d765ef1f))
    - First pass at handover function at PVSS level ([`7d7a761`](https://github.com/nucypher/ferveo/commit/7d7a761ae55dd52f54b5e330d54db6d90653cec8))
    - Add share index to HandoverTranscript struct ([`4d6f8a4`](https://github.com/nucypher/ferveo/commit/4d6f8a41760869697fd117ef496569a223abe1f8))
    - Always validate handover transcripts when finalizing them ([`653edd3`](https://github.com/nucypher/ferveo/commit/653edd353be98d6ac2159b8150d751e5a917cb91))
    - Extract function to generate share commitments from transcript poly commitments ([`4156211`](https://github.com/nucypher/ferveo/commit/4156211fd5d6fdc703fa7b2e9cf136c293650ff2))
    - Linting ([`5bf2f80`](https://github.com/nucypher/ferveo/commit/5bf2f80e103447c328974c18176ba1c5cfe8df77))
    - Function to finalize handover by the departing participant ([`f7f1230`](https://github.com/nucypher/ferveo/commit/f7f1230b5bdd1769aa391e22bf6ff2de106fa04a))
    - Extend test to show handover can finalize correctly ([`852ca44`](https://github.com/nucypher/ferveo/commit/852ca44e186503744cb92d6959ba527eb54103c4))
    - Draft for testing handover transcripts ([`9ac5f88`](https://github.com/nucypher/ferveo/commit/9ac5f88801e2cdf422a9cdad2cbe55ae12730c6c))
    - First draft of HandoverTranscript - a.k.a. The Baton ([`3a4b356`](https://github.com/nucypher/ferveo/commit/3a4b3568e9e9efe539069e53604098712e16a227))
    - Merge pull request #186 from cygnusv/spongebob ([`bc64858`](https://github.com/nucypher/ferveo/commit/bc6485811b40b1025115159a2504f49fac4789a8))
    - Link some TODOs and FIXMEs with issues ([`f7a0065`](https://github.com/nucypher/ferveo/commit/f7a00658cd121c2c1304d3ea628240765053515d))
    - Remove generator inverse from API ([`bf1cf0f`](https://github.com/nucypher/ferveo/commit/bf1cf0fd965edb3e7530ccefab428d1dad08c9dd))
    - Remove unnecessary code in context.rs ([`0efb567`](https://github.com/nucypher/ferveo/commit/0efb567655f681d6f007fe1624c7d60515d0423b))
    - At the API level, use local type for Refresh Transcripts ([`664f8ea`](https://github.com/nucypher/ferveo/commit/664f8eae55e0d27cddc49b1996e128bb2879c004))
    - Common test parameters for shares_num and threshold ([`66bfd37`](https://github.com/nucypher/ferveo/commit/66bfd37cb705e4e4e0862b0aa5c4c1c6d3fee698))
    - Code areas marked for refactor or removal ([`35eb653`](https://github.com/nucypher/ferveo/commit/35eb65318e24e689bb5370895b75aa7ab2827eaa))
    - Fix share refresh test at the API level! ([`096b91c`](https://github.com/nucypher/ferveo/commit/096b91c12fad2da9f1969f24a8d9e2be98388f1b))
    - Add refresh functionality at API level ([`b6aac7d`](https://github.com/nucypher/ferveo/commit/b6aac7d1bad08d3d823aeeb27c6fe730b26185a1))
    - New AggregatedTranscript constructor from an existing aggregate ([`5c797aa`](https://github.com/nucypher/ferveo/commit/5c797aab811576e63ef97071df155555672dead1))
    - Consider using multipairings ([`a3f607d`](https://github.com/nucypher/ferveo/commit/a3f607dcf5961973ad365f5bb5ed14d5272d3547))
    - Generating random DKG public keys should only be a test function ([`031aad5`](https://github.com/nucypher/ferveo/commit/031aad5788fae91e58fb0dd0831336ddf17b0b4f))
    - Use PublicKeys instead of internal G2 type when possible ([`8296118`](https://github.com/nucypher/ferveo/commit/8296118807587b04a6773c9edb2116635c1a349a))
    - Explicitly rename DKG PublicKeys to avoid confusion with Validator PKs ([`dceac71`](https://github.com/nucypher/ferveo/commit/dceac71f876f4f5f487aa3538697efa35a64d861))
    - Assorted cleanup ([`b3df880`](https://github.com/nucypher/ferveo/commit/b3df8808f391cb1710be507725277e3ad08a6bdc))
    - Tidy up imports in several places ([`8a52e07`](https://github.com/nucypher/ferveo/commit/8a52e07e2883794fa945be04d82af6301a48bf19))
    - Pass Keypairs as input to unblind BlindedKeyShares ([`bad0d3b`](https://github.com/nucypher/ferveo/commit/bad0d3bf1aad626c4b6af7cf0ffa8f83654728f1))
    - Recovery tests are broken. Marked as ignored and adjusted to compile ([`8f37b71`](https://github.com/nucypher/ferveo/commit/8f37b71023e7d66740446434d88a091abc9a87d8))
    - Point out that aggregate coefficients need to be updated too ([`48a5463`](https://github.com/nucypher/ferveo/commit/48a546334d7abcb0307b624d1ef983a4dd5cef18))
    - Fix test_dkg_simple_tdec_share_refreshing test! ([`1990248`](https://github.com/nucypher/ferveo/commit/1990248b04269a20e4f954fa86557216844ee701))
    - DKG level method for validators to create refresh transcripts ([`cd44ebe`](https://github.com/nucypher/ferveo/commit/cd44ebe0d0f5d0b10aa26cec6523135872075a40))
    - Method to refresh an AggregateTranscript ([`9515704`](https://github.com/nucypher/ferveo/commit/951570477116d60443510848e4ab6c6311d226da))
    - Use UpdateTranscripts as input to update BlindedKeyShares ([`69b5099`](https://github.com/nucypher/ferveo/commit/69b509916833697bda5ea4bc93039d33d09fbbef))
    - Basic refresh tests work again! ([`a620dfd`](https://github.com/nucypher/ferveo/commit/a620dfd16ffd82033da0198ff46dfbb6e8248583))
    - Don't update private key shares directly at the PVSS level ([`f83a860`](https://github.com/nucypher/ferveo/commit/f83a860ca55c2adcd2c587cef87a70e13c36c880))
    - Use BlindedKeyShare at the PVSS level ([`13adb7b`](https://github.com/nucypher/ferveo/commit/13adb7ba99e95bc8c0e19c62ab12b7a9cd4d3909))
    - Introduce UpdatableBlindedKeyShare as part of refresh API ([`f7d04bc`](https://github.com/nucypher/ferveo/commit/f7d04bcb5969cd6bd52b3c615365ddf6ce475eef))
    - Preparing for refactor 3 ([`7a08698`](https://github.com/nucypher/ferveo/commit/7a08698b480fcb68aaf2b96018220178f6d91ddc))
    - Preparing refactor 2 ([`bf44976`](https://github.com/nucypher/ferveo/commit/bf449765be4bcfe48625a393bef1b2bf7f292272))
    - Preparing refactor ([`dae4d4e`](https://github.com/nucypher/ferveo/commit/dae4d4e3a4a3ac432761dc88a90a29d64e15cb84))
    - Code quality ([`956032f`](https://github.com/nucypher/ferveo/commit/956032ff964e7ace5cf0025c29af52d6a6a074c3))
    - Comments ([`3bf9014`](https://github.com/nucypher/ferveo/commit/3bf9014faf3521fc602b5dd1a644f04cf761fd43))
    - UpdateTranscript validation: poly commitments fit the update type ([`60268c3`](https://github.com/nucypher/ferveo/commit/60268c371242b7f0f185e30bdb96390bf0adec4b))
    - Cargo-fix'n stuff ([`418b204`](https://github.com/nucypher/ferveo/commit/418b2048646c2fb7a847057562d18c04fc9741a3))
    - UpdateTranscript validation: add consistency checks with update poly ([`c83e2d9`](https://github.com/nucypher/ferveo/commit/c83e2d92fb8385e5bca009e0d5e2a4f791fa5ea6))
    - First version of UpdateTranscript validation ([`50b2259`](https://github.com/nucypher/ferveo/commit/50b22590ea5cb09ee81c777b13dc49dc026d4d1d))
    - Use UpdateTranscripts instead of ShareUpdate ([`b63c927`](https://github.com/nucypher/ferveo/commit/b63c927378076556a8e1f50e996d1c4837901402))
    - Move methods to create updates from ShareUpdate to UpdateTranscript ([`40df9ae`](https://github.com/nucypher/ferveo/commit/40df9aefa24cf81bf1730ebfaa0171871d394c73))
    - UpdateTranscript struct to encapsulate updates and poly commitments ([`cac942a`](https://github.com/nucypher/ferveo/commit/cac942a591f34ba3440c1f53318915ad96ceb47b))
    - Verify share update in first tests ([`e7704db`](https://github.com/nucypher/ferveo/commit/e7704dbedcf593cd3b03708bd2f8d8c44b891e6a))
    - Clarification ([`86469bc`](https://github.com/nucypher/ferveo/commit/86469bc388fded0978efee19ade8a4a317ac0279))
    - ShareUpdate verification method ([`bf94aba`](https://github.com/nucypher/ferveo/commit/bf94aba7be8d480cd54374ea9fe4a0bcf85ed27c))
    - Some tests fixed: share updating should be done on top of blinded shares ([`ec9e368`](https://github.com/nucypher/ferveo/commit/ec9e3687799526c2567321cfa981e823e150204a))
    - Clarifying some refresh tests ([`1020d00`](https://github.com/nucypher/ferveo/commit/1020d007afd8472bde2da93d16a9a5d58df80b24))
    - Jammin' with Piotr: draft of share update helpers with verifiability ([`574d0ba`](https://github.com/nucypher/ferveo/commit/574d0ba63f5c239f6ebd53320c17d03e84e6bdd3))
    - Merge pull request #189 from piotr-roslaniec/workspace-deps ([`be98542`](https://github.com/nucypher/ferveo/commit/be9854252fdff297d99a63eb443a473ecfd41f5a))
    - Move shared dependencies to workspace crate ([`983110c`](https://github.com/nucypher/ferveo/commit/983110c4dbb41eb7f0fba2c06f561b68718d0f29))
    - Merge pull request #187 from piotr-roslaniec/remove-fast-variant ([`b72a338`](https://github.com/nucypher/ferveo/commit/b72a33803852bfaf444d6c2c4a278f93f334ab89))
    - Remove fast variant ([`6e3369d`](https://github.com/nucypher/ferveo/commit/6e3369d11cfd4ec751775e1eee82f8192b51943e))
    - Fix a bad rebase ([`dc2f167`](https://github.com/nucypher/ferveo/commit/dc2f1675b32f9550bf9333091e8f06ad130397e9))
    - Merge pull request #185 from piotr-roslaniec/aggregate-from-subset ([`299a471`](https://github.com/nucypher/ferveo/commit/299a471d2ee658ca374c3400ccac8fd24bb8d1a1))
    - Merge pull request #183 from piotr-roslaniec/remove-dkg-state ([`aa69b36`](https://github.com/nucypher/ferveo/commit/aa69b364a57c511f96f8c2f1b1f0c36ab2309e50))
    - Merge pull request #182 from piotr-roslaniec/domain_points ([`703cbdd`](https://github.com/nucypher/ferveo/commit/703cbdd83451c7e3a0eacdb4f3bdc64839234f69))
    - Not using subset of participants in precomputed variant ([`975dae0`](https://github.com/nucypher/ferveo/commit/975dae0d5f8d1a2e5c061fbc8d11b1cc73c867d7))
    - Fix tests sensitive to message ordering ([`4a8375d`](https://github.com/nucypher/ferveo/commit/4a8375d1873560241ae8eea96230a42635ed1764))
    - Document domain point determinism ([`9aca6ae`](https://github.com/nucypher/ferveo/commit/9aca6aeeef0f88b5d9968829944caf6aec068398))
    - Introduce refreshing api in ferveo ([`0117a87`](https://github.com/nucypher/ferveo/commit/0117a87d8fd753b60d55570c6587a81d5cfd6051))
    - Merge pull request #175 from piotr-roslaniec/rewrite-refreshing ([`2c97934`](https://github.com/nucypher/ferveo/commit/2c97934251c04754b8c5353492823e3a97dc53a9))
    - Remove deprecated exceptions ([`93807a2`](https://github.com/nucypher/ferveo/commit/93807a2c92a271e7c0f8ebc31c76604d805fbd7c))
    - Hide g_inv from internat apis ([`b67aef9`](https://github.com/nucypher/ferveo/commit/b67aef9622d3b7a936ba3f930fb13609ae55a409))
    - Update serde serialization ([`ba12d6b`](https://github.com/nucypher/ferveo/commit/ba12d6b861447d4f2017cee37fe075651d114534))
    - Rename public key share to public key ([`0ef7de4`](https://github.com/nucypher/ferveo/commit/0ef7de4c9b4442e2c6125d457de9420146be50b7))
    - Remove state from dkg, part 2 ([`c9f1adc`](https://github.com/nucypher/ferveo/commit/c9f1adc19198464d99d5759391e6b967ab505a70))
    - Remove state from dkg, part 1 ([`315d2b4`](https://github.com/nucypher/ferveo/commit/315d2b4cc2825e13820d9c64639490c44b538385))
    - Introduce refreshing api in ferveo ([`4713848`](https://github.com/nucypher/ferveo/commit/47138489bc9567674b57d61b0d105ff6c1c7cb6c))
    - Avoid using crypto primitives directly, part 2 ([`cfa8c99`](https://github.com/nucypher/ferveo/commit/cfa8c990aa166623d4c596f2a4eb5638ab8a8848))
    - Avoid using crypto primitives directly, part 1 ([`8b26396`](https://github.com/nucypher/ferveo/commit/8b26396cc26ceeddca52dc37ac9461f0bb93ecfe))
    - Merge pull request #173 from piotr-roslaniec/relax-dkg-ceremony ([`a438438`](https://github.com/nucypher/ferveo/commit/a438438418fbc27eef63e0847f3b3577b8d37a2b))
    - Apply pr suggestions ([`61d6e64`](https://github.com/nucypher/ferveo/commit/61d6e641ecaf81c3bbc2febec0aa5d73cccfd8b7))
    - Merge pull request #172 from piotr-roslaniec/external-share-idx ([`15776e7`](https://github.com/nucypher/ferveo/commit/15776e73f1086f299ab592492157728e84c2007f))
    - Update tests for dkgs with relaxed constraints ([`6fd65bd`](https://github.com/nucypher/ferveo/commit/6fd65bd506a0502da39ea4fa292e5fc1669abc27))
    - Hide dkg fields in the internal api ([`514221e`](https://github.com/nucypher/ferveo/commit/514221ebb052f6757c49c0c7ed2ff097fb878b34))
    - Move a test to a dkg test module ([`3d98758`](https://github.com/nucypher/ferveo/commit/3d987585e28c5543107af5cb3705af28fae88461))
    - Relax dkg ceremony constraints ([`81bc1cb`](https://github.com/nucypher/ferveo/commit/81bc1cbb7c51db655db859684f29f86150bba072))
    - Relax dkg ceremony constraints ([`f98a417`](https://github.com/nucypher/ferveo/commit/f98a417091644cf7b99b7c4702fadb0629a9d0cf))
    - Add missing exception definition ([`e903c1b`](https://github.com/nucypher/ferveo/commit/e903c1ba6f84c9656aa5777b62a0885362c6fa08))
    - Document todos ([`72b8484`](https://github.com/nucypher/ferveo/commit/72b8484010979d5564dff9f89556f0e1564911e1))
    - Refactor aggregate method params ([`4bb4158`](https://github.com/nucypher/ferveo/commit/4bb41585cd6f93e58bbd047c27fd3e68ab9e723e))
    - Prevent panics during transcript aggregation ([`e6a7f6e`](https://github.com/nucypher/ferveo/commit/e6a7f6e55a34d892e664160f1f8cffe6e88c79da))
    - Remove unused code ([`d547a81`](https://github.com/nucypher/ferveo/commit/d547a81743fc21679cc2e2d199c7e2f97424fe5d))
    - Unify share creating methods ([`4af8017`](https://github.com/nucypher/ferveo/commit/4af8017fa6921c14080dab7790f519cd9394a7d5))
    - Remove unused code ([`280c37e`](https://github.com/nucypher/ferveo/commit/280c37e8eda75a982b0c281f8da655f149c035df))
    - Replace dkg validator with validator ([`935be2d`](https://github.com/nucypher/ferveo/commit/935be2dc056a8d295fff8c2e937fc23f8fa80f7e))
    - Enforce canonical share indices instead of validator ordering ([`6670da7`](https://github.com/nucypher/ferveo/commit/6670da7df8e0ff8c2210900cdb44a18dfd220892))
    - Add share_index field to validator ([`830cbc8`](https://github.com/nucypher/ferveo/commit/830cbc859b23c0bf43373bf47c18aedbb54943a2))
    - Merge pull request #171 from piotr-roslaniec/python-versions ([`de9cf36`](https://github.com/nucypher/ferveo/commit/de9cf36ad88a0242e43bbc6339eb840b6d97d88c))
    - Prevent precomputed shares from being created with inapprioriate variant ([`aebaab3`](https://github.com/nucypher/ferveo/commit/aebaab39e18a1c114e2aaae62ec9061d49f7a78a))
    - Document benchmark todos ([`e79b4e5`](https://github.com/nucypher/ferveo/commit/e79b4e5b05f83d16e23388edb04f2fed4674a355))
    - Allow double allocation when using SecretBox ([`b8fd959`](https://github.com/nucypher/ferveo/commit/b8fd959943c604eb0152e6715a13095501b906bb))
    - Deduplicate test utils ([`52f441c`](https://github.com/nucypher/ferveo/commit/52f441cae1ac8ed6c88743082bd2434f3cad9012))
    - Use test_case crate to deduplicate tests ([`66d25ae`](https://github.com/nucypher/ferveo/commit/66d25aecb5a3e29784f6d2ef1a7977ce4a2d406a))
    - Refactor dkg params into a seperate struct ([`06ae244`](https://github.com/nucypher/ferveo/commit/06ae244941d8eb93aff63a4ff1e5088c3deccd1b))
    - Merge pull request #166 from nucypher/chores ([`7350d91`](https://github.com/nucypher/ferveo/commit/7350d91708af55b5aa939a3f7e9cd62e7de7359a))
    - Fix unused import breaking release compilation ([`87c5f34`](https://github.com/nucypher/ferveo/commit/87c5f34fd44dfefe85f345c324535868a70df30a))
    - Fix false-positives in cargo machete check ([`0e6c03e`](https://github.com/nucypher/ferveo/commit/0e6c03ee643af057ddae5c275d33879019776c5b))
    - Remove unused curves ([`749a846`](https://github.com/nucypher/ferveo/commit/749a846bb9a5c129bbc0cf7ff25a84ca6dbdb8a5))
    - Rename ferveo-tpke package to ferveo-tdec ([`58002f5`](https://github.com/nucypher/ferveo/commit/58002f50155df31a11b9d58d94750a2ed1076102))
    - Rename tpke dir to ferveo-tpke ([`de4cde2`](https://github.com/nucypher/ferveo/commit/de4cde2db6ac5f87f7675e8956bb4c71f067bb4f))
    - Rename group_threshold_cryptography_pre_release crate to ferveo_tpke ([`40cf1c3`](https://github.com/nucypher/ferveo/commit/40cf1c380f682fd99ebeafae8ae296befb3fb81e))
    - Derive eq in DkgPublicKey ([`52efe01`](https://github.com/nucypher/ferveo/commit/52efe010264bdd5978111e148190359b9383d53e))
    - Merge pull request #158 from cygnusv/detection ([`a979fd6`](https://github.com/nucypher/ferveo/commit/a979fd6d15a0f9f7313fbcef08606674566bf64e))
    - Linting and stuff ([`1704f86`](https://github.com/nucypher/ferveo/commit/1704f86c40de0a074878f358fe075a8086bf1a55))
    - TODOs and comments ([`3b3ff48`](https://github.com/nucypher/ferveo/commit/3b3ff487555958255cdd078cd553f534f074b108))
    - Fix test_dkg_simple_tdec_share_refreshing() ([`8407f78`](https://github.com/nucypher/ferveo/commit/8407f781e25761a17179002c59dbc00ea0326d8e))
    - Definitely fix test_dkg_simple_tdec_share_recovery ([`ab5e58c`](https://github.com/nucypher/ferveo/commit/ab5e58c44707a7b52d93ca911ec0d452e4a7a2d7))
    - Almost fix test_dkg_simple_tdec_share_recovery ([`8ef9e7f`](https://github.com/nucypher/ferveo/commit/8ef9e7ff809af400808dbbc750d2afa25a7cde53))
    - Remove incorrect share refresh utility functions ([`ce675a6`](https://github.com/nucypher/ferveo/commit/ce675a61573fa2e43894229d551ea027fccc2e4a))
    - Simplify share refresh test ([`d732196`](https://github.com/nucypher/ferveo/commit/d7321966f7bb67fb3b2d1daa9c8545140e8df5f3))
    - Simplify simple recovery test ([`7c26487`](https://github.com/nucypher/ferveo/commit/7c264874d442d1ef5286499b2d250bb1a63d914e))
    - Make sure test for recovery at original point is correct ([`b65798f`](https://github.com/nucypher/ferveo/commit/b65798f28cd62323adc886aae5b39f13202e23a3))
    - Clarify how the degree in make_random_polynomial_with_root is defined ([`6115976`](https://github.com/nucypher/ferveo/commit/6115976bdf4d07a1a4ea28ad05e1669e2028eaac))
    - Cleaning up the DKG recovery test, in preparation for bug fixing ([`2d30abf`](https://github.com/nucypher/ferveo/commit/2d30abf5b4265ee7b890f07237d49f9d256daa20))
    - Helper functions to prepare share updates for both recovery & refresh ([`39ec865`](https://github.com/nucypher/ferveo/commit/39ec865c02466e727bca067fd59614d7123c5ae5))
    - Rename random polynomial function for refresh & recovery ([`b6d1f41`](https://github.com/nucypher/ferveo/commit/b6d1f416fc96fe637765126b7fe8dca253f94c23))
    - Adapting recovery & refresh tests ([`5c141e1`](https://github.com/nucypher/ferveo/commit/5c141e189c5bf0d33190b9f359f1d7ce589703b8))
    - Relocate refresh.rs module from tpke to ferveo crate ([`372f5d7`](https://github.com/nucypher/ferveo/commit/372f5d7224e2abccbc2b1bbd344f3a761f987f3b))
    - Remove Pvss type alias ([`59aacbb`](https://github.com/nucypher/ferveo/commit/59aacbb2a71e9910daed2d8dabfd491f3e786ba0))
    - Merge pull request #159 from nucypher/set-msrv-wasm-tools ([`0a73aa3`](https://github.com/nucypher/ferveo/commit/0a73aa38950c43fc059d210b43496a6cbaceb341))
    - Fix linter on stable ([`99632e8`](https://github.com/nucypher/ferveo/commit/99632e8af6477a1e8d46d198fb7144a5c015a49f))
    - Release ferveo-common-pre-release v0.1.1, group-threshold-cryptography-pre-release v0.2.0, ferveo-pre-release v0.3.0, safety bump ferveo-pre-release v0.3.0 ([`9c1970b`](https://github.com/nucypher/ferveo/commit/9c1970bb2d9bc36983b041b779a99cb0e95b6ec1))
    - Fix changelogs for cargo-smart-release ([`fe4ec4e`](https://github.com/nucypher/ferveo/commit/fe4ec4ec7667f513b6ebb4bd604303e6ff53a425))
    - Merge pull request #156 from derekpierre/acp ([`e2c4c2e`](https://github.com/nucypher/ferveo/commit/e2c4c2ee9efa20ee2f835530117dd03d67b142fb))
    - Merge pull request #155 from nucypher/update-ciphertext-api ([`bc0a6a5`](https://github.com/nucypher/ferveo/commit/bc0a6a56b9ae63aa6573c6ad045c73356b053058))
    - Apply pr suggestions ([`c06217c`](https://github.com/nucypher/ferveo/commit/c06217c06e16df17d0525027312d5c368f443cb6))
    - SharedSecret wasm-binding now derives AsRef. ([`c3fe68a`](https://github.com/nucypher/ferveo/commit/c3fe68a3214b398db617e687e5244371661a77f7))
    - Merge pull request #149 from cygnusv/thin ([`f44e1be`](https://github.com/nucypher/ferveo/commit/f44e1be4fe9a0a165d8b0b50ad29bb7f6818f672))
    - Appease linter. ([`2c1288b`](https://github.com/nucypher/ferveo/commit/2c1288b1adb983fdb432490d0a64a9a7cd929d76))
    - DkgPublicKey wasm-binding now derives From and AsRef. ([`ce7d280`](https://github.com/nucypher/ferveo/commit/ce7d280c46173297b0d123b54bac6e57e9f9cc36))
    - Add ciphertext header to ciphertext api ([`1800d3c`](https://github.com/nucypher/ferveo/commit/1800d3c5db164947c7cae35433fb8e3ad2650b66))
    - Clippy stuff ([`4337c3c`](https://github.com/nucypher/ferveo/commit/4337c3c312719987405f620f2e377cf493ece6d3))
    - Release ferveo-pre-release v0.2.1 ([`37ea895`](https://github.com/nucypher/ferveo/commit/37ea895e787ae013ffb2c8bb2d738b29a1c32163))
    - Merge pull request #139 from nucypher/fix-typings ([`dc9d81a`](https://github.com/nucypher/ferveo/commit/dc9d81a4128e1966effc11d6e6bb815958482d90))
    - Rename FerveoVariant attributes ([`0e7c561`](https://github.com/nucypher/ferveo/commit/0e7c5615a0660a69077e7b431dd24c5bb3d0f10d))
    - Add __hash__ to FerveoVariant ([`06321d7`](https://github.com/nucypher/ferveo/commit/06321d798fc30768173eec447aed753c34890194))
    - Add equality to FerveoVariant python bindings ([`cea467e`](https://github.com/nucypher/ferveo/commit/cea467e0bd48a096f70dd1c7ca24a7e4bd88b3d4))
    - Apply pr suggestions ([`6c1d4be`](https://github.com/nucypher/ferveo/commit/6c1d4becd89005d6698734caa9d681dde727bff6))
    - Add api conversion method to FerveoVariant ([`fbb97be`](https://github.com/nucypher/ferveo/commit/fbb97be59d991a263233a0b876da982143b2cbf2))
    - Apply pr suggestions ([`7cbe65d`](https://github.com/nucypher/ferveo/commit/7cbe65def65a76043d21763723ce98787cbf8eed))
    - Replace FerveoVariant static methods with class atributed ([`50511ff`](https://github.com/nucypher/ferveo/commit/50511fff3c9829d6f2004360be93b67730f66f1f))
    - Merge pull request #138 from nucypher/development ([`434fd5d`](https://github.com/nucypher/ferveo/commit/434fd5d07b54e72d120e9aa06cbc3e47848e6bcf))
    - Python typings don't match runtime ([`be90065`](https://github.com/nucypher/ferveo/commit/be900653a80e3570300f5a126af98660ab59a7d2))
    - Release ferveo-common-pre-release v0.1.0, subproductdomain-pre-release v0.1.0, group-threshold-cryptography-pre-release v0.1.0, ferveo-pre-release v0.2.0 ([`ffb9b21`](https://github.com/nucypher/ferveo/commit/ffb9b21619d0f5dc0fb309bf2f493d3c0c25e1f0))
    - Adjust changelogs for cargo-smart-release ([`0eb5bd4`](https://github.com/nucypher/ferveo/commit/0eb5bd48b598709dd0fc54adb424f5f41ce52e92))
    - Adjusting changelogs prior to release of ferveo-common-pre-release v0.1.0, subproductdomain-pre-release v0.1.0, group-threshold-cryptography-pre-release v0.1.0, ferveo-pre-release v0.2.0 ([`0ccba13`](https://github.com/nucypher/ferveo/commit/0ccba13b0608e2023d8792ac9b0402af5ebaad0b))
    - Release 0.1.0 crate versions ([`c02e305`](https://github.com/nucypher/ferveo/commit/c02e3050b7a9dcf0260a5eb4e42ff74f3788c3bf))
    - Release ferveo-common-pre-release@0.1.0-alpha.1 ([`2725ba4`](https://github.com/nucypher/ferveo/commit/2725ba455e2ae169af5be64c5f2261ec0c5ea648))
    - Release ferveo-pre-release@0.1.0-alpha.11 ([`f5f102e`](https://github.com/nucypher/ferveo/commit/f5f102e70e6333b572a0726261095b41ee0c42f6))
    - Merge pull request #134 from piotr-roslaniec/remove-ftt-opt ([`2338213`](https://github.com/nucypher/ferveo/commit/23382139265bc043769d41f4da9e0998f9ba9757))
    - Use general evaluation domain ([`2c20efb`](https://github.com/nucypher/ferveo/commit/2c20efb59d7d1075d6b1413b2ae7fbb55c422143))
    - Fix using bad number of domain points ([`d5ec5e0`](https://github.com/nucypher/ferveo/commit/d5ec5e0f9d1303e51a805c4dafbab7ed2efcb7be))
    - Merge remote-tracking branch 'upstream/pk-static-bytes' into development ([`e24d2cf`](https://github.com/nucypher/ferveo/commit/e24d2cf0067ec6d3770819ed1fd0792342d30605))
    - Merge pull request #137 from nucypher/ferveo-variant ([`802ddba`](https://github.com/nucypher/ferveo/commit/802ddba7a7b1694124395a8941e2ec93f0285ebe))
    - Merge pull request #136 from nucypher/pk-static-bytes ([`2b64c2e`](https://github.com/nucypher/ferveo/commit/2b64c2e8e5e594acffde734b65d212fde3df99e9))
    - Expose ferveo variant in bindings ([`e8d0598`](https://github.com/nucypher/ferveo/commit/e8d05981ee2cc983966c037babeebe5ba0134ffc))
    - Precomputed variant fails for non-power-of-two number of shares ([`8f45430`](https://github.com/nucypher/ferveo/commit/8f45430fb8b6198ae7895d8a598b9d0380f1e568))
    - Remove enforcement on number of shares ([`27c55d0`](https://github.com/nucypher/ferveo/commit/27c55d0c818d5a8e42801612519897844863190d))
    - Replace radix2 eval domain to mixed radix eval domain in ferveo ([`aa78183`](https://github.com/nucypher/ferveo/commit/aa7818320fed7b93d6c2e312e5bd7978da5d4717))
    - Benchmarks evaluation domains ([`9d3cb63`](https://github.com/nucypher/ferveo/commit/9d3cb63c2f50e7b556af5f388f4ca8a969907a08))
    - Update serialization tests where possible ([`3bc28d7`](https://github.com/nucypher/ferveo/commit/3bc28d7756567b4d68b262bf51cdeb53f61836fc))
    - Feat! use static arrays in ferveo public key serialization ([`f9ac1d7`](https://github.com/nucypher/ferveo/commit/f9ac1d70b0fc7df286438fa817537c31cb9e7682))
    - Merge pull request #132 from nucypher/development ([`2057782`](https://github.com/nucypher/ferveo/commit/2057782b0b0bb851e3cdf1fdeabdd60345c7eb36))
    - Release ferveo-pre-release@0.1.0-alpha.10 ([`8dc57d3`](https://github.com/nucypher/ferveo/commit/8dc57d3cf4958825830416574528c30d936bd046))
    - Merge pull request #131 from nucypher/fix-validator-msg-stub ([`0d4e973`](https://github.com/nucypher/ferveo/commit/0d4e973e007b16cff34d649ae107608c809349af))
    - Merge pull request #128 from nucypher/fix-dkg-pk-deser-wasm ([`ad22f46`](https://github.com/nucypher/ferveo/commit/ad22f4665d7d662c4fd723c748ebb0f201ceb9a9))
    - Fix ValidatorMessage stub in python bindings ([`4aeda15`](https://github.com/nucypher/ferveo/commit/4aeda15dd749694416f62fda0504f64bcbe2b444))
    - Expose missing method ([`e516562`](https://github.com/nucypher/ferveo/commit/e51656260f2ec8c607add8a63e6832786915b201))
    - Rename wasm method ([`7388027`](https://github.com/nucypher/ferveo/commit/7388027cb6c77357e8b4d24a891e24a9b4ea2031))
    - Dont hide shared deps behind features ([`3863842`](https://github.com/nucypher/ferveo/commit/38638429fcac9b303bf8a76a526a553c163a6e29))
    - Fix after rebase ([`81564a3`](https://github.com/nucypher/ferveo/commit/81564a3297c996b3fe5a9ed3830dc811d7d766ad))
    - Dkg serialization in wasm bindings ([`99ebfec`](https://github.com/nucypher/ferveo/commit/99ebfecdb7967c4858f918d27ce13cc635c329ac))
    - Merge pull request #127 from piotr-roslaniec/hide-dkg-public-params ([`ccdc209`](https://github.com/nucypher/ferveo/commit/ccdc20990ed3ad6ed8267e5dc54745a3a500b730))
    - Hide dkg public params from bindings ([`8b6e6f5`](https://github.com/nucypher/ferveo/commit/8b6e6f5834d7b736a1d7baf3ddbfa7c60837b9bb))
    - Merge pull request #126 from piotr-roslaniec/derive-equals ([`c259bf7`](https://github.com/nucypher/ferveo/commit/c259bf774939340fca0c2b90d3ee2fb2aa4ad947))
    - Merge pull request #125 from nucypher/naming-conflict ([`658af4b`](https://github.com/nucypher/ferveo/commit/658af4b48abbc6a4d0d03706f7c8986eb90e476d))
    - Merge pull request #125 from nucypher/naming-conflict ([`1dde2f1`](https://github.com/nucypher/ferveo/commit/1dde2f12c6d94d96ecfc024f06b5f89e7810720e))
    - Release ferveo-pre-release@0.1.0-alpha.8 ([`0842e87`](https://github.com/nucypher/ferveo/commit/0842e87cdbcb524e5796be021e96ed3c97a3f73d))
    - Update wasm-bindgen-derive to 0.2.1 ([`4a6a43a`](https://github.com/nucypher/ferveo/commit/4a6a43a043346a969ab0e0ed0c7641a7d6f5b376))
    - Merge pull request #119 from nucypher/nucypher-core-integration ([`52c1f27`](https://github.com/nucypher/ferveo/commit/52c1f27627798fa266d2e5079f5121cc71e8e284))
    - Merge pull request #118 from nucypher/expose-bindings-from-main-crate ([`11d6cea`](https://github.com/nucypher/ferveo/commit/11d6ceaf26f45c76dec0c5a9fcf5eae5301502d3))
    - Merge pull request #114 from piotr-roslaniec/python-exceptions ([`87d8f1c`](https://github.com/nucypher/ferveo/commit/87d8f1cf23e27e01c4a91c964a8327b24e4ad360))
    - Export py module making utility ([`3b02634`](https://github.com/nucypher/ferveo/commit/3b026342ade0ae2d02e210d8b7a72c580cc6e08e))
    - Rename PublicKey to FerveoPublicKey in python bindings ([`10cc1df`](https://github.com/nucypher/ferveo/commit/10cc1df897a81041cfef07b99f28e25de1e76ee8))
    - Expose DkgPublicKey.random in WASM bindings ([`d9edeb7`](https://github.com/nucypher/ferveo/commit/d9edeb7e07332b4e0c5960704206ef14f3c4e55c))
    - Bump wasm-bindgen and wasm-bindgen-derive versions ([`1b33424`](https://github.com/nucypher/ferveo/commit/1b334240c5c32334d4812020ca1b04de4b768a77))
    - Expose DkgPublicKey.random ([`48e54bd`](https://github.com/nucypher/ferveo/commit/48e54bd8d45a545b362fdca28f2a9dd92653f151))
    - Expose encrypt from api ([`fb4df1f`](https://github.com/nucypher/ferveo/commit/fb4df1fd727cf047629e0af37e29c1a8f1d7ed09))
    - Fix wasm locals exceeded ([`ac91e83`](https://github.com/nucypher/ferveo/commit/ac91e8359df44b72e5863da74ac71fe54f8eba81))
    - Update README.md ([`3adf188`](https://github.com/nucypher/ferveo/commit/3adf18857cfdcbd37aea78b7fe3f260ce174a805))
    - Publish 0.1.0-alpha.2 ([`8ce4697`](https://github.com/nucypher/ferveo/commit/8ce469734f08511ee3c897d09aa323a8a1ac62fe))
    - Publish ferveo@0.1.0-alpha.1 ([`1db0123`](https://github.com/nucypher/ferveo/commit/1db0123603a6f793e5f6485a89a7e6f0edbdffb1))
    - Fix import in benchmarks ([`1373b19`](https://github.com/nucypher/ferveo/commit/1373b194830162c1eb22b386bd1b12d7c5253df8))
    - Rename PublicKey to FerveoPublicKey in wasm bindings ([`0f399ef`](https://github.com/nucypher/ferveo/commit/0f399ef9b428889f99b65b57d4968b7afff91383))
    - Release pre-release crates ([`8df87ff`](https://github.com/nucypher/ferveo/commit/8df87ff36ac81bd9e60013cda892d31ddf402868))
    - Apply changes for nucypher-core integration ([`b69949c`](https://github.com/nucypher/ferveo/commit/b69949ca53b24d7f5fc4e71f3a0d7ca8e5d8d034))
    - Fix clippy warning ([`494d061`](https://github.com/nucypher/ferveo/commit/494d06174b4afc1caa706297f02389dd6c5ae63a))
    - Update crates to 2021 edition #111 ([`591c05e`](https://github.com/nucypher/ferveo/commit/591c05e64ef9d2f7218418b6aa9d33181c60c88f))
    - Move utils ([`98c49d1`](https://github.com/nucypher/ferveo/commit/98c49d18cee607395ffb65ad0e1dd8e863d28f94))
    - Move wasm bindings ([`7cfe558`](https://github.com/nucypher/ferveo/commit/7cfe55819ca4ae619c46cb63b0668225591931cd))
    - Move python bindings ([`f6c03f7`](https://github.com/nucypher/ferveo/commit/f6c03f76fbe36a78abbdaf41e69de0c8956f7046))
    - Rename InvalidFinalKey error type to InvalidDkgPublicKey ([`9554a4a`](https://github.com/nucypher/ferveo/commit/9554a4ad83e5e826cf04b4de74eb0a092822685a))
    - Expose typed python exceptions ([`6b6f6d7`](https://github.com/nucypher/ferveo/commit/6b6f6d724eeb11c1b638ce51c94f904dec9f73b1))
    - Merge pull request #107 from piotr-roslaniec/zeroize ([`a7eebe5`](https://github.com/nucypher/ferveo/commit/a7eebe57ecbb1aed57410c54710ad79fa6402601))
    - Apply pr suggestions ([`1a48fea`](https://github.com/nucypher/ferveo/commit/1a48fea1c43e038e5f29f9f0a884666ca8dbe9e2))
    - Merge remote-tracking branch 'upstream/main' into zeroize ([`c9b230a`](https://github.com/nucypher/ferveo/commit/c9b230aa011cc537d7d5dcee84cd63a595b471cc))
    - Zeroize plaintext ([`a7e1914`](https://github.com/nucypher/ferveo/commit/a7e1914a7cb677105ffe58d74e02a04afb5fc8a7))
    - Zeroize on drop ([`b2402e7`](https://github.com/nucypher/ferveo/commit/b2402e7eade318efde104220dcf92c390d45ccca))
    - Remove stray file from a bad merge ([`062e776`](https://github.com/nucypher/ferveo/commit/062e7765a893dfc0989ea180f0f9644063958294))
    - Zeroize shared secret ([`54ce650`](https://github.com/nucypher/ferveo/commit/54ce65076c45f937fa0e29a780206f2e32063a92))
    - Merge pull request #109 from piotr-roslaniec/static-arrays ([`e75e8b8`](https://github.com/nucypher/ferveo/commit/e75e8b86e228b5456a613d1f4ffd03d2540e23b1))
    - Remove unused packages ([`24d8fb4`](https://github.com/nucypher/ferveo/commit/24d8fb451e244e0ad9287e1ae30b72ffeeb5254b))
    - Merge remote-tracking branch 'upstream/main' into static-arrays ([`7f663f3`](https://github.com/nucypher/ferveo/commit/7f663f3e006e7a9657f84c1fdfb02d04bde413da))
    - Merge pull request #113 from piotr-roslaniec/fix-simple-tdec-shares ([`85fe85a`](https://github.com/nucypher/ferveo/commit/85fe85aeface8eba8752c00d029e7a200216e9e3))
    - Remove implicit ordering from domain points in public dkg params ([`6ab1df9`](https://github.com/nucypher/ferveo/commit/6ab1df92d0d55f5c93d8eeae505a2d8146b27811))
    - Ensure dkg pk is serialized to 48 bytes ([`5570c0d`](https://github.com/nucypher/ferveo/commit/5570c0d5bb2ee7a64eac78861c4999d9c98f455a))
    - Zeroize secret polynomial ([`eb033db`](https://github.com/nucypher/ferveo/commit/eb033db8e9a98f813f711a6001440e0ed0cd2dd5))
    - Merge remote-tracking branch 'upstream/main' into release-ferveo-py ([`b2cc5a8`](https://github.com/nucypher/ferveo/commit/b2cc5a81b443d9af182ca453ece8282e0c8341db))
    - Merge pull request #102 from piotr-roslaniec/local-verification-wasm ([`aacdf04`](https://github.com/nucypher/ferveo/commit/aacdf0462d73720e97c1d7924fc49e3d252a691a))
    - Fix pyo3 linking issues at test time ([`cf43433`](https://github.com/nucypher/ferveo/commit/cf43433893750acaf13f69e6f8426fba0c835f84))
    - Self review ([`51cd64f`](https://github.com/nucypher/ferveo/commit/51cd64f71459d56affe03eb7fa9327947e232611))
    - Fix failing test ([`c4912f5`](https://github.com/nucypher/ferveo/commit/c4912f5b11e87a96cb726e9122559ee042ffc15f))
    - Js bindings fail to correctly decrypt the ciphertext ([`ae79060`](https://github.com/nucypher/ferveo/commit/ae790601f691a7727489dbd8606dcd6ed0e4106d))
    - Update js examples ([`9463fb0`](https://github.com/nucypher/ferveo/commit/9463fb0ab7de13b44b2d132ca4005a18c0a76b2f))
    - Update wasm bindings ([`9215238`](https://github.com/nucypher/ferveo/commit/9215238e30987c13cbe66d4c05b118f9ff49d815))
    - Self review ([`c1beeba`](https://github.com/nucypher/ferveo/commit/c1beeba1d30716021400cfc2ec6c985744bca301))
    - Fix failing test ([`ffa71bc`](https://github.com/nucypher/ferveo/commit/ffa71bc19672ace4d6c298cad6d2e0ef58fff74c))
    - Js bindings fail to correctly decrypt the ciphertext ([`3e7db72`](https://github.com/nucypher/ferveo/commit/3e7db72e5878bfc54b0324c4c79a2a058fc9e0e9))
    - Update js examples ([`4a92ed6`](https://github.com/nucypher/ferveo/commit/4a92ed65aaabe055bac4f850f3877bbc3488b139))
    - Update wasm bindings ([`1cc7036`](https://github.com/nucypher/ferveo/commit/1cc7036007c05c231f241047ef01e394b8710205))
    - Merge pull request #93 from piotr-roslaniec/local-verification ([`a6ff917`](https://github.com/nucypher/ferveo/commit/a6ff91794d5a8ddd2b9ffcb7b398f58039017a96))
    - Self review ([`c919c5d`](https://github.com/nucypher/ferveo/commit/c919c5d565d4fb8aee217b2b9a793dd42f091a40))
    - Update python bindings ([`a77fc7a`](https://github.com/nucypher/ferveo/commit/a77fc7ac4aa4e2b5bd9a45faa44e40792fc8b65e))
    - Merge branch 'main' into local-verification ([`dd1eccf`](https://github.com/nucypher/ferveo/commit/dd1eccf1575d98d5bec2486452d3aa435faa02da))
    - Update ferveo api ([`212dcf3`](https://github.com/nucypher/ferveo/commit/212dcf3e37a741667c7c854595e26bd52d36614b))
    - Merge pull request #100 from piotr-roslaniec/expose-dkg-pk-size ([`bd72ef5`](https://github.com/nucypher/ferveo/commit/bd72ef560fc85defbce29e4de9a8d9bc676239f5))
    - Expose size of dkg public key in bindings ([`661780c`](https://github.com/nucypher/ferveo/commit/661780ce1292ed562828b2ad526de4f4b864e6ac))
    - Merge pull request #95 from piotr-roslaniec/implicit-ordering ([`9fded5b`](https://github.com/nucypher/ferveo/commit/9fded5bbd7b85985644844d31cf391dce52aea97))
    - Fix some error-related todos ([`b4117e4`](https://github.com/nucypher/ferveo/commit/b4117e46544eedc7838e278512238872c5426844))
    - Sort validator by their address ([`f6cf412`](https://github.com/nucypher/ferveo/commit/f6cf4125f3d2a767eeb98df1db8bd4b69ccdc222))
    - Refactor for 1.64.0 msrv ([`a23500c`](https://github.com/nucypher/ferveo/commit/a23500ca3918cf9456709340b00e1a54f651bb05))
    - Fix examples ([`2d96a30`](https://github.com/nucypher/ferveo/commit/2d96a30778b44335680c508538dc254114439451))
    - Merge branch 'main' into implicit-ordering ([`3f43524`](https://github.com/nucypher/ferveo/commit/3f43524e0ecdce0578d7b8b4ed7796708a153939))
    - Refactor internal ordering tracking ([`6bb4746`](https://github.com/nucypher/ferveo/commit/6bb4746ab1b2c7b0cd3ae7336fb5d8e5415b1abe))
    - Merge pull request #96 from piotr-roslaniec/bench-ark-sizes ([`1ea3abd`](https://github.com/nucypher/ferveo/commit/1ea3abd4239780e7e674df1af46cc9aa26f57336))
    - Bench arkworks primitives sizes ([`076fd5b`](https://github.com/nucypher/ferveo/commit/076fd5b1a8c9a7fa019e2afdcecc7ad4c676fe85))
    - Fix the ordering and refactor ([`5bb8888`](https://github.com/nucypher/ferveo/commit/5bb8888713d85de68eaffae2f512dfee5ddd2fb7))
    - Establish the correct ordering with sorting ([`0fd1859`](https://github.com/nucypher/ferveo/commit/0fd1859a2d8dc8ece2fdd576d5fa3e5845ffb53a))
    - Add a failing test to reproduce the ordering issue ([`fcb0420`](https://github.com/nucypher/ferveo/commit/fcb042059a976b11d630e2392a85d8c13697314e))
    - Fix after rebase ([`e074f0b`](https://github.com/nucypher/ferveo/commit/e074f0b5bfd3701af01ec04747fdfacad7d64f6d))
    - Expose methods for local verification on client side ([`08e965b`](https://github.com/nucypher/ferveo/commit/08e965bd1b15f35f8edc5d49e72044133b37d85b))
    - Merge pull request #92 from piotr-roslaniec/simple-tdec-py-bindings ([`4b9d8c4`](https://github.com/nucypher/ferveo/commit/4b9d8c4c50f64e5f84b35999557573fcd050f1c9))
    - Refactor bindings to support simple and precomputed tdec variants ([`edc2f26`](https://github.com/nucypher/ferveo/commit/edc2f26269d51d132066c3ff60c94466d4dbe5d8))
    - Merge pull request #75 from nucypher/release-ferveo-py ([`2529f74`](https://github.com/nucypher/ferveo/commit/2529f743fe6f07935938cbef81faa0230e478f87))
    - Fix python-test job on ci ([`9b91b9f`](https://github.com/nucypher/ferveo/commit/9b91b9f9865a2fd478abb4612fa70707e8de02a0))
    - Merge branch 'main' into release-ferveo-py ([`d503b8a`](https://github.com/nucypher/ferveo/commit/d503b8ab657cd6500dbc85cbf6c0d15804be57bc))
    - Replace g_inv with DkgPublicParameters ([`63e9a5f`](https://github.com/nucypher/ferveo/commit/63e9a5fe62ccc39c1f7f88683ce81d011c366342))
    - Merge pull request #91 from nucypher/typed-errors ([`b2eb9ef`](https://github.com/nucypher/ferveo/commit/b2eb9ef48cb977a2db724630ea8c0390d2976da6))
    - Add missing serializatin methods ([`9740da8`](https://github.com/nucypher/ferveo/commit/9740da827cb72145a5b3011f51dfcda5216b712b))
    - Add typed errors and expose them in Python bindings ([`200b4f5`](https://github.com/nucypher/ferveo/commit/200b4f5b4f00be9f939457b3f39a6ccf473d74d8))
    - Merge pull request #56 from nucypher/ferveo-light-tdec ([`8fa25b6`](https://github.com/nucypher/ferveo/commit/8fa25b66bf32585b2ef406bbec3999fd9ce75225))
    - Merge remote-tracking branch 'upstream/main' into ferveo-light-tdec ([`2c5d7c8`](https://github.com/nucypher/ferveo/commit/2c5d7c86af4a70f4694565093c399f5a9296873a))
    - Merge pull request #62 from nucypher/client-server-api ([`3a6e3c4`](https://github.com/nucypher/ferveo/commit/3a6e3c4b59c192289f86c0e37f119b29ccd3d620))
    - Merge pull request #67 from nucypher/arkworks-0.4 ([`bd78f97`](https://github.com/nucypher/ferveo/commit/bd78f9741246a2118bf6e3fdf48c72d6adf51b9e))
    - Merge pull request #72 from piotr-roslaniec/tpke-wasm-api-example ([`a6caaad`](https://github.com/nucypher/ferveo/commit/a6caaad16a10e6a77450f0196f63e5be4ba46f2e))
    - Merge pull request #68 from nucypher/error-handling ([`093f17e`](https://github.com/nucypher/ferveo/commit/093f17e22f606b33a468bd62ad37cf22f3dda265))
    - Merge branch 'error-handling' into tpke-wasm-api-example ([`707f460`](https://github.com/nucypher/ferveo/commit/707f460666acc2781d6dcfa49e0f75f1159f466f))
    - Replace cargo-udeps with cargo-machete ([`9d38a03`](https://github.com/nucypher/ferveo/commit/9d38a03f0f229ff91c5c9d21cc290b30e88ad993))
    - Merge branch 'error-handling' into release-ferveo-py ([`d2a0ca0`](https://github.com/nucypher/ferveo/commit/d2a0ca045beb4dd298f2c06b20b313456a1e81f9))
    - Sketch a pypi package release using maturin ([`3d7ecb4`](https://github.com/nucypher/ferveo/commit/3d7ecb44f9e16f0977c6d91f4264ae5ddef92528))
    - Fix cargo-udeps error ([`8e6f391`](https://github.com/nucypher/ferveo/commit/8e6f3912850ad57e89a21c2d6625e64fcd150fa2))
    - Fix broken build after merge ([`1e78512`](https://github.com/nucypher/ferveo/commit/1e785126d218bec875f5baca28d75233517d4b88))
    - Merge pull request #51 from nucypher/ferveo-pss ([`23955a9`](https://github.com/nucypher/ferveo/commit/23955a9a557b49e425b43e809d9c2555b85e66c5))
    - Sketch error handling in ferveo ([`a68d2d9`](https://github.com/nucypher/ferveo/commit/a68d2d9b62414fd06afa234f240508d1c41e68a8))
    - Fix benchmarks not running on ci ([`af9505d`](https://github.com/nucypher/ferveo/commit/af9505d277eb43760698c5677d2cc0583d6484f4))
    - Refactor serialization ([`b9535fe`](https://github.com/nucypher/ferveo/commit/b9535fefae0795f4b43f726378c5c65d0e776937))
    - Trim external apis ([`0b95048`](https://github.com/nucypher/ferveo/commit/0b9504833ff4025236d9821c5bdc40e66f6774d6))
    - Replace unwrap calls with result type ([`a9b4331`](https://github.com/nucypher/ferveo/commit/a9b4331c3755a0bb0dc0ca5cc355a892dc13d7d3))
    - Self review ([`2d926de`](https://github.com/nucypher/ferveo/commit/2d926de9a96a9492063fe4ad69a4dee51d5cae88))
    - Merge branch 'client-server-api' into arkworks-0.4 ([`ed88c8b`](https://github.com/nucypher/ferveo/commit/ed88c8b9f4bc11b5921ad82274776dc4603fc9c5))
    - Remove unused crate ([`eb9322b`](https://github.com/nucypher/ferveo/commit/eb9322bc3ff49e060b03abf8a915654f3a857f7b))
    - Merge branch 'ferveo-light-tdec' into client-server-api ([`8d5bef8`](https://github.com/nucypher/ferveo/commit/8d5bef892ee8d365e0a6fcc720ae4718a6475cd4))
    - Update arkworks to 0.4.0 - first pass ([`b1999b8`](https://github.com/nucypher/ferveo/commit/b1999b86a2b04c719ec29b1263612de88a0cfd49))
    - Update dev deps settings ([`d588cc8`](https://github.com/nucypher/ferveo/commit/d588cc8d339f8f4fb336fa447dbd914faee80604))
    - Update after rebase ([`aa39d7a`](https://github.com/nucypher/ferveo/commit/aa39d7a0f5e91d2945348cc49f0b5788bcf681af))
    - Merge pull request #54 from theref/TODO ([`6022f00`](https://github.com/nucypher/ferveo/commit/6022f00eaa0a495d0edf7dc92c703a5928824e18))
    - Add simple tdec to wasm bindings ([`1cc35b4`](https://github.com/nucypher/ferveo/commit/1cc35b480ebeb1f0ac6dcfd6c91e5ce627e9929c))
    - Fix import style ([`6d92b01`](https://github.com/nucypher/ferveo/commit/6d92b010139b915da1a89ffa686bf24871c7afd1))
    - Refactor module visibility ([`d287129`](https://github.com/nucypher/ferveo/commit/d287129e0a687edc7dc40ce196461be6617dcbba))
    - Simple tdec on client side fails ([`7257843`](https://github.com/nucypher/ferveo/commit/7257843a9722f4a63bfbe82fcfbaf2088711dfb6))
    - Support server-side persistance ([`81ea692`](https://github.com/nucypher/ferveo/commit/81ea692b10493f81720431750a99392eefba43f3))
    - Merge pull request #48 from nucypher/benchmark-primitives-size ([`58515cf`](https://github.com/nucypher/ferveo/commit/58515cf06c39c578eced7f276d0e7b1b98fd00e9))
    - Merge branch 'ferveo-pss' into ferveo-light-tdec ([`20f0eda`](https://github.com/nucypher/ferveo/commit/20f0edaa20865ef40ce34e99417c35b42b44e1f9))
    - Merge pull request #46 from nucypher/verify-simple-tdec-shares ([`530de97`](https://github.com/nucypher/ferveo/commit/530de97b5008b94b60420adc5735cf1b656b8218))
    - Merge branch 'main' into ferveo-pss ([`1857ef6`](https://github.com/nucypher/ferveo/commit/1857ef6d4249ea2a120ee4264dbfe1745fd25f15))
    - Merge pull request #63 from nucypher/remove-msg ([`9050db0`](https://github.com/nucypher/ferveo/commit/9050db0a2fae2ac9d7f1843813413db8aab0857d))
    - Merge branch 'main' into verify-simple-tdec-shares ([`48a2513`](https://github.com/nucypher/ferveo/commit/48a2513d0e479067fb8e0a5dee574ec3fefb9ce7))
    - Add ferveo-python example ([`fd47f97`](https://github.com/nucypher/ferveo/commit/fd47f97510fad4132712dc58714c19fc0fd0d7e4))
    - Simple tdec on server side ([`39f7f39`](https://github.com/nucypher/ferveo/commit/39f7f39cf618e6c46a809707cfc93bf1aae4e49e))
    - Sketch the server api ([`5ba7451`](https://github.com/nucypher/ferveo/commit/5ba7451f1ae54995e90570b2e970263124ffa803))
    - Remove dependency on block time ([`c85ea43`](https://github.com/nucypher/ferveo/commit/c85ea43d8e2b961aa3871c524c079df04224af4a))
    - Remove unused code ([`735b9c1`](https://github.com/nucypher/ferveo/commit/735b9c1b5244d515238eabbc798eed888267f244))
    - Merge pull request #38 from nucypher/validity-checks ([`168bde6`](https://github.com/nucypher/ferveo/commit/168bde69694089000d8363fba08dd86cc6e101ce))
    - Apply pr suggestions ([`1f76347`](https://github.com/nucypher/ferveo/commit/1f76347c0326424c5776c0e2a99c833d911c9b95))
    - Merge branch 'main' into use-sha256 ([`fa1c1a8`](https://github.com/nucypher/ferveo/commit/fa1c1a8bf2b338cb379a481d8b042c45af23c470))
    - Setup ferveo-python for server api ([`9b0a4c6`](https://github.com/nucypher/ferveo/commit/9b0a4c6a532f477c5e581ad65d9ebc747824fce3))
    - Refactor validator checksums into a struct ([`3366d80`](https://github.com/nucypher/ferveo/commit/3366d8011d960c4e493548011ba9610155d8360d))
    - Integrate light tdec into ferveo crate ([`5eb4fcf`](https://github.com/nucypher/ferveo/commit/5eb4fcfdf6ae19dda06871eb09155f067fb97645))
    - Refactor light tdec ([`20dbfec`](https://github.com/nucypher/ferveo/commit/20dbfec954af517bd9764e81b4bf97abe94ac10d))
    - Remove `window`, `my_partition` and `retry_after` from codebase ([`46d42ab`](https://github.com/nucypher/ferveo/commit/46d42ab0a45e8a0a62d27fd747c7381cf9c4c03a))
    - Merge branch 'verify-simple-tdec-shares' into ferveo-pss ([`3693ba8`](https://github.com/nucypher/ferveo/commit/3693ba85e11ce2dbfc0d6202cb5eef0505b8f753))
    - Merge branch 'validity-checks' into verify-simple-tdec-shares ([`a34b995`](https://github.com/nucypher/ferveo/commit/a34b995d68258b0c956cff87dafa2f968f7ab0ef))
    - Merge branch 'main' into validity-checks ([`dd9e458`](https://github.com/nucypher/ferveo/commit/dd9e4584f9b9715e5c63816234e1c0c0c63df5bc))
    - Size is expressed in bytes ([`6f1b7d4`](https://github.com/nucypher/ferveo/commit/6f1b7d4c7086517f7960a0388acd17baf78504b1))
    - Set polynomial degree to t-1 in pvss ([`6966b28`](https://github.com/nucypher/ferveo/commit/6966b28e3ee273f51c73402ac986a03e10743139))
    - Fix switched columns ([`076f261`](https://github.com/nucypher/ferveo/commit/076f2610c753bb02cd5fe5a2219679f63cdffdea))
    - Benchmark per ratio with no duplicates ([`feb8d80`](https://github.com/nucypher/ferveo/commit/feb8d8077564b43a5dae255b30e842ae75e2e85b))
    - Benchmark size of pvss transcripts ([`6c28d48`](https://github.com/nucypher/ferveo/commit/6c28d48ddc8aa0805b0fdb634564a627baf1f52f))
    - Self review ([`2c9bfec`](https://github.com/nucypher/ferveo/commit/2c9bfec29abf83f7e50fe37b5aceb4908bd40416))
    - Integrate key recovery into ferveo ([`7aa400f`](https://github.com/nucypher/ferveo/commit/7aa400f58a2ca766f36b50a248625aa2d3f2b7f1))
    - Refactor tdec recovery tests in tpke ([`a366089`](https://github.com/nucypher/ferveo/commit/a3660896800cfa35ddab2c07fc1d7dada8f39adb))
    - Integrate key refreshing into ferveo ([`0223a16`](https://github.com/nucypher/ferveo/commit/0223a1623d8f0d4aa0ade9ccf5f33a235cea57cb))
    - Merge pull request #32 from nucypher/simple-decryption-precomputed ([`cd50056`](https://github.com/nucypher/ferveo/commit/cd50056e1f36a7485b7f974e40e4c6584241d151))
    - Refactor key refreshing ([`864dbc2`](https://github.com/nucypher/ferveo/commit/864dbc26cbc6863b7eda7c03ed8e585d0a7159d8))
    - Add pvss verification benchmarks ([`886ca60`](https://github.com/nucypher/ferveo/commit/886ca60e7dbfe02e1af1526f3bccaf6af3e9228c))
    - Implement and benchmark subvariant of simple tdec ([`1bde49d`](https://github.com/nucypher/ferveo/commit/1bde49d8c1920f94cf3d33ca6bb705e667eda22c))
    - Merge branch 'main' into validity-checks ([`208d95c`](https://github.com/nucypher/ferveo/commit/208d95c990084f81eb2e82339e772b0baa8c7748))
    - Merge pull request #27 from nucypher/dkg-pvss-flow ([`e842b8a`](https://github.com/nucypher/ferveo/commit/e842b8a5bb2cafe2e768ca29e5f0210f969ea748))
    - Replace redundant variable ([`6181179`](https://github.com/nucypher/ferveo/commit/618117998ece797319bd5aba765ad51120872d83))
    - Benchmark share verification ([`d499c28`](https://github.com/nucypher/ferveo/commit/d499c2820d8c0cbe959c8092fdefd632da2357af))
    - Refactor decryption share creation ([`64f5023`](https://github.com/nucypher/ferveo/commit/64f5023663ccf6f33b82e87a21b9c89eb7b135ac))
    - Implement simple tdec decryption share verification ([`655e5e3`](https://github.com/nucypher/ferveo/commit/655e5e3a9173d6e38ad176efecd0d380f19578f1))
    - Remove unused variable ([`bacea0a`](https://github.com/nucypher/ferveo/commit/bacea0a2b2e31adcfcdb78bff45b4b69f82c54de))
    - Documents and refactor code ([`6fb4c89`](https://github.com/nucypher/ferveo/commit/6fb4c890cef5c1ca077d301bf4e3e12c78584d39))
    - Fix after rebase ([`dc53f7b`](https://github.com/nucypher/ferveo/commit/dc53f7b568abe296f2f0812b8233e5e388965277))
    - Fix rustfmt ([`0125381`](https://github.com/nucypher/ferveo/commit/0125381809b9ae50e1a40cc167bfe7d2fa710e69))
    - Remove unused code ([`002d407`](https://github.com/nucypher/ferveo/commit/002d407d1f592af1de836af1f5030b9baa423b90))
    - Rename TendermintValidator to ExternalValidator ([`8bd2888`](https://github.com/nucypher/ferveo/commit/8bd2888a95ec91686ce8e62da1533459dc159469))
    - Remove ValidatorSet ([`60e4c6f`](https://github.com/nucypher/ferveo/commit/60e4c6f26c6cc2041ba66cd6697db3bae66ff04e))
    - Cargo fmt ([`6621541`](https://github.com/nucypher/ferveo/commit/66215410afa829639db6417772f7bf443da36d6c))
    - Fix clippy after 1.66 update ([`cafca08`](https://github.com/nucypher/ferveo/commit/cafca08919841dcef7019c6e98e636450d522fa8))
    - Self code review ([`b560ad6`](https://github.com/nucypher/ferveo/commit/b560ad6e5e72a4b1521486cbc90e84fcbff2ed6f))
    - Simple threshold decryption works ([`d3c76cd`](https://github.com/nucypher/ferveo/commit/d3c76cde43f13a9a7c24d24511acbd980b5b6e44))
    - Fix clippy ([`cca3270`](https://github.com/nucypher/ferveo/commit/cca32700b3b13aafab6fcb899f852d3643dddcfd))
    - Simple decryption with one validator works with ferveo dkg ([`4fbaab3`](https://github.com/nucypher/ferveo/commit/4fbaab341e8481d7fbcf103e8b9c29b0a7ea348a))
    - Update aggregation ([`0474b48`](https://github.com/nucypher/ferveo/commit/0474b484a6eb8b9d91eb4b3cb7d56db207eda12c))
    - Updating scheme ([`e2b55b4`](https://github.com/nucypher/ferveo/commit/e2b55b4cd8583d64e02c6b63a936bd6c670dd046))
    - Initial removal of share partitioning ([`ab2857d`](https://github.com/nucypher/ferveo/commit/ab2857d7d30627753ca2ae2a3550284d73d56fec))
    - Incorrect length of decrypted shares after pvss combination ([`efa6150`](https://github.com/nucypher/ferveo/commit/efa6150f3aa07e262290392f41dfa37c83a7a4a4))
    - Wip ([`1b260cc`](https://github.com/nucypher/ferveo/commit/1b260cc97fabf263f88b2f0db1e0ff8cded3928d))
    - Update function docstring ([`da92818`](https://github.com/nucypher/ferveo/commit/da92818fbb7ce06a0b06a3324e975b7f3966f544))
    - Add negative test case for verify_full ([`8e43ae4`](https://github.com/nucypher/ferveo/commit/8e43ae4d39afdab8e9e00d65b3d337bef71b85e6))
    - Documents and refactor code ([`8f7308b`](https://github.com/nucypher/ferveo/commit/8f7308b380483349dc744cc6665b7f7bc9412ded))
    - Fix after rebase ([`26fe690`](https://github.com/nucypher/ferveo/commit/26fe690d14dc29231886f593065d94193a3f913e))
    - Fix rustfmt ([`99d2b9c`](https://github.com/nucypher/ferveo/commit/99d2b9c49b953339ae20a33e5cb9f0e87115b7f3))
    - Remove unused code ([`fb05e62`](https://github.com/nucypher/ferveo/commit/fb05e62fdb784b5b68b80040677a01386eb61141))
    - Rename TendermintValidator to ExternalValidator ([`995fdce`](https://github.com/nucypher/ferveo/commit/995fdcedf42ee3bacdd66689852fcc2f3d5f9794))
    - Remove ValidatorSet ([`4f62c70`](https://github.com/nucypher/ferveo/commit/4f62c704156c9929754bf16a5fd801bf9908ba3f))
    - Cargo fmt ([`1d9f623`](https://github.com/nucypher/ferveo/commit/1d9f623b8bd566871c7888d662264f2b893cdb9f))
    - Fix clippy after 1.66 update ([`44bd186`](https://github.com/nucypher/ferveo/commit/44bd186c365ad62eb47299739928e2490dbe4bee))
    - Self code review ([`89ebffc`](https://github.com/nucypher/ferveo/commit/89ebffc583ee13bc5b19a846fef168663e106bcb))
    - Simple threshold decryption works ([`856790c`](https://github.com/nucypher/ferveo/commit/856790c48d882c87275ddf6d87bbeb1a31ad559b))
    - Fix clippy ([`7cad9ae`](https://github.com/nucypher/ferveo/commit/7cad9aea331ed8e510bca6afd043fe61a466ef08))
    - Simple decryption with one validator works with ferveo dkg ([`57255f5`](https://github.com/nucypher/ferveo/commit/57255f5befb64f3c4cce8d97b2d28db0f0c4f0eb))
    - Update aggregation ([`32f9c49`](https://github.com/nucypher/ferveo/commit/32f9c49e7267a4a1d982dccb023e4f683effeb5a))
    - Updating scheme ([`9759860`](https://github.com/nucypher/ferveo/commit/9759860de694bc35cfb878f5908886283ed83ac7))
    - Initial removal of share partitioning ([`9d38f62`](https://github.com/nucypher/ferveo/commit/9d38f62f5ae7f4a4b25e149e84aad77a02bc4a03))
    - Incorrect length of decrypted shares after pvss combination ([`81d4dd2`](https://github.com/nucypher/ferveo/commit/81d4dd2c67026f2a672c2c421efa38bdfc5f226b))
    - Wip ([`8cb52d8`](https://github.com/nucypher/ferveo/commit/8cb52d8577027414bd1300d40ed9c96669e85f00))
    - Merge pull request #34 from nucypher/benchmarks-pr-compare ([`185822b`](https://github.com/nucypher/ferveo/commit/185822b781ec6febfef28660acbe6fa39dd893a4))
    - Fix benchmarks on ci ([`33cf5c2`](https://github.com/nucypher/ferveo/commit/33cf5c2f7ed7c0971c2f349e38df24047b1ea4f6))
    - Merge pull request #25 from piotr-roslaniec/sd-benchmarks ([`25c745e`](https://github.com/nucypher/ferveo/commit/25c745e3e830fab8161612af6963bc673ce00bb2))
    - Run benchmarks on gh actions ([`ffd67c4`](https://github.com/nucypher/ferveo/commit/ffd67c47238b3dd5d9273ff8e0ba1979d10d4732))
    - Merge pull request #20 from piotr-roslaniec/simple-decryption ([`b2b4809`](https://github.com/nucypher/ferveo/commit/b2b48091092c861ca7a39fcc54573dcd8117db2e))
    - Silence clippy warnings ([`1160971`](https://github.com/nucypher/ferveo/commit/116097195929ffd85e1a979b47d8783cd02285d6))
    - Implement simple threshold decryption variant ([`e7ecab0`](https://github.com/nucypher/ferveo/commit/e7ecab0e1b9b310490e7f7ccf6deb73d08c866b4))
    - Merge pull request #10 from piotr-roslaniec/wasm-bindings ([`f26552d`](https://github.com/nucypher/ferveo/commit/f26552db645e095fb4df6732aa38e1fff1401d72))
    - Merge pull request #17 from nucypher/benchmark-wasm ([`85fba9e`](https://github.com/nucypher/ferveo/commit/85fba9e27de154b8b9701873ab1d370a07283fe3))
    - Panicks at 'capacity overflow' during js-benches ([`9d358e1`](https://github.com/nucypher/ferveo/commit/9d358e16acf3e033e5e5f8bef15a3b05d00d15c6))
    - Fix clippy ([`d80d112`](https://github.com/nucypher/ferveo/commit/d80d11292c35fc2f464c465aecc8803a55f5812b))
    - Expose randomness in dkg setup ([`d8b51ce`](https://github.com/nucypher/ferveo/commit/d8b51cea0b614efb89e2b17c8c23730268a0f65e))
    - Update after rebase ([`b8b2392`](https://github.com/nucypher/ferveo/commit/b8b2392de11068acde07895dc9b6897a742b9b2d))
    - Fix clippy ([`2462c8a`](https://github.com/nucypher/ferveo/commit/2462c8ad5398927047aa35f0b245e1aa29851391))
    - Setup benchmarks ([`1b96071`](https://github.com/nucypher/ferveo/commit/1b960712911e2e02ae2f41e9e773134d8ccdbd96))
    - Add wasm setup ([`ca2e46e`](https://github.com/nucypher/ferveo/commit/ca2e46e67637ce34d531da03124523fb567b7002))
    - Merge pull request #8 from piotr-roslaniec/aad#1 ([`41b5408`](https://github.com/nucypher/ferveo/commit/41b54081c2061126fa8d661207e13aa74406733f))
    - Address pr comments ([`3786af1`](https://github.com/nucypher/ferveo/commit/3786af1e6a8c8ec26c82435f125f6d67c05884cd))
    - Address some clippy warnings ([`e8087d2`](https://github.com/nucypher/ferveo/commit/e8087d23ec6d1845585016259e51cc173160bb92))
    - Replace chacha20 with chacha20poly1305 ([`ce89ead`](https://github.com/nucypher/ferveo/commit/ce89eadb7737e511c743ec01a2fe3bfc9826b32c))
    - Merge pull request #75 from anoma/bat/state-guard-refactor ([`2a35d56`](https://github.com/nucypher/ferveo/commit/2a35d56cacf740bc92478b6be2ebee83a54f4dcc))
    - When announcing an aggregation, the resulting key should also be announced and checked so that it can be included on chain ([`caef6ef`](https://github.com/nucypher/ferveo/commit/caef6ef73dd43a9952d783fcf18abb893b36635f))
    - Strengthened state guards against aggregation. Necessary for preparing blocks easily ([`1594750`](https://github.com/nucypher/ferveo/commit/159475028209948eb40388458a24b0a086afc311))
    - Merge pull request #73 from anoma/bat/announcement-refactor ([`9786ac0`](https://github.com/nucypher/ferveo/commit/9786ac0c9d70f0b73fb2303405db730c98e06440))
    - Fixing up the benchmarks to reflect the refactor in dkg ([`d3fb002`](https://github.com/nucypher/ferveo/commit/d3fb002e52774cd14bff0d1187a2634fad6eea51))
    - Formatting ([`d786fae`](https://github.com/nucypher/ferveo/commit/d786fae33b01cd0863f29b70810dfcc847f2542b))
    - Added retry logic to the dkg ([`09f26b3`](https://github.com/nucypher/ferveo/commit/09f26b39ddc71d9a4b1f226e2dafbdb4c51a7caa))
    - Removed the announce phase from the dkg ([`ec58fe1`](https://github.com/nucypher/ferveo/commit/ec58fe1828d0560525c80cd1dc4013915b0ac54e))
    - Merge pull request #65 from anoma/joe/20210922 ([`d6d603f`](https://github.com/nucypher/ferveo/commit/d6d603fbe82706525a194f42cbab9c3431dd7cc4))
    - Latest ferveo ([`714d8b9`](https://github.com/nucypher/ferveo/commit/714d8b9ea0aaf4ddf1fa910d5c474d80a2985f00))
    - Latest ferveo ([`6c6033c`](https://github.com/nucypher/ferveo/commit/6c6033cdf797c2642462451dd63f2180cc3a2cce))
    - Latest ferveo ([`0f17c3b`](https://github.com/nucypher/ferveo/commit/0f17c3be5cfa55b5f878defcb74ab2b4e13c3190))
</details>

## 0.3.0 (2023-08-28)

### New Features (BREAKING)

 - <csr-id-1800d3c5db164947c7cae35433fb8e3ad2650b66/> add ciphertext header to ciphertext api

## v0.2.1 (2023-08-01)

### New Features

 - <csr-id-50511fff3c9829d6f2004360be93b67730f66f1f/> replace FerveoVariant static methods with class atributed

### Bug Fixes

 - <csr-id-be900653a80e3570300f5a126af98660ab59a7d2/> python typings don't match runtime

## v0.2.0 (2023-07-07)

<csr-id-caef6ef73dd43a9952d783fcf18abb893b36635f/>
<csr-id-159475028209948eb40388458a24b0a086afc311/>
<csr-id-d3fb002e52774cd14bff0d1187a2634fad6eea51/>
<csr-id-d786fae33b01cd0863f29b70810dfcc847f2542b/>
<csr-id-09f26b39ddc71d9a4b1f226e2dafbdb4c51a7caa/>
<csr-id-ec58fe1828d0560525c80cd1dc4013915b0ac54e/>
<csr-id-0eb5bd48b598709dd0fc54adb424f5f41ce52e92/>

### New Features

 - <csr-id-e8d05981ee2cc983966c037babeebe5ba0134ffc/> expose ferveo variant in bindings
 - <csr-id-e51656260f2ec8c607add8a63e6832786915b201/> expose missing method

### Bug Fixes

 - <csr-id-99ebfecdb7967c4858f918d27ce13cc635c329ac/> dkg serialization in wasm bindings

### Other

 - <csr-id-caef6ef73dd43a9952d783fcf18abb893b36635f/> When announcing an aggregation, the resulting key should also be announced and checked so that it can be included on chain
 - <csr-id-159475028209948eb40388458a24b0a086afc311/> Strengthened state guards against aggregation. Necessary for preparing blocks easily
 - <csr-id-d3fb002e52774cd14bff0d1187a2634fad6eea51/> Fixing up the benchmarks to reflect the refactor in dkg
 - <csr-id-d786fae33b01cd0863f29b70810dfcc847f2542b/> Formatting
 - <csr-id-09f26b39ddc71d9a4b1f226e2dafbdb4c51a7caa/> Added retry logic to the dkg
 - <csr-id-ec58fe1828d0560525c80cd1dc4013915b0ac54e/> Removed the announce phase from the dkg

### Chore

 - <csr-id-0eb5bd48b598709dd0fc54adb424f5f41ce52e92/> adjust changelogs for cargo-smart-release

### New Features (BREAKING)

 - <csr-id-8b6e6f5834d7b736a1d7baf3ddbfa7c60837b9bb/> hide dkg public params from bindings

### Bug Fixes (BREAKING)

 - <csr-id-7388027cb6c77357e8b4d24a891e24a9b4ea2031/> rename wasm method

