# New version publishing instructions

We're [cargo-smart-release](https://lib.rs/crates/cargo-smart-release) to automate the release process.

## Writing commit messages

As long as you adhere to the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format, you can
write your commit messages however you want.

## Releasing workflow

We're currently not releasing Python and WASM bindings, we're only releasing the Rust crate.

In order to release a new version, run:

```bash
cargo smart-release \
  ferveo-nucypher-common \
  subproductdomain-nucypher \
  ferveo-nucypher-tdec \
  ferveo-nucypher \
  --update-crates-index
```

_Typically `smart-release` handles the package ordering for you, but since the naming of packages don't match their directory names, you
need to specify the package names explicitly._

Inspect the changes and confirm the release:

```bash
cargo smart-release \
  ferveo-nucypher-common \
  subproductdomain-nucypher \
  ferveo-nucypher-tdec \
  ferveo-nucypher \
  --update-crates-index --execute
```

