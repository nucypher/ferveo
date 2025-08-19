# New version publishing instructions

We're [cargo-smart-release](https://lib.rs/crates/cargo-smart-release) to automate the release process.

## Writing commit messages

As long as you adhere to the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format, you can
write your commit messages however you want.

## Releasing workflow

### Update Version

Update the version in the `Cargo.toml` for the relevant package(s) you want to release.

### Publish Package

We're currently not releasing Python and WASM bindings, we're only releasing the Rust crate.

You can either specify all of the packages in the workspace, or just the ones you want to release. The full list is:
- `ferveo-nucypher-common`
- `subproductdomain-nucypher`
- `ferveo-nucypher-tdec`
- `ferveo-nucypher`


In order to release all of the packages, run the following from the `main` branch:

```bash
cargo smart-release \
  ferveo-nucypher-common \
  subproductdomain-nucypher \
  ferveo-nucypher-tdec \
  ferveo-nucypher \
  --update-crates-index
```

_Typically, `smart-release` handles the package ordering for you, but since the naming of packages don't match their directory names, you
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

- You can modify the command to only publish specific packages if needed.
- This will update the respective package `CHANGELOG.md` files in one commit, and produce tags for each of the packages. Be
sure to push up that additional commit and relevant tags to the `main` branch. Using the tags you can create a corresponding GitHub release.
