#!/usr/bin/env bash
set -e

git config user.name "$GITHUB_USERNAME" && git config user.email "$GITHUB_EMAIL"

cargo install cargo-bump --force

cargo bump patch

VERSION=$(grep -e '^version' Cargo.toml | cut -d "\"" -f2)

cargo uninstall cargo-bump

cargo publish --token $CARGO_REGISTRY_TOKEN --verbose --allow-dirty

git commit -am "[skip ci] new development bump to $VERSION"

git tag -a "$VERSION" -m "$VERSION release"

git push origin --follow-tags
