#!/usr/bin/env bash
cargo install cargo-release --force

git config user.name "$GITHUB_USERNAME"

git config user.email "$GITHUB_EMAIL"

cargo release --no-confirm
