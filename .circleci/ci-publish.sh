#!/usr/bin/env bash
cargo install cargo-bump --force

git config user.name "$GITHUB_USERNAME"

git config user.email "$GITHUB_EMAIL"

cargo bump $CIRCLE_TAG

cargo publish --dry-run --allow-dirty
