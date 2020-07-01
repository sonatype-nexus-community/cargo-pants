#!/usr/bin/env bash
cargo install cargo-bump --force

git config user.name "$GITHUB_USERNAME"

git config user.email "$GITHUB_EMAIL"

cargo bump $CIRCLE_TAG

git add .

git commit -m "[skip ci] release of $CIRCLE_TAG"

git push origin master

cargo publish
