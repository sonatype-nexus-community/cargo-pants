.PHONY: all lint build lint-ci build-cargo

build: lint build-cargo

build-clean: clean build

lint:
	cargo fmt

lint-ci:
	cargo fmt -- --check

clean:
	cargo clean

build-cargo:
	cargo build
