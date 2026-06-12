.PHONY: build test clean

build:
	cargo build

release:
	cargo build --release

install:
	cargo install --path=.

format:
	cargo fmt

test:
	cargo test

clean:
	cargo clean
