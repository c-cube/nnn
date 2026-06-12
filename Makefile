.PHONY: build test clean

build:
	cargo build

release:
	cargo build --release

install:
	cargo install --path=.

test:
	cargo test

clean:
	cargo clean
