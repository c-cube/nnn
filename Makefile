.PHONY: build test clean

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

clean:
	cargo clean
