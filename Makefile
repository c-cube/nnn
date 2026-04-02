.PHONY: build sync-profiles test clean

build:
	cargo build

release:
	cargo build --release

sync-profiles:
	python3 scripts/sync-profiles.py

test:
	cargo test

clean:
	cargo clean
