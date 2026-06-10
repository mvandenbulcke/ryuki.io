.PHONY: build test lint clean run validate

build:
	cargo build --workspace

test:
	cargo test --workspace

lint:
	cargo fmt --check --all
	cargo clippy --workspace -- -D warnings

validate:
	cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
	./scripts/no-secret-scan.sh

clean:
	cargo clean
	rm -rf output/

run-api:
	cargo run --manifest-path sources/ryuki-api/Cargo.toml

run-portal:
	cargo leptos serve --manifest-path portal/portal-ui/Cargo.toml

compose-up:
	docker compose -f deploy/compose/compose.yaml up --build

compose-down:
	docker compose -f deploy/compose/compose.yaml down
