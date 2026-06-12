.PHONY: build test lint validate clean run-api run-portal compose-up compose-down docker-build release-check

build:
	cargo build --workspace

test:
	cargo test --workspace

lint:
	cargo fmt --check --all
	cargo clippy --workspace -- -D warnings

validate:
	cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all --root .
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

docker-build:
	docker build -f sources/ryuki-api/Dockerfile -t ryuki/platform-api:rust-dev .
	docker build -f portal/portal-ui/Dockerfile -t ryuki/portal-ui:rust-dev .

release-check:
	cargo fmt --check --all
	cargo clippy --workspace -- -D warnings
	cargo test --workspace
	$(MAKE) validate
	$(MAKE) docker-build
