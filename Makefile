.PHONY: build test test-unit test-db lint validate clean run-api run-portal compose-up compose-down docker-build release-check

build:
	cargo build --workspace

# Run in-memory unit tests only (no database).
# RYUKI_DATABASE_URL is explicitly unset so every DB test in ryuki-api skips
# (they guard on the env var).  This prevents contamination: ryuki-api uses a
# process-global `database::POOL` OnceLock — if ANY test in the same process
# calls try_connect_with_url(), the pool is set for the entire process and the
# in-memory request unit_tests (which expect no-DB mode) enter the DB code path
# and fail.  Running unit tests without the URL keeps the pool unset and the
# two test categories fully isolated.
test-unit:
	RYUKI_DATABASE_URL= cargo test -p ryuki-api
	cargo test -p ryuki-engine

# Run DB integration tests only (requires a live Postgres instance).
# Filtered by name so only DB tests run in this process — no in-memory
# unit_tests are executed, and the global pool contamination cannot occur.
#
# Convention (DO NOT hand-maintain a per-module allowlist — it silently drifts
# and hid real bugs in untested modules): every DB-backed test module is named
# `*_db_tests` (or the foundational `db_tests` migration suite), so the
# `db_tests` substring filter auto-includes new modules.  `db_lifecycle_tests`
# and `agents::tests::db_` are the DB suites whose names lack the `db_tests`
# substring (agents uses `mod tests` with `db_*`-prefixed fns), so they are
# listed explicitly.  Run single-threaded: these tests share one physical
# database, so parallel execution causes cross-test contention/flakes.
#
# `test_migrations_run_against_pg18` is skipped here: it is a CLEAN-database
# migration smoke test (asserts the fresh-seed row counts) and so cannot pass
# against the shared, already-seeded dev database — it belongs to `make test`
# run against a throwaway Postgres.
test-db:
	RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
	  cargo test -p ryuki-api -- --test-threads=1 \
	    --skip test_migrations_run_against_pg18 \
	    db_tests db_lifecycle_tests agents::tests::db_

test:
	cargo test --workspace

lint:
	cargo fmt --check --all
	cargo clippy --workspace --all-targets -- -D warnings

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
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	$(MAKE) validate
	$(MAKE) docker-build
