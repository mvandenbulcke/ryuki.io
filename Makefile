.PHONY: build test test-unit test-db lint validate verify-clean cache-status clean run-api run-portal compose-up compose-down docker-build release-check db-backup db-restore

# The ordinary Cargo targets below intentionally keep ./target for iterative
# human development. Use `make verify-clean` for every complete verification
# wave; it caps and removes a disposable target. Run `make clean` after any
# deliberate debugging session that opts back into full debug information.

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

# Full one-shot verification for CI and coding agents. Uses one temporary,
# non-incremental target and deletes it on success, failure, or interruption.
verify-clean:
	./scripts/verify-workspace-clean.sh

cache-status:
	@du -sh target 2>/dev/null || echo "target: absent"
	@df -h . | tail -1

clean:
	cargo clean
	rm -rf output/

run-api:
	RYUKI_MIGRATION_MODE=local-auto cargo run --manifest-path sources/ryuki-api/Cargo.toml

run-portal:
	cargo leptos serve --manifest-path portal/portal-ui/Cargo.toml

# Local-dev logical backup of the compose database. Writes a timestamped,
# custom-format (-Fc) dump under ./backups/ that `db-restore` can replay. This
# is the local developer / drill path only — production recovery is the CNPG
# Barman object store (see docs/runbooks/db-restore-runbook.md).
DB_URL ?= postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform
db-backup:
	mkdir -p backups
	pg_dump --format=custom --no-owner --no-privileges \
	  --dbname=$(DB_URL) \
	  --file=backups/ryuki_platform-$$(date -u +%Y%m%dT%H%M%SZ).dump
	@echo "Wrote backup to backups/ (newest):"
	@ls -1t backups/*.dump | head -1

# Restore a dump produced by `db-backup` into the LOCAL compose database.
# Usage: make db-restore FILE=backups/<dump-file> CONFIRM_RESTORE=local-ryuki
# --clean --if-exists DROPS existing objects first, so this is destructive and
# guarded: it refuses any non-localhost DB_URL and requires an explicit
# CONFIRM_RESTORE token; --single-transaction makes it all-or-nothing. Production
# recovery is the CNPG path (docs/runbooks/db-restore-runbook.md), never this.
db-restore:
	@test -n "$(FILE)" || { echo "error: set FILE=backups/<dump-file>"; exit 2; }
	@case "$(DB_URL)" in \
	  *@localhost:*|*@127.0.0.1:*) ;; \
	  *) echo "refusing: db-restore is a LOCAL-DEV drill only; DB_URL must target localhost (got: $(DB_URL))"; exit 2;; \
	esac
	@test "$(CONFIRM_RESTORE)" = "local-ryuki" || { echo "refusing: db-restore DROPS and replaces objects in $(DB_URL). Re-run with CONFIRM_RESTORE=local-ryuki to proceed."; exit 2; }
	pg_restore --clean --if-exists --no-owner --no-privileges --single-transaction \
	  --dbname=$(DB_URL) \
	  $(FILE)

compose-up:
	docker compose -f deploy/compose/compose.yaml up --build

compose-down:
	docker compose -f deploy/compose/compose.yaml down

docker-build:
	docker build -f sources/ryuki-api/Dockerfile -t ryuki/platform-api:rust-dev .
	docker build -f portal/portal-ui/Dockerfile -t ryuki/portal-ui:rust-dev .

release-check:
	$(MAKE) verify-clean
	$(MAKE) docker-build
