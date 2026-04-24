# AGENTS.md

## Repo Shape
- The root service is a Julia app (`Project.toml`, `src/`, `load_common.jl`, `start.jl`); Rust code is split into independent crates, not a Cargo workspace.
- Run Cargo commands from the crate directory: `primal-cache/`, `primal-media/`, `ws-connector/`, or `pg_primal/`.
- `src/PrimalServer.jl` only includes `load_common.jl`; startup wiring and local defaults live in `start.jl` and `env-vars.jl`.
- API handler discovery is mostly in Julia `src/app*.jl` and `src/cache_server_handlers*.jl`; README request examples are not exhaustive.

## Local Environment
- Use `nix develop` at the repo root for the Julia/Postgres/pgrx toolchain; the shell hook sets `LD_LIBRARY_PATH`, `NIX_LD`, clang bindgen vars, and runs `make` to build `libbech32.so`.
- Root README setup commands are the intended local DB path: `$setup_postgres`, `$setup_pg_primal`, `$start_postgres`, then schema init/server start. Verify helper names in `shell.nix` before relying on README prose; `setup_pg_extensions`, `init_postgres_schema`, and `start_primal_server` are referenced there but are not active root shell scripts in the current `shell.nix`.
- Default local Postgres assumptions recur across code: host `127.0.0.1`, port `54017`, DB `primal1`; Rust services generally use user `pr`, while `start.jl` uses `ENV["USER"]`.
- `env-vars.jl` defaults `PRIMALSERVER_RELAYS` to `relays-minimal.txt`, `PRIMALSERVER_STORAGE_PATH` to `./var`, and the cache websocket port to `8800 + PRIMALSERVER_NODE_IDX`.

## Commands
- Julia package load check: `nix develop -c julia --project -e 'import PrimalServer'`.
- Start the Julia server manually when needed: `nix develop -c julia --project -t8 -L pkg.jl -L load_common.jl -L start.jl`.
- Rust formatting per crate: `cargo fmt` from that crate directory.
- Rust unit/focused tests per crate: `cargo test <test_name>` from that crate directory; do not run `cargo test` at repo root.
- `pg_primal` is a pgrx extension; install with the root helper `$setup_pg_primal` or run pgrx commands from `pg_primal/` against the matching `pg_config`.

## Rust Build/Test Gotchas
- There is no checked-in `.sqlx/` metadata. Crates using `sqlx::query!` (`primal-cache`, `primal-media`, `ws-connector`) need a reachable database/schema at compile time unless you deliberately change SQLx setup.
- `ws-connector/.cargo/config.toml` sets `tokio_unstable`/`tokio_taskdump`; keep Cargo invocations inside `ws-connector/` so those rustflags apply.
- `ws-connector` integration tests build `--release --all-targets`, spawn `target/release/ws-connector`, connect to backend `ws://127.0.0.1:8817`, compare with `ws://127.0.0.1:9001`, and query Postgres at `postgresql://pr@127.0.0.1:54017/primal1`; they are not hermetic unit tests.
- `primal-media` reads `./primal-media.config.json` by default or `PRIMAL_MEDIA_CONFIG_FILE`/`--config`; defaults include production-looking media paths and external hosts, so provide a local config before running real media commands.
- Media processing shells out to tools such as `ffmpeg`, `magick`, and sometimes `exiftool`/SSH; Cargo tests or manual runs may fail for missing executables even when Rust compiles.
- `primal-cache` binaries require `--config-file` or `CONFIG_FILE`; the JSON must include `cache_database_url`, `membership_database_url`, and `import_latest_t_key`.

## Julia Gotchas
- Load order matters: `load_common.jl` includes many `src/*.jl` files in a fixed sequence and prints each include; avoid reordering unless you validate startup.
- `start.jl` wires Postgres pools, DAG runner, firehose, fetching, cache server, blossom, spam detection, and internal services; many changes need startup verification, not just `import PrimalServer`.
- Some Julia tests are embedded in source files (`src/dag.jl`, `pgext/pg_ext_init.jl`) rather than under a standard `test/` directory.
