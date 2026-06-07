# svault — local QA runner.
# `make qa` is the SAME gate CI enforces: format, lint, test, build.
# Run it before every push. If `make qa` is green, CI will be green.
#
# Note: cargo must be on PATH. If you see "command not found: cargo",
# run `source ~/.cargo/env` first (or add it to your shell profile).

CARGO ?= cargo

.PHONY: qa fmt fmt-check lint test build release clean run

## qa: the full gate — what CI runs. Fails on any warning.
qa: fmt-check lint test build
	@echo "✅ QA gate passed."

## fmt: auto-format the code in place.
fmt:
	$(CARGO) fmt

## fmt-check: verify formatting without changing files (CI mode).
fmt-check:
	$(CARGO) fmt --check

## lint: clippy with warnings treated as errors, across all targets.
lint:
	$(CARGO) clippy --all-targets -- -D warnings

## test: run the unit + integration test suite.
test:
	$(CARGO) test

## build: debug build.
build:
	$(CARGO) build

## release: optimized build.
release:
	$(CARGO) build --release

## clean: remove build artifacts.
clean:
	$(CARGO) clean

## run: run the debug binary (pass args via ARGS, e.g. `make run ARGS=list`).
run:
	$(CARGO) run -- $(ARGS)
