.PHONY: gateway simulator agents dashboard casper-contract casper-preflight casper-shared-host-setup smoke test package clean

PYTHON ?= python3
UV ?= uv
PACKAGE_NAME ?= concordia-dao-council.zip
CASPER_CONTRACT_TOOLCHAIN ?= nightly-2025-02-01

# Run the FastAPI gateway only.
gateway:
	$(UV) run uvicorn gateway.app:app --reload --host 0.0.0.0 --port 8000

# Run the local DAO proposal simulator used for offline rehearsals.
simulator:
	$(UV) run uvicorn app:app --app-dir proposal-simulator --reload --host 0.0.0.0 --port 9000

# Start these in separate terminals for the full council workflow.
agents:
	@echo "uv run python -m agents.rowan             # Rowan"
	@echo "uv run python -m agents.mercer            # Mercer"
	@echo "uv run python -m agents.verity            # Verity"
	@echo "uv run python -m agents.alden             # Alden"
	@echo "uv run python -m agents.locke             # Locke"
	@echo "uv run python -m agents.recorder.heartbeat # Concordia Core"
	@echo "uv run python -m agents.wells              # Wells (optional summary)"

# Run the dashboard from dashboard/.
dashboard:
	cd dashboard && npm install && npm run dev

casper-contract:
	rustup toolchain install $(CASPER_CONTRACT_TOOLCHAIN) --profile minimal
	rustup +$(CASPER_CONTRACT_TOOLCHAIN) target add wasm32-unknown-unknown
	cd contracts/governance-receipt && cargo +$(CASPER_CONTRACT_TOOLCHAIN) build --release --target wasm32-unknown-unknown

casper-preflight:
	$(PYTHON) scripts/casper_preflight.py

casper-shared-host-setup:
	$(PYTHON) scripts/finalize_casper_shared_host.py

smoke:
	$(PYTHON) -m compileall -q shared gateway agents proposal-simulator scripts
	$(PYTHON) scripts/check_repo_hygiene.py

test: smoke
	$(PYTHON) -m pytest -q

package: smoke
	$(PYTHON) scripts/package_repo.py --output /mnt/data/$(PACKAGE_NAME)

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ concordia.db dashboard/.next node_modules dashboard/node_modules
