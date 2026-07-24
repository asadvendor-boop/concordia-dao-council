.PHONY: gateway simulator agents dashboard casper-contract casper-preflight casper-shared-host-setup runtime-preflight smoke test package clean

UV ?= uv
UV_RUN ?= $(UV) run --frozen --isolated --python 3.12.11
PYTHON ?= $(UV_RUN) python
PACKAGE_NAME ?= concordia-dao-council.zip
CASPER_CONTRACT_TOOLCHAIN ?= nightly-2025-02-01

# Run the FastAPI gateway only.
gateway:
	$(UV_RUN) uvicorn gateway.app:app --reload --host 0.0.0.0 --port 8000

# Run the local DAO proposal simulator used for offline rehearsals.
simulator:
	$(UV_RUN) uvicorn app:app --app-dir proposal-simulator --reload --host 0.0.0.0 --port 9000

# Start these in separate terminals for the full council workflow.
agents:
	@echo "$(UV_RUN) python -m agents.rowan             # Rowan"
	@echo "$(UV_RUN) python -m agents.mercer            # Mercer"
	@echo "$(UV_RUN) python -m agents.verity            # Verity"
	@echo "$(UV_RUN) python -m agents.alden             # Alden"
	@echo "$(UV_RUN) python -m agents.locke             # Locke"
	@echo "$(UV_RUN) python -m agents.recorder.heartbeat # Concordia Core"
	@echo "$(UV_RUN) python -m agents.wells              # Wells (optional summary)"

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

runtime-preflight:
	$(PYTHON) -c "import sys; assert sys.version_info[:3] == (3, 12, 11), sys.version"

smoke:
	$(PYTHON) -m compileall -q shared gateway agents proposal-simulator scripts
	$(PYTHON) scripts/check_repo_hygiene.py

test: runtime-preflight smoke
	$(PYTHON) -m pytest -q

package: smoke
	$(PYTHON) scripts/package_repo.py --output /mnt/data/$(PACKAGE_NAME)

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ concordia.db dashboard/.next node_modules dashboard/node_modules
