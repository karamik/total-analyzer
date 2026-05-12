# =============================================================================
# TOTAL Analyzer – Makefile
# =============================================================================

.PHONY: help build test docker clean scan batch-scan install push pre-commit all

# ------------------------------------------------------------
# Variables
# ------------------------------------------------------------
BINARY_NAME = total-analyzer
BINARY_PATH = target/release/$(BINARY_NAME)
DOCKER_IMAGE = ghcr.io/karamik/total-analyzer
VERSION ?= v1.0-beta
EXAMPLES_DIR = examples
SARIF_OUTPUT = results.sarif
BATCH_SARIF = merged-report.sarif
WORKERS ?= 4

# ------------------------------------------------------------
# Default target
# ------------------------------------------------------------
all: build

# ------------------------------------------------------------
# Help
# ------------------------------------------------------------
help:
	@echo "TOTAL Analyzer – Makefile targets:"
	@echo ""
	@echo "  build         – Compile Rust binary (release mode)"
	@echo "  test          – Run analyzer on example vulnerable app (generates results.sarif)"
	@echo "  docker        – Build Docker image locally"
	@echo "  scan          – Scan current directory using Docker (output total-report.sarif)"
	@echo "  batch-scan    – Batch scan all Python files in current dir (merged SARIF)"
	@echo "  install       – Install binary to /usr/local/bin (Linux only)"
	@echo "  pre-commit    – Install pre-commit hook"
	@echo "  push          – Tag and push Docker image to GHCR"
	@echo "  clean         – Remove build artifacts and reports"
	@echo "  help          – Show this help"

# ------------------------------------------------------------
# Build
# ------------------------------------------------------------
build:
	@echo "🔨 Building release binary..."
	cargo build --release
	@echo "✅ Binary ready: $(BINARY_PATH)"

# ------------------------------------------------------------
# Test (on example vulnerable app)
# ------------------------------------------------------------
test: build
	@mkdir -p $(EXAMPLES_DIR)
	@echo 'from flask import Flask, request' > $(EXAMPLES_DIR)/test_app.py
	@echo 'app = Flask(__name__)' >> $(EXAMPLES_DIR)/test_app.py
	@echo '@app.route("/user")' >> $(EXAMPLES_DIR)/test_app.py
	@echo 'def get_user():' >> $(EXAMPLES_DIR)/test_app.py
	@echo '    uid = request.args.get("id")' >> $(EXAMPLES_DIR)/test_app.py
	@echo '    query = f"SELECT * FROM users WHERE id = {uid}"' >> $(EXAMPLES_DIR)/test_app.py
	@echo '    db.execute(query)' >> $(EXAMPLES_DIR)/test_app.py
	@echo '    return "ok"' >> $(EXAMPLES_DIR)/test_app.py
	@echo "🔍 Running analyzer on test_app.py..."
	$(BINARY_PATH) $(EXAMPLES_DIR)/test_app.py --sarif > $(SARIF_OUTPUT)
	@echo "✅ Test completed. SARIF report saved to $(SARIF_OUTPUT)"

# ------------------------------------------------------------
# Docker
# ------------------------------------------------------------
docker:
	@echo "🐳 Building Docker image $(DOCKER_IMAGE):$(VERSION)..."
	docker build -t $(DOCKER_IMAGE):$(VERSION) .
	docker tag $(DOCKER_IMAGE):$(VERSION) $(DOCKER_IMAGE):latest
	@echo "✅ Docker image built"

# ------------------------------------------------------------
# Scan current directory using Docker
# ------------------------------------------------------------
scan:
	@echo "🔍 Scanning current directory with Docker..."
	docker run --rm -v $(PWD):/src $(DOCKER_IMAGE):$(VERSION) /src --sarif > total-report.sarif
	@echo "✅ SARIF report written to total-report.sarif"

# ------------------------------------------------------------
# Batch scan using Python script
# ------------------------------------------------------------
batch-scan: build
	@echo "🔍 Batch scanning all Python files in $(PWD)..."
	python3 scripts/batch_scan.py --path . --sarif $(BATCH_SARIF) --workers $(WORKERS)
	@echo "✅ Merged SARIF report saved to $(BATCH_SARIF)"

# ------------------------------------------------------------
# Install binary system-wide (Linux only)
# ------------------------------------------------------------
install: build
	@echo "📦 Installing $(BINARY_PATH) to /usr/local/bin/..."
	sudo cp $(BINARY_PATH) /usr/local/bin/
	@echo "✅ Installed. Run 'total-analyzer --help'"

# ------------------------------------------------------------
# Pre-commit hook
# ------------------------------------------------------------
pre-commit:
	@echo "🔧 Installing pre-commit hook..."
	@if ! command -v pre-commit &> /dev/null; then \
		echo "pre-commit not found, installing..."; \
		pip install pre-commit; \
	fi
	@pre-commit install
	@echo "✅ Pre-commit hook installed. It will run TOTAL Analyzer on every commit."

# ------------------------------------------------------------
# Push Docker image to GHCR
# ------------------------------------------------------------
push: docker
	@echo "🚀 Pushing Docker image to GHCR..."
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest
	@echo "✅ Push complete"

# ------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------
clean:
	@echo "🧹 Cleaning build artifacts and reports..."
	cargo clean
	rm -f $(SARIF_OUTPUT) total-report.sarif $(BATCH_SARIF)
	rm -rf $(EXAMPLES_DIR)
	@echo "✅ Clean done"
