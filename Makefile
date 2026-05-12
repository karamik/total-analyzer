.PHONY: build test docker clean scan help

BINARY_NAME=total-analyzer
DOCKER_IMAGE=ghcr.io/total-protocol/total-analyzer:v1.0-beta
EXAMPLES_DIR=examples

help:
	@echo "Available targets:"
	@echo "  build    - Compile Rust binary (release mode)"
	@echo "  test     - Run analyzer on example vulnerable app"
	@echo "  docker   - Build Docker image locally"
	@echo "  scan     - Run Docker container on current directory (output results.sarif)"
	@echo "  clean    - Remove build artifacts and reports"
	@echo "  push     - Tag and push to GHCR (requires docker login)"

build:
	cargo build --release
	@echo "Binary ready: target/release/$(BINARY_NAME)"

test: build
	@mkdir -p $(EXAMPLES_DIR)
	@echo '# Example vulnerable Flask app' > $(EXAMPLES_DIR)/vulnerable_app.py
	@echo 'from flask import Flask, request' >> $(EXAMPLES_DIR)/vulnerable_app.py
	@echo 'app = Flask(__name__)' >> $(EXAMPLES_DIR)/vulnerable_app.py
	@echo '@app.route("/user")' >> $(EXAMPLES_DIR)/vulnerable_app.py
	@echo 'def get_user():' >> $(EXAMPLES_DIR)/vulnerable_app.py
	@echo '    uid = request.args.get("id")' >> $(EXAMPLES_DIR)/vulnerable_app.py
	@echo '    query = f"SELECT * FROM users WHERE id = {uid}"' >> $(EXAMPLES_DIR)/vulnerable_app.py
	@echo '    db.execute(query)  # Should be detected' >> $(EXAMPLES_DIR)/vulnerable_app.py
	@echo '    return "ok"' >> $(EXAMPLES_DIR)/vulnerable_app.py
	./target/release/$(BINARY_NAME) $(EXAMPLES_DIR)/vulnerable_app.py --sarif > results.sarif
	@echo "Test completed. Results saved to results.sarif"

docker:
	docker build -t $(DOCKER_IMAGE) .

scan:
	docker run --rm -v $(PWD):/src $(DOCKER_IMAGE) /src --sarif > total-report.sarif
	@echo "SARIF report written to total-report.sarif"

clean:
	cargo clean
	rm -f results.sarif total-report.sarif
	rm -rf $(EXAMPLES_DIR)

push: docker
	docker tag $(DOCKER_IMAGE) ghcr.io/total-protocol/total-analyzer:latest
	docker push ghcr.io/total-protocol/total-analyzer:latest
	docker push $(DOCKER_IMAGE)

# Default target
all: build
