# redloop — automatic penetration testing agent
#
#   make            show this help
#   make build      build the Docker image (Kali toolchain + agent)
#   make run TARGET=10.10.11.42 [ARGS="--max-steps 60"]
#   make demo       spin up the bundled vulnerable lab and watch the agent pwn it
#
# Everything runs in Docker; nothing is installed on the host.

SHELL      := /bin/bash
IMAGE      ?= redloop:latest
LAB_IMAGE  ?= redloop-lab:latest
TOOLSET    ?= full
RUNS_DIR   ?= $(CURDIR)/runs
TARGET     ?=
ARGS       ?=
PROVIDER   ?=
MODEL      ?=
BASE_URL   ?=
API_KEY    ?=
COMPOSE    ?= docker compose
SERVICE    ?= redloop
DOCKER_RUN  = docker run --rm -it \
                --env-file .env \
                -v "$(RUNS_DIR):/app/runs" \
                --add-host host.docker.internal:host-gateway \
                --cap-add NET_RAW --cap-add NET_ADMIN \
                -e REDLOOP_IN_DOCKER=1 \
                -e OLLAMA_HOST \
                $(IMAGE)

.DEFAULT_GOAL := help
.PHONY: help build install rebuild check-target check-env check-docker run shell demo lab lab-stop doctor test lint \
        format local-install venv ollama-pull logs clean runs version

# --------------------------------------------------------------------------- #
# help
# --------------------------------------------------------------------------- #
help: ## Show this help
	@echo ""
	@echo "  redloop — autonomous offensive-security agent"
	@echo ""
	@echo "  Usage:"
	@echo "    make build                          build the image (Kali toolchain + agent)"
	@echo "    make run TARGET=<ip|host>           run an engagement"
	@echo "    make run TARGET=<ip> ARGS=\"--max-steps 60 --max-minutes 120\""
	@echo "    make run TARGET=<ip> PROVIDER=ollama MODEL=qwen2.5-coder:14b"
	@echo "    make demo                           attack the bundled vulnerable lab"
	@echo "    make doctor                         check the environment and the model endpoint"
	@echo "    make shell                          interactive shell inside the container"
	@echo "    make test                           run the test suite"
	@echo ""
	@echo "  Targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_.-]+:.*##/ {printf "    %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "  Variables: IMAGE=$(IMAGE) TOOLSET=$(TOOLSET) RUNS_DIR=$(RUNS_DIR)"
	@echo "  Providers: anthropic (default), openai, ollama, lmstudio, openrouter, groq, mock"
	@echo ""

# --------------------------------------------------------------------------- #
# docker lifecycle
# --------------------------------------------------------------------------- #
check-target: ## Internal: fail early when TARGET is missing
	@if [ -z "$(TARGET)" ] && [ "$(MAKECMDGOALS)" = "run" ]; then \
		echo "!! TARGET is required, e.g.  make run TARGET=10.10.11.42"; \
		echo "   options: make run TARGET=<ip> ARGS=\"--max-steps 60 --objective 'get a shell'\""; \
		exit 1; \
	fi

check-env: ## Internal: make sure .env exists (Docker needs the file)
	@[ -f .env ] || { echo ">> no .env file; copying .env.example — add your API key to it"; cp .env.example .env; }

check-docker: ## Verify Docker is installed and running
	@command -v docker >/dev/null 2>&1 || { \
		echo "!! Docker is not installed."; \
		echo "   Install it from https://docs.docker.com/engine/install/ and try again,"; \
		echo "   or run the agent without Docker: make venv && source .venv/bin/activate && redloop --help"; \
		exit 1; }
	@docker info >/dev/null 2>&1 || { echo "!! Docker is installed but the daemon is not reachable."; exit 1; }

build: check-env check-docker ## Build the agent image
	docker build --build-arg TOOLSET=$(TOOLSET) -t $(IMAGE) .
	@echo ""
	@echo "Built $(IMAGE). Next:"
	@echo "  cp .env.example .env      # then put your ANTHROPIC_API_KEY in it"
	@echo "  make run TARGET=10.10.11.42"

install: build ## Alias for build (install the image)

rebuild: check-env check-docker ## Rebuild the image from scratch
	docker build --no-cache --build-arg TOOLSET=$(TOOLSET) -t $(IMAGE) .

# --------------------------------------------------------------------------- #
# running
# --------------------------------------------------------------------------- #
run: check-target check-env check-docker ## Run an engagement (requires TARGET=...)
	@if [ -z "$(TARGET)" ]; then \
		echo "!! TARGET is required. Examples:"; \
		echo "     make run TARGET=10.10.11.42"; \
		echo "     make run TARGET=10.10.11.42 ARGS=\"--max-steps 60 --objective 'get a shell'\""; \
		exit 1; \
	fi
	@mkdir -p "$(RUNS_DIR)"
	@echo ""
	@echo "  You are about to run an automated attack against: $(TARGET)"
	@echo "  By continuing you confirm you own this system or have explicit written"
	@echo "  permission to test it. Unauthorised access is a criminal offence."
	@echo ""
	$(DOCKER_RUN) --target $(TARGET) --i-am-authorized \
		$(if $(PROVIDER),--provider $(PROVIDER)) $(if $(MODEL),--model $(MODEL)) \
		$(if $(BASE_URL),--base-url $(BASE_URL)) $(if $(API_KEY),--api-key $(API_KEY)) $(ARGS)

shell: check-env check-docker ## Interactive shell inside the container (tools available)
	@mkdir -p "$(RUNS_DIR)"
	docker run --rm -it --env-file .env -v "$(RUNS_DIR):/app/runs" \
		--add-host host.docker.internal:host-gateway \
		--cap-add NET_RAW --cap-add NET_ADMIN \
		--entrypoint /bin/bash $(IMAGE)

doctor: check-env check-docker ## Check the toolchain, config and model endpoint
	@mkdir -p "$(RUNS_DIR)"
	$(DOCKER_RUN) --doctor --check-model \
		$(if $(PROVIDER),--provider $(PROVIDER)) $(if $(MODEL),--model $(MODEL)) \
		$(if $(BASE_URL),--base-url $(BASE_URL))

logs: ## Show the most recent run's feed
	@latest=$$(ls -1dt "$(RUNS_DIR)"/*/ 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "no runs yet"; else echo "$$latest"; tail -n 80 "$$latest/feed.txt" 2>/dev/null || true; fi

runs: ## List previous runs
	@ls -1dt "$(RUNS_DIR)"/*/ 2>/dev/null | sed 's|$(RUNS_DIR)/||; s|/$$||' || echo "no runs yet"

# --------------------------------------------------------------------------- #
# demo / lab
# --------------------------------------------------------------------------- #
lab: check-env check-docker ## Start the bundled vulnerable lab on http://localhost:8080
	$(COMPOSE) --profile lab up -d lab
	@echo "lab is up at http://localhost:8080 (flag: flag{r3dl00p_l4b_sql1_byp4ss})"
	@echo "stop it with: make lab-stop"

lab-stop: ## Stop the lab
	-$(COMPOSE) --profile lab stop lab

demo: check-env check-docker ## Watch the agent solve the bundled lab (no API key needed)
	@mkdir -p "$(RUNS_DIR)"
	@echo ">> building and starting the practice lab"
	@$(COMPOSE) --profile lab up -d --build lab
	@echo ">> waiting for the lab to accept connections"
	@for i in $$(seq 1 30); do \
		if $(COMPOSE) exec -T lab python -c "import socket;s=socket.socket();s.settimeout(0.2);s.connect(('127.0.0.1',8080));s.close()" 2>/dev/null; then break; fi; \
		sleep 1; \
	done
	@echo ">> running redloop with the offline demo model (provider=mock)"
	@$(COMPOSE) run --rm --no-deps $(SERVICE) \
		--target lab-web --provider mock --plain --max-steps 20 \
		--runs-dir /app/runs --i-am-authorized || true
	@echo ""
	@echo ">> that run used the built-in rule-based model. For a real one:"
	@echo "     make run TARGET=lab-web PROVIDER=ollama MODEL=qwen2.5-coder:14b"

ollama-pull: check-env check-docker ## Download a local model (MODEL=qwen2.5-coder:14b)
	@[ -n "$(MODEL)" ] || { echo "!! set MODEL=..., e.g. make ollama-pull MODEL=qwen2.5-coder:14b"; exit 1; }
	$(COMPOSE) --profile local run --rm ollama ollama pull $(MODEL)

# --------------------------------------------------------------------------- #
# development
# --------------------------------------------------------------------------- #
venv: ## Create a local virtualenv and install the package in editable mode
	python3 -m venv .venv
	./.venv/bin/pip install --upgrade pip
	./.venv/bin/pip install -e ".[dev]"
	@echo "activate it with: source .venv/bin/activate"

local-install: venv ## Alias for venv

test: ## Run the test suite (uses the local venv if present, else Docker)
	@if [ -x ./.venv/bin/pytest ]; then ./.venv/bin/python -m pytest tests/ -q; \
	else docker run --rm -v "$(CURDIR):/src" -w /src $(IMAGE) python -m pytest tests/ -q; fi

lint: ## Lint with ruff
	@if [ -x ./.venv/bin/ruff ]; then ./.venv/bin/ruff check redloop tests; \
	else echo "ruff is not installed; run: make venv"; fi

format: ## Auto-format and fix lint issues
	@if [ -x ./.venv/bin/ruff ]; then ./.venv/bin/ruff check --fix redloop tests; \
	else echo "ruff is not installed; run: make venv"; fi

version: ## Print the version
	@python3 -c "import re;print(re.search(r'version = \"([^\"]+)\"', open('pyproject.toml').read()).group(1))" 2>/dev/null || echo "unknown"

clean: ## Remove run artefacts
	rm -rf runs/*/ loot/* .pytest_cache .ruff_cache
	@echo "cleaned runs/ and loot/"

.PHONY: help build install rebuild check-target check-env check-docker run shell demo lab lab-stop doctor test lint \
        format local-install venv ollama-pull logs clean runs version
