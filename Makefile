# SafeCadence Network Risk — convenience targets.
#
# All targets use python3 and a project-local virtualenv at .venv so nothing
# leaks into your system Python. First time, run `make install`.
#
# Usage:
#   make install      # create .venv and install the package + AI extras
#   make scan         # scan the bundled sample config
#   make ai           # run the BYOK AI explainer on the sample
#   make test         # run pytest
#   make report       # generate Markdown + JSON reports for the sample
#   make history      # show local scan history
#   make clean        # remove .venv and build artifacts
#   make shell        # drop into a venv-activated subshell

PY      ?= python3
VENV    := .venv
BIN     := $(VENV)/bin
PIP     := $(BIN)/pip
SC      := $(BIN)/safecadence
SAMPLE  := examples/sample_configs/cisco_ios_running.txt

.PHONY: help install scan ai test report history clean shell upgrade

help:
	@echo "SafeCadence Network Risk — make targets"
	@echo ""
	@echo "  make install   create .venv and install in editable mode (with AI extras)"
	@echo "  make scan      scan the bundled Cisco IOS sample"
	@echo "  make ai        run the BYOK AI executive briefing on the sample"
	@echo "  make test      run the pytest suite"
	@echo "  make report    write Markdown + JSON reports to ./out/"
	@echo "  make history   show local scan history (requires --save-history runs)"
	@echo "  make shell     spawn a subshell with the venv activated"
	@echo "  make upgrade   upgrade pip + reinstall the package"
	@echo "  make clean     wipe .venv and build artifacts"
	@echo ""
	@echo "BYOK AI: export OPENAI_API_KEY=sk-...   or   export ANTHROPIC_API_KEY=sk-ant-..."
	@echo "        before running 'make ai' to get an LLM-generated remediation plan."

INSTALL_STAMP := $(VENV)/.installed

$(VENV)/pyvenv.cfg:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip wheel

$(INSTALL_STAMP): pyproject.toml | $(VENV)/pyvenv.cfg
	$(PIP) install -e ".[ai]"
	$(PIP) install pytest
	@touch $(INSTALL_STAMP)
	@echo ""
	@echo "Installed. Try:  make scan"

install: $(INSTALL_STAMP)

upgrade: $(VENV)/pyvenv.cfg
	$(BIN)/pip install --upgrade pip wheel
	$(PIP) install --upgrade -e ".[ai]"
	@touch $(INSTALL_STAMP)

scan: $(INSTALL_STAMP)
	$(SC) scan $(SAMPLE)

ai: $(INSTALL_STAMP)
	@mkdir -p out
	$(SC) ai-explain $(SAMPLE) --output out/ai-brief.md
	@echo ""
	@echo "Saved AI briefing to: out/ai-brief.md"

test: $(INSTALL_STAMP)
	$(BIN)/pytest -v

report: $(INSTALL_STAMP)
	@mkdir -p out
	$(SC) scan $(SAMPLE) --output out/report.md --json out/report.json --html out/report.html --docx out/report.docx --quiet
	@echo ""
	@echo "Wrote: out/report.md"
	@echo "Wrote: out/report.json"
	@echo "Wrote: out/report.html"
	@echo "Wrote: out/report.docx"

history: $(INSTALL_STAMP)
	$(SC) history

shell: $(INSTALL_STAMP)
	@echo "Spawning a subshell with $(VENV) activated. Type 'exit' to leave."
	@bash --rcfile <(echo "source $(BIN)/activate; PS1='(safecadence) \w \$$ '")

clean:
	rm -rf $(VENV) build dist *.egg-info src/*.egg-info out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
