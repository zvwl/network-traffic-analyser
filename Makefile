# Makefile for Network Traffic Analyser

# Variables
PYTHON := python3
VENV := .venv
ACTIVATE := source $(VENV)/bin/activate
REQ := requirements.txt

# Targets
.PHONY: all setup install run test clean

all: setup install

setup:
	@echo "Setting up the virtual environment..."
	$(PYTHON) -m venv $(VENV)

install:
	@echo "Installing dependencies..."
	$(ACTIVATE) && pip install -r $(REQ)

run:
	@echo "Running the Network Traffic Analyser..."
	$(ACTIVATE) && $(PYTHON) src/main.py

test:
	@echo "Running tests..."
	$(ACTIVATE) && pytest tests/

clean:
	@echo "Cleaning up..."
	rm -rf $(VENV)
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
