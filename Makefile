# Open Redirect Scanner Makefile

.PHONY: help install test clean run setup

help:
	@echo "Open Redirect Scanner - Available Commands:"
	@echo "  install    - Install dependencies"
	@echo "  test       - Run test scan"
	@echo "  run        - Run scanner with example target"
	@echo "  clean      - Clean up generated files"
	@echo "  setup      - Setup development environment"

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt
	@echo "Dependencies installed successfully!"

test:
	@echo "Running test scan..."
	python test_scanner.py

run:
	@echo "Running scanner with example target..."
	python run_scanner.py https://httpbin.org test_results 5

clean:
	@echo "Cleaning up generated files..."
	rm -rf scan_results/
	rm -rf test_results/
	rm -rf __pycache__/
	rm -rf *.pyc
	rm -rf .pytest_cache/
	@echo "Cleanup completed!"

setup: install
	@echo "Setting up development environment..."
	pip install -e .
	@echo "Setup completed!"

# Example usage targets
example-basic:
	python run_scanner.py https://example.com

example-advanced:
	python run_scanner.py https://example.com advanced_results 20

# Development targets
dev-install:
	pip install -r requirements.txt
	pip install -e .

dev-test:
	python -m pytest tests/ -v

# Documentation
docs:
	@echo "Generating documentation..."
	@echo "See README.md for detailed usage instructions"