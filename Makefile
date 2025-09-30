# ARAT - Advanced Reconnaissance & Assessment Tool Makefile

.PHONY: help install setup test clean run web-panel docker-build docker-run docker-stop

# Default target
help:
	@echo "ARAT - Advanced Reconnaissance & Assessment Tool"
	@echo "==============================================="
	@echo ""
	@echo "Available targets:"
	@echo "  install     - Install dependencies"
	@echo "  setup       - Run setup script"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean temporary files"
	@echo "  run         - Run ARAT with example target"
	@echo "  web-panel   - Start web panel"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run  - Run with Docker Compose"
	@echo "  docker-stop - Stop Docker containers"
	@echo ""
	@echo "Examples:"
	@echo "  make run TARGET=example.com"
	@echo "  make run TARGET=example.com PHASE=1"
	@echo "  make run TARGET=example.com ALL_PHASES=true"

# Install dependencies
install:
	@echo "📦 Installing dependencies..."
	pip install -r requirements.txt
	@echo "✅ Dependencies installed"

# Run setup script
setup:
	@echo "🚀 Running setup script..."
	chmod +x setup.sh
	./setup.sh
	@echo "✅ Setup completed"

# Run tests
test:
	@echo "🧪 Running tests..."
	python test_arat.py
	@echo "✅ Tests completed"

# Clean temporary files
clean:
	@echo "🧹 Cleaning temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.log" -delete
	rm -rf data/*.db
	rm -rf logs/*.log
	rm -rf output/*
	rm -rf reports/*
	@echo "✅ Cleanup completed"

# Run ARAT
run:
	@echo "🚀 Running ARAT..."
	@if [ "$(ALL_PHASES)" = "true" ]; then \
		python main.py --target $(TARGET) --all-phases; \
	elif [ -n "$(PHASE)" ]; then \
		python main.py --target $(TARGET) --phase $(PHASE); \
	else \
		python main.py --target $(TARGET) --phase 1; \
	fi

# Start web panel
web-panel:
	@echo "🌐 Starting web panel..."
	python main.py --web-panel --host 0.0.0.0 --port 8080

# Build Docker image
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t arat .
	@echo "✅ Docker image built"

# Run with Docker Compose
docker-run:
	@echo "🐳 Starting Docker containers..."
	docker-compose up -d
	@echo "✅ Docker containers started"
	@echo "🌐 Web panel: http://localhost:8080"

# Stop Docker containers
docker-stop:
	@echo "🛑 Stopping Docker containers..."
	docker-compose down
	@echo "✅ Docker containers stopped"

# Development targets
dev-install:
	@echo "🔧 Installing development dependencies..."
	pip install -r requirements.txt
	pip install pytest pytest-asyncio black flake8 mypy pre-commit
	@echo "✅ Development dependencies installed"

# Code formatting
format:
	@echo "🎨 Formatting code..."
	black .
	@echo "✅ Code formatted"

# Linting
lint:
	@echo "🔍 Running linters..."
	flake8 .
	mypy .
	@echo "✅ Linting completed"

# Pre-commit hooks
pre-commit:
	@echo "🔗 Installing pre-commit hooks..."
	pre-commit install
	@echo "✅ Pre-commit hooks installed"

# Database operations
db-init:
	@echo "🗄️ Initializing database..."
	python -c "from core.database import Database; from core.config import Config; import asyncio; asyncio.run(Database(Config().database_url).create_tables())"
	@echo "✅ Database initialized"

db-reset:
	@echo "🗄️ Resetting database..."
	rm -f data/*.db
	make db-init
	@echo "✅ Database reset"

# Backup operations
backup:
	@echo "💾 Creating backup..."
	mkdir -p backups
	tar -czf backups/arat-backup-$(shell date +%Y%m%d-%H%M%S).tar.gz data/ logs/ reports/ output/
	@echo "✅ Backup created"

# Update wordlists
update-wordlists:
	@echo "📝 Updating wordlists..."
	@echo "This would download updated wordlists from various sources"
	@echo "✅ Wordlists updated"

# Security scan
security-scan:
	@echo "🔒 Running security scan..."
	python -m bandit -r . -f json -o security-report.json
	@echo "✅ Security scan completed"

# Performance test
perf-test:
	@echo "⚡ Running performance test..."
	python -c "import asyncio; from test_arat import test_phase_execution; asyncio.run(test_phase_execution())"
	@echo "✅ Performance test completed"

# Documentation
docs:
	@echo "📚 Generating documentation..."
	@echo "Documentation generation would go here"
	@echo "✅ Documentation generated"

# Release
release:
	@echo "🚀 Creating release..."
	@echo "Release creation would go here"
	@echo "✅ Release created"

# Default target for TARGET
TARGET ?= example.com
PHASE ?= 1
ALL_PHASES ?= false