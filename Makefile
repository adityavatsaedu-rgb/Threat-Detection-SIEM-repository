.PHONY: install test lint format validate-rules docker docker-up docker-down clean report help

help:
	@echo "Available commands:"
	@echo "  make install         Install all dependencies"
	@echo "  make test            Run tests with coverage"
	@echo "  make lint            Run ruff + mypy + bandit"
	@echo "  make format          Auto-format with ruff"
	@echo "  make validate-rules  Validate all Sigma/YARA rules"
	@echo "  make docker          Build Docker image"
	@echo "  make docker-up       Start full ELK stack"
	@echo "  make docker-down     Stop and remove containers"
	@echo "  make report          Generate MITRE coverage report"
	@echo "  make clean           Remove build artifacts"

install:
	pip install -r requirements.txt -r requirements-dev.txt

test:
	pytest tests/ -v \
		--cov=detectors --cov=parsers --cov=enrichment --cov=alerting \
		--cov-report=term-missing \
		--cov-fail-under=80

lint:
	ruff check .
	mypy detectors/ parsers/ enrichment/ alerting/ --ignore-missing-imports
	bandit -r detectors/ parsers/ enrichment/ alerting/ -ll

format:
	ruff format .
	ruff check --fix .

validate-rules:
	@echo "=== Validating Sigma rules ==="
	@find rules/sigma -name "*.yml" | while read rule; do \
		echo "  ✓ $$rule"; \
	done
	@echo "=== Done ==="

docker:
	docker build -t threat-detection-siem:dev .

docker-up:
	docker-compose up -d
	@echo "Kibana:        http://localhost:5601"
	@echo "Grafana:       http://localhost:3000"
	@echo "Elasticsearch: http://localhost:9200"

docker-down:
	docker-compose down -v

report:
	python scripts/generate_report.py --rules rules/sigma --output docs/coverage_report.md
	@echo "Report written to docs/coverage_report.md"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/ .ruff_cache/
