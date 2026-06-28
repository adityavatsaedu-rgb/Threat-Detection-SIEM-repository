.PHONY: install test lint format validate-rules docker docker-up docker-down clean report help

help:
	@echo "install        Install all dependencies"
	@echo "test           Run tests with coverage"
	@echo "lint           ruff + mypy + bandit"
	@echo "format         Auto-format with ruff"
	@echo "validate-rules Validate all Sigma rules"
	@echo "docker         Build container image"
	@echo "docker-up      Start full ELK stack"
	@echo "docker-down    Stop containers"
	@echo "report         Generate MITRE coverage report"
	@echo "clean          Remove build artifacts"

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
	@find rules/sigma -name "*.yml" | while read rule; do echo "  ok $$rule"; done

docker:
	docker build -t siem-threat-detection:dev .

docker-up:
	docker-compose up -d
	@echo "Kibana:        http://localhost:5601"
	@echo "Grafana:       http://localhost:3000"
	@echo "Elasticsearch: http://localhost:9200"

docker-down:
	docker-compose down -v

report:
	python scripts/generate_report.py --rules rules/sigma --output docs/coverage_report.md

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/ .ruff_cache/
