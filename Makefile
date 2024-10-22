.PHONY: setup run test clean

# Install dependencies from requirements.txt
setup:
	pip install -r requirements.txt

# Run the network traffic analyzer
run:
	python3 src/analyser.py

# Run unit tests
test:
	pytest tests/

# Clean up .pyc files and __pycache__ directories
clean:
	find . -name "*.pyc" -exec rm -f {} \;
	find . -name "__pycache__" -exec rm -rf {} \;
