PATH := $(CURDIR)/.env/bin:$(PATH)

test: .env
	python runtests.py && flake8 && isort -rc --diff --check-only hipaa

clean:
	rm -rf .env
	find -iname "*.pyc" -or -iname "__pycache__" -delete

.env:
	python3 -m venv .env
	curl https://raw.githubusercontent.com/pypa/pip/master/contrib/get-pip.py | python
	pip install -e .[dev]

coverage: .env
	coverage run runtests.py
	coverage html --omit ".env*,runtests.py" && cd htmlcov && python -m http.server 9000
