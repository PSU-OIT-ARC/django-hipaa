PATH := $(CURDIR)/.env/bin:$(PATH)
# run the tests for python3
test: .env
	python runtests.py

pretty: .env
	flake8
	isort --diff -rc hipaa

# remove junk
clean:
	rm -rf .env
	find -iname "*.pyc" -or -iname "__pycache__" -delete

# setup a virtualenv for python3 and install pip
.env:
	python3 -m venv .env
	curl https://raw.githubusercontent.com/pypa/pip/master/contrib/get-pip.py | python
	pip install -e .[dev]

coverage: .env
	coverage run runtests.py
	coverage html --omit ".env*,runtests.py" && cd htmlcov && python -m http.server 9000
