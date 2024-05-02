VERSION:=$(shell poetry version --short)

install:
	@poetry install

clean:
	rm -rf *.egg-info build dist report.xml *.csv

release-minor:
	@poetry version minor
	@git tag -a v$(VERSION)

release-patch:
	@poetry version patch

publish: clean
	@poetry publish --build
