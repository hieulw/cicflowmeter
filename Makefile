VERSION:=$(shell uv version --short)

install:
	@uv sync

clean:
	rm -rf *.egg-info build dist report.xml *.csv

release-minor:
	@uv version --bump minor
	@git tag -a v$(VERSION)

release-patch:
	@uv version --bump patch

publish: clean
	@uv publish
