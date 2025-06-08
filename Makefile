install:
	@uv sync

clean:
	rm -rf *.egg-info build dist report.xml *.csv

release-minor:
	@uv version --bump minor
	@git tag -a v$(shell uv version --short)

release-patch:
	@uv version --bump patch
	@git tag -a v$(shell uv version --short)

publish: clean
	@uv build
	@uv publish
