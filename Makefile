VERSION:=$(shell poetry version --short)

install:
	python setup.py install

uninstall:
	pip uninstall cicflowmeter -y

clean:
	rm -rf *.egg-info build dist report.xml *.csv

build:
	python setup.py sdist bdist_wheel --universal

release:
	@git tag -a v$(VERSION)
	@git push --tag
