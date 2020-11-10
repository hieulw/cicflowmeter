install:
	python setup.py install

uninstall:
	pip uninstall cicflowmeter -y

clean:
	rm -rf *.egg-info build dist

build:
	python setup.py sdist bdist_wheel --universal
