test:
	PYTHONPATH=./src pytest

install:
	python setup.py install

uninstall:
	pip uninstall cicflowmeter -y

clean:
	rm -rf *.egg-info/ dist/ build/
