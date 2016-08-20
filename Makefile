doc:
	make -C docs html

test:
	python3.5 setup.py test

develop:
	python3.5 setup.py test


.PHONY: doc
