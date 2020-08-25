all:
	# disabled

doc:
	make -C docs html

# pypi accepts only rst
# see http://inre.dundeemt.com/2014-05-04/pypi-vs-readme-rst-a-tale-of-frustration-and-unnecessary-binding/
rst:
	cat README.md | pandoc -f markdown -t rst > README.rst

.PHONY: setup.py
setup.py:
	poetry build -v --format sdist && tar --wildcards -xvf dist/*.tar.gz -O '*/setup.py' > setup.py

publish:
	# todo use poetry publish instead
	python setup.py sdist bdist_wheel
	# twine upload --verbose --repository-url https://test.pypi.org/legacy/ dist/*
	twine upload --verbose dist/*
	echo "You probably want to also tag the version now:"
	echo "  git tag -a VERSION -m 'version X'"
	echo "  git push --tags"

gen_transcripts:
	# https://cmd2.readthedocs.io/en/latest/freefeatures.html#script-files
	# ReGenerate tests
	tests/gen_transcripts.sh

tests: tests/*
	# Add -b to print standard output
	tests/run_transcripts.sh

man:
	# wrong name for the program but can't override :/
	# see also rst2man in docutils*.deb
	help2man -n "mptcpanalyzer - a multipath tcp pcap analysis tool" -o docs/mptcpanalyzer.man mptcpanalyzer


.PHONY: doc tests gen_transcripts
