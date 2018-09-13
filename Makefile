all:
	# disabled

doc:
	make -C docs html

# pypi accepts only rst
# see http://inre.dundeemt.com/2014-05-04/pypi-vs-readme-rst-a-tale-of-frustration-and-unnecessary-binding/
rst:
	cat README.md | pandoc -f markdown -t rst > README.rst


# 
publish:
	python setup.py sdist upload
	python setup.py bdist_wheel upload
	echo "You probably want to also tag the version now:"
	echo "  git tag -a VERSION -m 'version X'"
	echo "  git push --tags"

tests:
	# Add -b to print standard output
	# python -munittest tests/cache_test.py -b
	tests/run_transcripts.sh

develop:
	python setup.py develop --user

uninstall:
	python setup.py develop --user --uninstall

man:
	# wrong name for the program but can't override :/
	# see also rst2man in docutils*.deb
	help2man -n "mptcpanalyzer - a multipath tcp pcap analysis tool" -o docs/mptcpanalyzer.man mptcpanalyzer


.PHONY: doc tests
